//! In-process RFB 3.8 (RFC 6143) test server on loopback.
//!
//! Serves a synthetic RGBA framebuffer that the test mutates through [`RfbHandle`]. Supports the
//! security types None, VNC Authentication and VeNCrypt (all subtypes, see [`VeNCryptSub`]),
//! the encodings Raw, CopyRect, ZRLE and Tight basic (fill / copy / palette / gradient, no
//! JPEG), the pseudo-encodings DesktopSize, ExtendedDesktopSize, LastRect and QEMU Extended Key
//! Event, cut text in both directions, and records every input event it receives.
//! [`Knobs`] turn on hostile behaviour for negative tests.

mod conn;
mod encode;
mod framebuffer;
mod pixel;
mod session;
mod vencrypt;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch};

use crate::tls::TestCert;
pub use encode::{TightMode, ZrleMode};
pub use framebuffer::{Framebuffer, Rect};
pub use pixel::PixelFormat;
pub use vencrypt::vnc_auth_response;

/// Encoding numbers (RFC 6143 §7.7 and the rfbproto community registry).
pub mod encoding {
    pub const RAW: i32 = 0;
    pub const COPY_RECT: i32 = 1;
    pub const TIGHT: i32 = 7;
    pub const ZRLE: i32 = 16;
    pub const DESKTOP_SIZE: i32 = -223;
    pub const LAST_RECT: i32 = -224;
    pub const CURSOR: i32 = -239;
    pub const QEMU_EXTENDED_KEY: i32 = -258;
    pub const EXTENDED_DESKTOP_SIZE: i32 = -308;
}

/// A security type the server offers in its list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityOffer {
    /// Type 1.
    None,
    /// Type 2: DES challenge against [`RfbConfig::password`].
    VncAuth,
    /// Type 19 with these subtypes, in this order.
    VeNCrypt(Vec<VeNCryptSub>),
    /// Any other type number (offered, but the server closes if the client picks it).
    Other(u8),
}

/// VeNCrypt 0.2 subtypes. The `Tls*` subtypes are specified as anonymous-DH TLS, which rustls
/// does not implement; this server answers them with an ordinary certificate TLS handshake, so
/// they are only useful to check that a client *refuses* them (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VeNCryptSub {
    Plain,
    TlsNone,
    TlsVnc,
    TlsPlain,
    X509None,
    X509Vnc,
    X509Plain,
}

impl VeNCryptSub {
    pub const fn code(self) -> u32 {
        match self {
            Self::Plain => 256,
            Self::TlsNone => 257,
            Self::TlsVnc => 258,
            Self::TlsPlain => 259,
            Self::X509None => 260,
            Self::X509Vnc => 261,
            Self::X509Plain => 262,
        }
    }

    pub fn from_code(code: u32) -> Option<Self> {
        [
            Self::Plain,
            Self::TlsNone,
            Self::TlsVnc,
            Self::TlsPlain,
            Self::X509None,
            Self::X509Vnc,
            Self::X509Plain,
        ]
        .into_iter()
        .find(|s| s.code() == code)
    }
}

/// Hostile / unusual behaviour. Every field defaults to off. Read at the start of every
/// connection (and for update knobs before every update), so a test can flip them between
/// connections with [`RfbHandle::set_knobs`].
#[derive(Debug, Clone, Default)]
pub struct Knobs {
    /// Send this 12-byte version string instead of `RFB 003.008\n`.
    pub version: Option<[u8; 12]>,
    /// Remove VeNCrypt (19) from the security list for connection number ≥ n (0-based), i.e.
    /// a MITM stripping TLS after the client pinned the certificate on an earlier connection.
    pub strip_tls_after: Option<u32>,
    /// Delay before every byte of the handshake (version, security, ServerInit).
    pub slow_loris: Option<Duration>,
    /// Next updates carry a rect that extends past the framebuffer by this many pixels.
    pub oversized_rect: Option<u16>,
    /// ZRLE / Tight zlib length field claims this many bytes (the real data is sent).
    pub lie_zlib_length: Option<u32>,
    /// ServerCutText length field claims this many bytes (the real text is sent).
    pub lie_cut_text_length: Option<u32>,
    /// FramebufferUpdate announces this many more rects than it sends.
    pub missing_rects: Option<u16>,
    /// Announce 0xFFFF rects and terminate with a LastRect pseudo-rect.
    pub use_last_rect: bool,
    /// Send every rect in this encoding even if the client did not advertise it.
    pub force_encoding: Option<i32>,
    /// Tight rects use the JPEG compression control (0x90) with garbage data.
    pub tight_jpeg: bool,
    /// SecurityResult always fails with this reason (after a correct password).
    pub fail_auth_reason: Option<String>,
    /// ServerInit name of this many bytes (cap tests; default name otherwise).
    pub huge_name: Option<u32>,
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct RfbConfig {
    pub width: u16,
    pub height: u16,
    pub name: String,
    /// Security list in offer order.
    pub security: Vec<SecurityOffer>,
    /// VNC Authentication password (first 8 bytes used, as in RFB).
    pub password: Option<String>,
    /// Username + password for VeNCrypt Plain / TLSPlain / X509Plain.
    pub plain_user: Option<(String, String)>,
    /// Certificate for VeNCrypt (generated if `None` and VeNCrypt is offered).
    pub cert: Option<TestCert>,
    /// Fixed 16-byte VNC Authentication challenge (vector tests); random otherwise.
    pub fixed_challenge: Option<[u8; 16]>,
    pub zrle_mode: ZrleMode,
    pub tight_mode: TightMode,
    /// Accept SetDesktopSize from the client (answered with ExtendedDesktopSize).
    pub allow_client_resize: bool,
    pub knobs: Knobs,
}

impl Default for RfbConfig {
    fn default() -> Self {
        Self {
            width: 640,
            height: 480,
            name: "mooring-testsrv".to_owned(),
            security: vec![SecurityOffer::None],
            password: None,
            plain_user: None,
            cert: None,
            fixed_challenge: None,
            zrle_mode: ZrleMode::Auto,
            tight_mode: TightMode::Auto,
            allow_client_resize: true,
            knobs: Knobs::default(),
        }
    }
}

/// One key event as received (`KeyEvent` or QEMU Extended Key Event).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRecord {
    pub down: bool,
    pub keysym: u32,
    /// XT scancode for QEMU Extended Key Events, `None` for plain `KeyEvent`.
    pub qemu_keycode: Option<u32>,
}

/// What the server has seen so far (all connections together).
#[derive(Debug, Clone, Default)]
pub struct RfbStats {
    pub connections: u32,
    /// `(type, VeNCrypt subtype)` the client chose, per connection.
    pub chosen_security: Vec<(u8, Option<u32>)>,
    pub auth_ok: u32,
    pub auth_failed: u32,
    /// Client versions as sent (12 bytes, lossy UTF-8).
    pub client_versions: Vec<String>,
    pub pixel_formats: Vec<PixelFormat>,
    /// Last `SetEncodings` list.
    pub encodings: Vec<i32>,
    pub update_requests: u32,
    pub updates_sent: u32,
    pub pointer_events: u32,
    pub last_pointer: Option<(u8, u16, u16)>,
    pub key_events: Vec<KeyRecord>,
    /// `ClientCutText` payloads (Latin-1 bytes as sent).
    pub client_cut_text: Vec<Vec<u8>>,
    /// `SetDesktopSize` requests `(w, h)`.
    pub desktop_size_requests: Vec<(u16, u16)>,
    /// `ClientInit.shared` per connection.
    pub shared_flags: Vec<bool>,
    /// Protocol errors that ended a connection.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum Event {
    Dirty(Rect),
    Copy { dst: Rect, src_x: u16, src_y: u16 },
    CutText(Vec<u8>),
    Resized,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) config: Mutex<RfbConfig>,
    pub(crate) fb: Mutex<Framebuffer>,
    pub(crate) stats: Mutex<RfbStats>,
    pub(crate) events: broadcast::Sender<Event>,
    pub(crate) tls: Option<Arc<rustls::ServerConfig>>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A running server. Dropping it stops accepting; live connections end with their peer.
#[derive(Debug)]
pub struct RfbHandle {
    addr: SocketAddr,
    shared: Arc<Shared>,
    cert: Option<TestCert>,
    _stop: watch::Sender<()>,
}

/// Starts the server on `127.0.0.1:port` (`0` = ephemeral). Needs a Tokio runtime.
pub async fn start(mut config: RfbConfig, port: u16) -> std::io::Result<RfbHandle> {
    let wants_tls = config.security.iter().any(|s| matches!(s, SecurityOffer::VeNCrypt(_)));
    if wants_tls && config.cert.is_none() {
        config.cert = Some(TestCert::generate(&[]).map_err(std::io::Error::other)?);
    }
    let cert = config.cert.clone();
    let tls = match &cert {
        Some(c) => Some(c.server_config().map_err(std::io::Error::other)?),
        None => None,
    };
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    let fb = Framebuffer::synthetic(config.width, config.height);
    let (events, _) = broadcast::channel(1024);
    let shared = Arc::new(Shared {
        config: Mutex::new(config),
        fb: Mutex::new(fb),
        stats: Mutex::new(RfbStats::default()),
        events,
        tls,
    });
    let (stop, mut stopped) = watch::channel(());
    let accept_shared = Arc::clone(&shared);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    let index = {
                        let mut stats = lock(&accept_shared.stats);
                        stats.connections += 1;
                        stats.connections - 1
                    };
                    tokio::spawn(conn::serve(Arc::clone(&accept_shared), stream, index));
                }
            }
        }
    });
    Ok(RfbHandle { addr, shared, cert, _stop: stop })
}

impl RfbHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The VeNCrypt certificate, when one is configured.
    pub fn cert(&self) -> Option<&TestCert> {
        self.cert.as_ref()
    }

    pub fn stats(&self) -> RfbStats {
        lock(&self.shared.stats).clone()
    }

    pub fn set_knobs(&self, knobs: Knobs) {
        lock(&self.shared.config).knobs = knobs;
    }

    /// Replaces the security list for new connections.
    pub fn set_security(&self, security: Vec<SecurityOffer>) {
        lock(&self.shared.config).security = security;
    }

    /// Snapshot of the framebuffer (RGBA).
    pub fn framebuffer(&self) -> Framebuffer {
        lock(&self.shared.fb).clone()
    }

    /// Fills `r` with `rgba` and marks it dirty for every connection.
    pub fn fill(&self, r: Rect, rgba: [u8; 4]) {
        let r = lock(&self.shared.fb).fill(r, rgba);
        if let Some(r) = r {
            let _ = self.shared.events.send(Event::Dirty(r));
        }
    }

    /// Writes RGBA pixels (`r.w * r.h * 4` bytes) into `r`.
    pub fn blit(&self, r: Rect, rgba: &[u8]) {
        let r = lock(&self.shared.fb).blit(r, rgba);
        if let Some(r) = r {
            let _ = self.shared.events.send(Event::Dirty(r));
        }
    }

    /// Copies `dst.w × dst.h` pixels from `(src_x, src_y)` to `dst`; sent as CopyRect to clients
    /// that advertise it, as a dirty rect otherwise.
    pub fn copy(&self, dst: Rect, src_x: u16, src_y: u16) {
        if lock(&self.shared.fb).copy(dst, src_x, src_y) {
            let _ = self.shared.events.send(Event::Copy { dst, src_x, src_y });
        }
    }

    /// Resizes the framebuffer (synthetic content); announced with DesktopSize or
    /// ExtendedDesktopSize to clients that advertise one of them.
    pub fn resize(&self, w: u16, h: u16) {
        *lock(&self.shared.fb) = Framebuffer::synthetic(w, h);
        let _ = self.shared.events.send(Event::Resized);
    }

    /// Sends `ServerCutText` (Latin-1 bytes) to every connected client.
    pub fn server_cut_text(&self, latin1: &[u8]) {
        let _ = self.shared.events.send(Event::CutText(latin1.to_vec()));
    }
}
