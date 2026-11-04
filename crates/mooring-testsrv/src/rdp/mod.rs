//! RDP test server built on `ironrdp-acceptor` 0.12 (the ADR-0011 generation).
//!
//! The acceptor runs the X.224 / MCS / CredSSP / capability / finalization sequence; this
//! module adds what `ironrdp-server` would (it is a different, older IronRDP generation that
//! drags in `reqwest`): TLS via rustls, a synthetic framebuffer sent as fast-path bitmap
//! updates (uncompressed 32 bpp or RDP 6.0 planar), input receipt, a `cliprdr` text channel
//! and a Display Control DVC that records monitor layouts. See docs/qa/test-servers.md for
//! what it can and cannot exercise.
//!
//! IronRDP futures are `!Send`, so the server runs on its own thread with a current-thread
//! Tokio runtime and a `LocalSet`; the handle works from any runtime.

mod active;
mod bitmap;
mod channels;
mod conn;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{broadcast, watch};

pub use crate::rfb::{Framebuffer, Rect};
use crate::tls::TestCert;

/// Security protocol the acceptor offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpSecurity {
    /// `PROTOCOL_SSL`: TLS, then the credentials arrive in Client Info (legacy, "TLS without NLA").
    Tls,
    /// `PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX`: TLS + CredSSP (NTLM) — NLA.
    Nla,
}

/// How bitmap updates are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BitmapMode {
    /// Uncompressed 32 bpp (BGRX, bottom-up).
    #[default]
    Raw,
    /// RDP 6.0 planar codec (`BITMAP_COMPRESSION` at 32 bpp) with RLE, for tiles whose width
    /// is a multiple of 4; other tiles fall back to raw.
    Planar,
}

/// Hostile / unusual behaviour (all off by default).
#[derive(Debug, Clone, Copy, Default)]
pub struct RdpKnobs {
    /// Every bitmap update also carries a tile that extends this many pixels past the desktop.
    pub out_of_bounds_bitmap: Option<u16>,
    /// Close the TCP connection right after the connection sequence (no bitmap).
    pub drop_after_accept: bool,
}

#[derive(Debug, Clone)]
pub struct RdpConfig {
    pub width: u16,
    pub height: u16,
    pub security: RdpSecurity,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    /// Generated when `None`.
    pub cert: Option<TestCert>,
    pub bitmap: BitmapMode,
    /// Offer the `cliprdr` static channel.
    pub clipboard: bool,
    /// Offer `drdynvc` with the Display Control channel.
    pub display_control: bool,
    pub knobs: RdpKnobs,
}

impl Default for RdpConfig {
    fn default() -> Self {
        Self {
            width: 640,
            height: 480,
            security: RdpSecurity::Nla,
            username: "alice".to_owned(),
            password: "correct horse".to_owned(),
            domain: None,
            cert: None,
            bitmap: BitmapMode::Raw,
            clipboard: true,
            display_control: true,
            knobs: RdpKnobs::default(),
        }
    }
}

/// One received input event (fast-path or slow-path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputRecord {
    /// Scancode, `true` = released.
    Key {
        code: u8,
        extended: bool,
        release: bool,
    },
    Unicode {
        code: u16,
        release: bool,
    },
    /// Absolute pointer: raw `PointerFlags` bits, position, wheel units.
    Mouse {
        flags: u16,
        x: u16,
        y: u16,
        wheel: i16,
    },
    Sync(u32),
}

#[derive(Debug, Clone, Default)]
pub struct RdpStats {
    pub connections: u32,
    /// Connection sequences that reached the active stage.
    pub accepted: u32,
    /// Failed sequences (TLS, CredSSP, finalization) with the error text.
    pub errors: Vec<String>,
    /// Selected protocol per accepted connection (`"ssl"`, `"hybrid"`, `"hybrid_ex"`).
    pub security: Vec<String>,
    pub keyboard_layout: Option<u32>,
    pub client_desktop: Option<(u16, u16)>,
    pub inputs: Vec<InputRecord>,
    pub bitmap_updates: u32,
    /// Tiles sent planar-compressed (the rest went raw).
    pub planar_tiles: u32,
    /// Text the client copied (CF_UNICODETEXT, decoded).
    pub clipboard_from_client: Vec<String>,
    /// Times the client fetched the server's clipboard text.
    pub clipboard_served: u32,
    /// Display Control monitor layouts `(w, h)` (primary monitor).
    pub layouts: Vec<(u32, u32)>,
    pub shutdown_requests: u32,
}

#[derive(Debug, Clone)]
pub(crate) enum Event {
    Dirty(Rect),
    ClipboardOffer,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) config: RdpConfig,
    pub(crate) tls: Arc<rustls::ServerConfig>,
    pub(crate) fb: Mutex<Framebuffer>,
    pub(crate) stats: Mutex<RdpStats>,
    pub(crate) events: broadcast::Sender<Event>,
    /// Text the server offers (served on a client's Format Data Request).
    pub(crate) clipboard: Mutex<Option<String>>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A running RDP test server; dropping it stops the accept loop and its thread.
#[derive(Debug)]
pub struct RdpHandle {
    addr: SocketAddr,
    cert: TestCert,
    shared: Arc<Shared>,
    stop: Option<watch::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Starts the server on `127.0.0.1:port` (`0` = ephemeral) on a dedicated thread.
pub fn start(mut config: RdpConfig, port: u16) -> std::io::Result<RdpHandle> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(std::io::Error::other)?,
    };
    config.cert = Some(cert.clone());
    let tls = cert.server_config().map_err(std::io::Error::other)?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let (events, _) = broadcast::channel(1024);
    let shared = Arc::new(Shared {
        fb: Mutex::new(Framebuffer::synthetic(config.width, config.height)),
        config,
        tls,
        stats: Mutex::new(RdpStats::default()),
        events,
        clipboard: Mutex::new(None),
    });
    let (stop, stopped) = watch::channel(());
    let thread_shared = Arc::clone(&shared);
    let thread = std::thread::Builder::new().name("rdp-testsrv".to_owned()).spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
            return;
        };
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, conn::accept_loop(thread_shared, listener, stopped));
    })?;
    Ok(RdpHandle { addr, cert, shared, stop: Some(stop), thread: Some(thread) })
}

impl RdpHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The certificate the server presents (TOFU pin tests, CredSSP public key).
    pub fn cert(&self) -> &TestCert {
        &self.cert
    }

    pub fn stats(&self) -> RdpStats {
        lock(&self.shared.stats).clone()
    }

    pub fn framebuffer(&self) -> Framebuffer {
        lock(&self.shared.fb).clone()
    }

    /// Fills `r` and sends it as a bitmap update to every active connection.
    pub fn fill(&self, r: Rect, rgba: [u8; 4]) {
        if let Some(r) = lock(&self.shared.fb).fill(r, rgba) {
            let _ = self.shared.events.send(Event::Dirty(r));
        }
    }

    /// Writes RGBA pixels into `r` and sends the update.
    pub fn blit(&self, r: Rect, rgba: &[u8]) {
        if let Some(r) = lock(&self.shared.fb).blit(r, rgba) {
            let _ = self.shared.events.send(Event::Dirty(r));
        }
    }

    /// Announces `text` on the clipboard channel (Format List with CF_UNICODETEXT); the
    /// client fetches it with a Format Data Request.
    pub fn set_clipboard(&self, text: &str) {
        *lock(&self.shared.clipboard) = Some(text.to_owned());
        let _ = self.shared.events.send(Event::ClipboardOffer);
    }
}

impl Drop for RdpHandle {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
