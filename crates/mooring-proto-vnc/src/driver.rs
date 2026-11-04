//! The per-connection task: credential → connect (TOFU, fallback) → set-up → control loop.
//!
//! The control loop owns the write half and paces `FramebufferUpdateRequest`s: at most
//! [`MAX_OUTSTANDING`] in flight, the next one no earlier than `1 / maxFps` after the last,
//! so a slow consumer slows the server too. The reader task owns the read half.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mooring_core::audit::ClipboardDirection;
use mooring_core::frame::{FrameSink, Rect};
use mooring_core::known_certs::peer_identity;
use mooring_core::session::{SessionEvent, SessionInput};
use mooring_core::Protocol;
use tokio::io::{AsyncWrite, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::conn::{send, Io, RecvBuf};
use crate::connect::{establish, Target};
use crate::error::VncError;
use crate::handshake::PixelFormat;
use crate::input::{button_mask, unicode_keys, KeyOut, KeyTracker, Wheel};
use crate::messages::{client, enc, string_to_latin1, MAX_CUT_TEXT};
use crate::reader::{self, ReaderEvent};
use crate::security::Credential;
use crate::session::Clipboard;
use crate::shared::{ClipAudit, Shared};

/// Most `FramebufferUpdateRequest`s in flight.
pub const MAX_OUTSTANDING: u32 = 1;
/// `SetDesktopSize` debounce (ADR-0012).
pub const RESIZE_DEBOUNCE: Duration = Duration::from_millis(300);

/// Commands from the front.
#[derive(Debug)]
pub(crate) enum Command {
    Input(SessionInput),
    Close,
}

pub(crate) struct Driver {
    pub(crate) target: Target,
    pub(crate) cred: CredSource,
    pub(crate) sink: FrameSink,
    pub(crate) clipboard: Arc<dyn Clipboard>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) commands: mpsc::Receiver<Command>,
}

/// The credential, or the connect-time form to ask for it.
pub(crate) enum CredSource {
    Ready(Credential),
    Ask(mooring_core::session::PromptAccount),
}

impl Driver {
    pub(crate) async fn run(mut self) {
        let shared = Arc::clone(&self.shared);
        let end = self.run_inner().await;
        tracing::debug!(code = ?end.code(), "vnc session ended");
        shared.cancel_prompt();
        let _ = shared
            .events
            .send(SessionEvent::Closed { reason: end.reason(), code: end.code() })
            .await;
    }

    async fn run_inner(&mut self) -> VncError {
        let cred = match std::mem::replace(&mut self.cred, CredSource::Ready(Credential::None)) {
            CredSource::Ready(c) => c,
            CredSource::Ask(account) => match self.shared.ask_credential(account).await {
                Some((user, password)) if !user.is_empty() => {
                    Credential::UserPassword { user, password }
                }
                Some((_, password))
                    if !secrecy::ExposeSecret::expose_secret(&password).is_empty() =>
                {
                    Credential::Password(password)
                }
                _ => return VncError::User,
            },
        };
        let established = tokio::select! {
            r = establish(&self.target, &cred, &self.shared) => match r {
                Ok(e) => e,
                Err(e) => return e,
            },
            () = wait_close(&mut self.commands) => return VncError::User,
        };
        // The secret is not needed past authentication.
        drop(cred);
        let crate::connect::Established { conn, init, security, tls_fp } = established;
        if let Err(e) = self.sink.resize(init.width, init.height) {
            return VncError::protocol(format!("frame: {e}"));
        }
        let (io, leftover) = conn.into_parts();
        let (rd, mut wr) = tokio::io::split(io);
        let setup = [
            client::set_pixel_format(&PixelFormat::RGBX),
            client::set_encodings(&enc::ADVERTISED),
            client::update_request(false, Rect::new(0, 0, init.width, init.height)),
        ]
        .concat();
        if let Err(e) = send(&mut wr, &setup).await {
            return e;
        }
        let connected = SessionEvent::Connected {
            protocol: Protocol::Vnc,
            peer_identity: tls_fp.as_ref().map(peer_identity),
            security: Some(security.to_owned()),
        };
        let resized =
            SessionEvent::DesktopResized { width: init.width.into(), height: init.height.into() };
        if self.shared.events.send(connected).await.is_err()
            || self.shared.events.send(resized).await.is_err()
        {
            return VncError::User;
        }
        let (tx, rx) = mpsc::channel(64);
        let rb = RecvBuf::with_leftover(rd, leftover, crate::conn::HANDSHAKE_MAX);
        let reader = tokio::spawn(reader::run(rb, self.sink.clone(), tx));
        let mut lp = Loop::new(self, wr);
        let end = lp.run(rx).await;
        lp.clip.flush(&lp.d.shared.audit);
        reader.abort();
        end
    }
}

struct Loop<'a> {
    d: &'a mut Driver,
    wr: WriteHalf<Box<dyn Io>>,
    keys: KeyTracker,
    wheel: Wheel,
    clip: ClipAudit,
    buttons: u8,
    pos: (u16, u16),
    outstanding: u32,
    last_request: Instant,
    full_next: bool,
    next_request: Option<Instant>,
    ext_screen: Option<(u32, u32)>,
    pending_resize: Option<(u16, u16, Instant)>,
    qemu_keys: bool,
}

impl<'a> Loop<'a> {
    fn new(d: &'a mut Driver, wr: WriteHalf<Box<dyn Io>>) -> Self {
        Self {
            d,
            wr,
            keys: KeyTracker::default(),
            wheel: Wheel::default(),
            clip: ClipAudit::default(),
            buttons: 0,
            pos: (0, 0),
            outstanding: 1,
            last_request: Instant::now(),
            full_next: false,
            next_request: None,
            ext_screen: None,
            pending_resize: None,
            qemu_keys: false,
        }
    }

    async fn run(&mut self, mut rx: mpsc::Receiver<ReaderEvent>) -> VncError {
        loop {
            let deadline =
                [self.next_request, self.pending_resize.map(|p| p.2)].into_iter().flatten().min();
            let r = tokio::select! {
                ev = rx.recv() => match ev {
                    Some(ev) => self.on_reader(ev).await,
                    None => Err(VncError::Network("reader stopped".into())),
                },
                cmd = self.d.commands.recv() => match cmd {
                    Some(Command::Input(i)) => self.on_input(i).await,
                    Some(Command::Close) | None => Err(VncError::User),
                },
                () = sleep_until(deadline), if deadline.is_some() => self.on_timer().await,
            };
            if let Err(e) = r {
                return e;
            }
        }
    }

    async fn write(&mut self, msg: &[u8]) -> Result<(), VncError> {
        write_to(&mut self.wr, msg).await
    }

    async fn on_reader(&mut self, ev: ReaderEvent) -> Result<(), VncError> {
        match ev {
            ReaderEvent::UpdateDone => {
                self.outstanding = self.outstanding.saturating_sub(1);
                let interval = self.d.target.conn.max_fps.interval();
                self.next_request = Some((self.last_request + interval).max(Instant::now()));
            }
            ReaderEvent::Resized { w, h } => {
                self.full_next = true;
                let ev = SessionEvent::DesktopResized { width: w.into(), height: h.into() };
                self.d.shared.events.send(ev).await.map_err(|_| VncError::User)?;
            }
            ReaderEvent::ExtDesktop(screen) => self.ext_screen = Some(screen),
            ReaderEvent::QemuExtKey => self.qemu_keys = true,
            ReaderEvent::CutText(text) => {
                if self.d.target.conn.clipboard.allows_from_remote() && !text.is_empty() {
                    if self.d.clipboard.write_text(&text) {
                        let n = u64::try_from(text.len()).unwrap_or(u64::MAX);
                        self.clip.record(&self.d.shared.audit, ClipboardDirection::FromRemote, n);
                    }
                } else {
                    tracing::debug!("vnc: server cut text dropped by policy");
                }
            }
            ReaderEvent::Bell => tracing::debug!("vnc: bell"),
            ReaderEvent::Failed(e) => return Err(e),
        }
        Ok(())
    }

    async fn on_timer(&mut self) -> Result<(), VncError> {
        let now = Instant::now();
        if self.next_request.is_some_and(|t| t <= now) && self.outstanding < MAX_OUTSTANDING {
            self.next_request = None;
            let (w, h) = self.d.sink.size();
            let incremental = !std::mem::take(&mut self.full_next);
            self.write(&client::update_request(incremental, Rect::new(0, 0, w, h))).await?;
            self.outstanding += 1;
            self.last_request = now;
        }
        if let Some((w, h, at)) = self.pending_resize {
            if at <= now {
                self.pending_resize = None;
                if let Some((id, flags)) = self.ext_screen {
                    self.write(&client::set_desktop_size(w, h, id, flags)).await?;
                }
            }
        }
        Ok(())
    }

    async fn on_input(&mut self, input: SessionInput) -> Result<(), VncError> {
        // Defence in depth: the front already dropped inputs that arrived in view-only.
        if self.d.shared.view_only.load(Ordering::Relaxed)
            && !matches!(input, SessionInput::ReleaseAll)
        {
            return Ok(());
        }
        match input {
            SessionInput::Key { code, key, pressed } => {
                if let Some(k) = self.keys.key(&code, &key, pressed) {
                    self.send_key(k).await?;
                }
            }
            SessionInput::Unicode { text } => {
                for k in unicode_keys(&text) {
                    self.send_key(k).await?;
                }
            }
            SessionInput::Pointer { x, y, buttons } => {
                let (w, h) = self.d.sink.size();
                let clamp = |v: u32, max: u16| {
                    u16::try_from(v).unwrap_or(u16::MAX).min(max.saturating_sub(1))
                };
                self.pos = (clamp(x, w), clamp(y, h));
                self.buttons = button_mask(buttons);
                self.write(&client::pointer_event(self.buttons, self.pos.0, self.pos.1)).await?;
            }
            SessionInput::Wheel { dx, dy } => {
                let mut msg = Vec::new();
                for bit in self.wheel.feed(dx, dy) {
                    msg.extend(client::pointer_event(self.buttons | bit, self.pos.0, self.pos.1));
                    msg.extend(client::pointer_event(self.buttons, self.pos.0, self.pos.1));
                }
                if !msg.is_empty() {
                    self.write(&msg).await?;
                }
            }
            SessionInput::ReleaseAll => {
                for k in self.keys.release_all() {
                    self.send_key(k).await?;
                }
                if self.buttons != 0 {
                    self.buttons = 0;
                    self.write(&client::pointer_event(0, self.pos.0, self.pos.1)).await?;
                }
            }
            SessionInput::ClipboardOffer => self.offer_clipboard().await?,
            SessionInput::Resize { size } => {
                let ok = |v: u32| {
                    u16::try_from(v).ok().filter(|v| (1..=mooring_core::frame::MAX_DIM).contains(v))
                };
                if let (Some(w), Some(h), Some(_)) =
                    (ok(size.width), ok(size.height), self.ext_screen)
                {
                    self.pending_resize = Some((w, h, Instant::now() + RESIZE_DEBOUNCE));
                }
            }
            SessionInput::Bytes { .. }
            | SessionInput::Answer { .. }
            | SessionInput::CredentialAnswer { .. } => {}
        }
        Ok(())
    }

    async fn send_key(&mut self, k: KeyOut) -> Result<(), VncError> {
        let msg = if self.qemu_keys && k.scancode != 0 {
            client::qemu_key_event(k.down, k.keysym, k.scancode)
        } else {
            client::key_event(k.down, k.keysym)
        };
        self.write(&msg).await
    }

    async fn offer_clipboard(&mut self) -> Result<(), VncError> {
        if !self.d.target.conn.clipboard.allows_to_remote() {
            return Ok(());
        }
        let Some(text) = self.d.clipboard.read_text() else { return Ok(()) };
        let Some(latin1) = string_to_latin1(&text) else {
            tracing::debug!("vnc: clipboard text is not Latin-1; not sent");
            return Ok(());
        };
        if latin1.is_empty() || latin1.len() > MAX_CUT_TEXT {
            return Ok(());
        }
        self.write(&client::cut_text(&latin1)).await?;
        let n = u64::try_from(text.len()).unwrap_or(u64::MAX);
        self.clip.record(&self.d.shared.audit, ClipboardDirection::ToRemote, n);
        Ok(())
    }
}

async fn write_to<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> Result<(), VncError> {
    send(w, msg).await
}

/// Resolves on `Close` (or a dropped front); inputs before `Connected` are discarded.
async fn wait_close(commands: &mut mpsc::Receiver<Command>) {
    while let Some(c) = commands.recv().await {
        if matches!(c, Command::Close) {
            return;
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}
