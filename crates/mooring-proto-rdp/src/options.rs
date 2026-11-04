//! What the Tauri layer hands to [`crate::RdpSession::connect`] besides `ConnectParams`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mooring_core::options::RdpConnOptions;
use mooring_core::SessionAudit;

/// The OS clipboard, implemented by the Tauri layer (`clipboard.rs`, arboard). This crate
/// never links a clipboard library: it calls these from `spawn_blocking`.
pub trait LocalClipboard: Send + Sync + std::fmt::Debug {
    /// Current OS clipboard text, if any (local → remote on `ClipboardOffer`).
    fn read_text(&self) -> Option<String>;
    /// Put remote-originated text on the OS clipboard (the implementation records its digest
    /// for `clear_if_unchanged` on lock / exit).
    fn write_text(&self, text: &str);
}

/// Per-connection options.
#[derive(Debug, Clone)]
pub struct RdpOptions {
    /// `$APP_DATA/known_rdp_certs` (`CertProtocol::Rdp.file_name()`).
    pub known_certs: PathBuf,
    /// The connection's `options_json` (validated again at connect).
    pub conn: RdpConnOptions,
    /// OS clipboard; `None` disables cliprdr regardless of `conn.clipboard`.
    pub clipboard: Option<Arc<dyn LocalClipboard>>,
    /// TCP connect timeout (default 15 s).
    pub connect_timeout: Duration,
    /// Whole handshake timeout: TLS + NLA + capability exchange (default 30 s). Time spent
    /// waiting for the user at a prompt is not counted.
    pub handshake_timeout: Duration,
    /// TCP keepalive idle time (default 30 s); `None` disables it.
    pub keepalive: Option<Duration>,
    /// Client computer name sent to the server (≤ 15 chars, default `MOORING`).
    pub client_name: String,
}

impl RdpOptions {
    /// Defaults for everything but the trust store path and the connection options.
    pub fn new(known_certs: impl Into<PathBuf>, conn: RdpConnOptions) -> Self {
        Self {
            known_certs: known_certs.into(),
            conn,
            clipboard: None,
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(30),
            keepalive: Some(Duration::from_secs(30)),
            client_name: "MOORING".to_owned(),
        }
    }

    /// Attach the OS clipboard.
    #[must_use]
    pub fn with_clipboard(mut self, clipboard: Arc<dyn LocalClipboard>) -> Self {
        self.clipboard = Some(clipboard);
        self
    }
}

/// Shared, append-only audit buffer. The session pushes; the Tauri layer drains it either
/// through `Session::take_audit_events` or through its own clone (useful while the session is
/// owned by a task). Events never carry secret material or clipboard text.
#[derive(Debug, Clone, Default)]
pub struct AuditSink(Arc<Mutex<Vec<SessionAudit>>>);

impl AuditSink {
    /// Empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one event.
    pub fn push(&self, event: SessionAudit) {
        tracing::info!(action = event.action(), "rdp audit event");
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(event);
    }

    /// Drain everything recorded so far.
    pub fn take(&self) -> Vec<SessionAudit> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}
