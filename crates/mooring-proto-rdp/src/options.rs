//! What the Tauri layer hands to [`crate::RdpSession::connect`] besides `ConnectParams`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mooring_core::options::RdpConnOptions;
use mooring_core::transport::SharedDialer;

/// The OS clipboard, implemented by the Tauri layer (`clipboard.rs`, arboard). This crate
/// never links a clipboard library: it calls it from `spawn_blocking`. Same trait as
/// `mooring_proto_vnc::Clipboard` ([`mooring_core::clipboard::Clipboard`]).
pub use mooring_core::clipboard::Clipboard as LocalClipboard;

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
    /// Accept exactly this leaf (SHA-256 of the DER) as if pinned, for this session only: the
    /// user said `yes` to a `certificate_trust` prompt but the Tauri layer could not write the
    /// pin (`GraphicalConnect::trusted_once`).
    pub trusted_once: Option<[u8; 32]>,
    /// ADR-0025: reach the server through this dialer (a jump-host chain) instead of direct
    /// TCP. `None` = direct TCP with `keepalive`. Every reconnect dials again.
    pub dialer: Option<SharedDialer>,
    /// ADR-0027: trust store, credential and `trusted_once` of the RD Gateway named in
    /// `conn.gateway`. `None` with a gateway configured = `known_rdg_certs` next to
    /// `known_certs`, the sign-in credential, no `trusted_once`.
    pub gateway: Option<crate::gateway::GatewayConfig>,
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
            trusted_once: None,
            dialer: None,
            gateway: None,
        }
    }

    /// Reach the server through `dialer` (ADR-0025 jump hosts).
    #[must_use]
    pub fn via(mut self, dialer: SharedDialer) -> Self {
        self.dialer = Some(dialer);
        self
    }

    /// Attach the OS clipboard.
    #[must_use]
    pub fn with_clipboard(mut self, clipboard: Arc<dyn LocalClipboard>) -> Self {
        self.clipboard = Some(clipboard);
        self
    }
}

/// Shared, append-only audit buffer ([`mooring_core::AuditBuffer`], also
/// `mooring_proto_vnc::AuditLog`). The session pushes; the Tauri layer drains it through
/// `Session::take_audit_events` or its own clone. Never carries secrets or clipboard text.
pub type AuditSink = mooring_core::AuditBuffer;
