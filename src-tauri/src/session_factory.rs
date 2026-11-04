//! Constructors of graphical sessions (RDP, VNC) behind one small trait, so the Tauri layer
//! can be tested with scripted sessions (ADR-0011 R2). [`BuiltinFactory`] builds the real
//! `mooring_proto_rdp::RdpSession` / `mooring_proto_vnc::VncSession`.
//!
//! Trust (R2 contract): the protocol crates only *read* `known_*_certs` and emit the
//! `certificate_trust` prompt; the Tauri layer writes the pin and audits the answer
//! (`graphical_task`), then reconnects with `trusted_once` when the pin could not be saved.
//! View-only is enforced once, in the Tauri gate (`session_set_view_only` toggles it), so the
//! VNC crate's own switch is started off.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use mooring_core::frame::FrameSink;
use mooring_core::session::{ConnectParams, Session};
use mooring_core::{Protocol, ProtocolOptions};

use mooring_core::AuditBuffer;

use crate::clipboard::Clipboard;
use crate::error::{IpcError, IpcResult};

/// Everything a graphical protocol crate gets for one connect attempt. A reconnect builds a
/// fresh one (the credential is resolved from the vault again, ADR-0011).
pub struct GraphicalConnect {
    /// `Rdp` or `Vnc`.
    pub protocol: Protocol,
    /// Host, port, resolved secret, desktop size (pixels).
    pub params: ConnectParams,
    /// The connection's validated options (`ProtocolOptions::Rdp` / `::Vnc`).
    pub options: ProtocolOptions,
    /// `$APP_DATA/known_rdp_certs` or `known_vnc_certs`. The protocol crate reads it; the
    /// Tauri layer writes pins after a `certificate_trust` prompt.
    pub known_certs: PathBuf,
    /// Framebuffer the protocol draws into; the same sink survives reconnects.
    pub frames: FrameSink,
    /// OS clipboard; writes are tracked so a lock clears remote text.
    pub clipboard: Arc<dyn Clipboard>,
    /// Accept exactly this leaf (SHA-256 of the DER) for this one connect: the user said `yes`
    /// to a `certificate_trust` prompt but the pin could not be written.
    pub trusted_once: Option<[u8; 32]>,
}

impl std::fmt::Debug for GraphicalConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphicalConnect")
            .field("protocol", &self.protocol)
            .field("params", &self.params)
            .field("trusted_once", &self.trusted_once.is_some())
            .finish_non_exhaustive()
    }
}

/// A connect in progress.
pub type ConnectFuture = Pin<Box<dyn Future<Output = IpcResult<Box<dyn Session>>> + Send>>;

/// Opens graphical sessions. Like `SshSession::connect`, the future resolves once the TCP
/// connection is up; handshake, trust and authentication continue in the session task.
pub trait SessionFactory: Send + Sync {
    /// Connect `req.protocol`.
    fn connect(&self, req: GraphicalConnect) -> ConnectFuture;
}

/// The production factory.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuiltinFactory;

/// [`mooring_core::clipboard::Clipboard`] over the Tauri clipboard: reads for
/// `ClipboardOffer`, writes through the tracked [`crate::clipboard::RemoteClipboard`] so a lock
/// clears remote text. Errors are logged by the inner clipboard, never the text.
#[derive(Clone)]
pub struct SessionClipboard(pub Arc<dyn Clipboard>);

impl std::fmt::Debug for SessionClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionClipboard").finish_non_exhaustive()
    }
}

impl mooring_core::clipboard::Clipboard for SessionClipboard {
    fn read_text(&self) -> Option<String> {
        self.0.text().ok().flatten().map(|t| t.as_str().to_owned())
    }

    fn write_text(&self, text: &str) -> bool {
        self.0.set(text).is_ok()
    }
}

fn wrong_options() -> IpcError {
    IpcError::invalid("options", "do not match the protocol")
}

async fn connect_rdp(req: GraphicalConnect) -> IpcResult<Box<dyn Session>> {
    let ProtocolOptions::Rdp(conn) = req.options else { return Err(wrong_options()) };
    let mut options = mooring_proto_rdp::RdpOptions::new(req.known_certs, conn)
        .with_clipboard(Arc::new(SessionClipboard(req.clipboard)));
    options.trusted_once = req.trusted_once;
    let session =
        mooring_proto_rdp::RdpSession::connect(req.params, options, req.frames, AuditBuffer::new())
            .await
            .map_err(IpcError::from)?;
    Ok(Box::new(session))
}

async fn connect_vnc(req: GraphicalConnect) -> IpcResult<Box<dyn Session>> {
    let ProtocolOptions::Vnc(mut conn) = req.options else { return Err(wrong_options()) };
    // View-only lives in the Tauri gate (initialised from `conn.view_only`, toggled by
    // `session_set_view_only`); a second switch here could not be turned off from IPC.
    conn.view_only = false;
    let mut options = mooring_proto_vnc::VncOptions::new(req.known_certs, conn);
    options.clipboard = Arc::new(SessionClipboard(req.clipboard));
    options.trusted_once = req.trusted_once;
    let session =
        mooring_proto_vnc::VncSession::connect(req.params, options, req.frames, AuditBuffer::new())
            .await
            .map_err(IpcError::from)?;
    Ok(Box::new(session))
}

impl SessionFactory for BuiltinFactory {
    fn connect(&self, req: GraphicalConnect) -> ConnectFuture {
        Box::pin(async move {
            match req.protocol {
                Protocol::Rdp => connect_rdp(req).await,
                Protocol::Vnc => connect_vnc(req).await,
                other => Err(IpcError::session_failed(format!(
                    "{} is not a graphical protocol",
                    other.name()
                ))),
            }
        })
    }
}

// --- ADR-0014 K4: Kubernetes exec shells are ordinary terminal sessions ----------------
/// Open an exec shell through a connected cluster client, boxed like every other session.
/// Errors come back before a session exists (`KubeError`, mapped by the caller).
pub async fn kube_exec(
    client: &mooring_proto_kube::KubeClient,
    target: mooring_proto_kube::ExecTarget,
    size: mooring_core::session::Size,
) -> Result<Box<dyn Session>, mooring_proto_kube::KubeError> {
    Ok(Box::new(client.exec(target, Some(size)).await?))
}
// --- end ADR-0014 K4 ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::session::{ConnectSecret, Size};

    fn req(protocol: Protocol, options: ProtocolOptions, port: u16) -> GraphicalConnect {
        GraphicalConnect {
            protocol,
            params: ConnectParams {
                host: "127.0.0.1".into(),
                port,
                username: None,
                secret: ConnectSecret::None,
                r#become: None,
                size: Size { width: 800, height: 600 },
            },
            options,
            known_certs: PathBuf::from("/nonexistent/known_certs"),
            frames: FrameSink::new(),
            clipboard: Arc::new(crate::clipboard::MemoryClipboard::default()),
            trusted_once: None,
        }
    }

    #[tokio::test]
    async fn refuses_non_graphical_protocols_and_mismatched_options() {
        let ssh = req(Protocol::Ssh, ProtocolOptions::default_for(Protocol::Ssh), 22);
        assert_eq!(BuiltinFactory.connect(ssh).await.err().expect("refused").code, "session.failed");
        let wrong = req(Protocol::Rdp, ProtocolOptions::default_for(Protocol::Vnc), 3389);
        assert_eq!(BuiltinFactory.connect(wrong).await.err().expect("refused").code, "input.invalid");
        // RDP refuses ConnectSecret::None at connect (input error, before any TCP).
        let none = req(Protocol::Rdp, ProtocolOptions::default_for(Protocol::Rdp), 3389);
        assert_eq!(BuiltinFactory.connect(none).await.err().expect("refused").code, "input.invalid");
        let port0 = req(Protocol::Vnc, ProtocolOptions::default_for(Protocol::Vnc), 0);
        assert_eq!(BuiltinFactory.connect(port0).await.err().expect("refused").code, "input.invalid");
    }

    #[tokio::test]
    async fn vnc_connects_and_reports_through_the_session() {
        // Nothing listens on a fresh ephemeral port: the session exists and ends with network.
        let port = std::net::TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("a").port();
        let r = req(Protocol::Vnc, ProtocolOptions::default_for(Protocol::Vnc), port);
        let mut s = BuiltinFactory.connect(r).await.expect("session");
        assert_eq!(s.protocol(), Protocol::Vnc);
        let ev = tokio::time::timeout(std::time::Duration::from_secs(20), s.next_event()).await;
        let Ok(Ok(Some(mooring_core::SessionEvent::Closed { code, .. }))) = ev else { panic!("{ev:?}") };
        assert_eq!(code, mooring_core::CloseCode::Network);
    }

    #[test]
    fn session_clipboard_reads_and_writes_through_the_tracked_clipboard() {
        use mooring_core::clipboard::Clipboard as _;
        let inner = Arc::new(crate::clipboard::MemoryClipboard::default());
        let c = SessionClipboard(inner.clone());
        assert_eq!(c.read_text(), None);
        assert!(c.write_text("from remote"));
        assert_eq!(inner.peek().as_deref(), Some("from remote"));
        assert_eq!(c.read_text().as_deref(), Some("from remote"));
    }
}
