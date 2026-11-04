//! Constructors of graphical sessions (RDP, VNC) behind one small trait, so the Tauri shell
//! compiles and is tested without `mooring-proto-rdp` / `mooring-proto-vnc` (ADR-0011 R2).
//!
//! **Merge hook (R3/R4):** replace the two `unavailable(..)` arms in
//! [`BuiltinFactory::connect`] with the real constructors, e.g.
//! `mooring_proto_rdp::RdpSession::connect(req.params, RdpOptions { .. }).await` boxed as
//! `Box<dyn Session>`, mapping `MooringError` with `IpcError::from`. Everything a protocol
//! needs is in [`GraphicalConnect`].

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use mooring_core::frame::FrameSink;
use mooring_core::session::{ConnectParams, Session};
use mooring_core::{Protocol, ProtocolOptions};

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

fn unavailable(name: &str) -> IpcError {
    IpcError::new("protocol.unavailable", format!("{name} sessions are not available in this build"))
}

impl SessionFactory for BuiltinFactory {
    fn connect(&self, req: GraphicalConnect) -> ConnectFuture {
        Box::pin(async move {
            match req.protocol {
                // MERGE R3: mooring_proto_rdp::RdpSession::connect(..)
                Protocol::Rdp => Err(unavailable("RDP")),
                // MERGE R4: mooring_proto_vnc::VncSession::connect(..)
                Protocol::Vnc => Err(unavailable("VNC")),
                other => Err(IpcError::session_failed(format!(
                    "{} is not a graphical protocol",
                    other.name()
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::session::{ConnectSecret, Size};

    #[tokio::test]
    async fn stubs_report_protocol_unavailable() {
        for (protocol, code) in [
            (Protocol::Rdp, "protocol.unavailable"),
            (Protocol::Vnc, "protocol.unavailable"),
            (Protocol::Ssh, "session.failed"),
        ] {
            let req = GraphicalConnect {
                protocol,
                params: ConnectParams {
                    host: "rdp.example.test".into(),
                    port: 3389,
                    username: None,
                    secret: ConnectSecret::None,
                    r#become: None,
                    size: Size { width: 800, height: 600 },
                },
                options: ProtocolOptions::default_for(protocol),
                known_certs: PathBuf::from("known_rdp_certs"),
                frames: FrameSink::new(),
                clipboard: Arc::new(crate::clipboard::MemoryClipboard::default()),
                trusted_once: None,
            };
            let e = BuiltinFactory.connect(req).await.err().expect("refused");
            assert_eq!(e.code, code);
        }
    }
}
