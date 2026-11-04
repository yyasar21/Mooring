//! The per-connection task: handshake (with TOFU) → authentication → shell → pump.
//!
//! This is the state machine behind `SshSession::next_event` / `send`: every state change is
//! an event on the bounded channel, and the only inputs it waits on are the TOFU / keyboard
//! prompts (through the broker) and the command channel.

use std::sync::{Arc, OnceLock};

use mooring_core::session::{Become, CloseCode, SessionEvent, Size};
use mooring_core::Protocol;
use russh::client::Handle;
use russh::Disconnect;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::auth::{authenticate, Credentials};
use crate::channel::{open_shell, pump, Command};
use crate::handler::ClientHandler;
use crate::shared::Shared;

/// The connected, authenticated russh handle, published for part b (forwarding, SFTP).
pub(crate) type HandleSlot = Arc<OnceLock<Arc<Handle<ClientHandler>>>>;

pub(crate) struct Driver {
    pub(crate) stream: TcpStream,
    pub(crate) config: russh::client::Config,
    pub(crate) handler: ClientHandler,
    pub(crate) creds: Credentials,
    pub(crate) r#become: Option<Become>,
    pub(crate) size: Size,
    pub(crate) shared: Arc<Shared>,
    pub(crate) commands: mpsc::Receiver<Command>,
    pub(crate) slot: HandleSlot,
}

impl Driver {
    pub(crate) async fn run(self) {
        let shared = Arc::clone(&self.shared);
        let (code, reason) = self.run_inner().await;
        tracing::debug!("ssh session ended");
        // Forwards and SFTP never outlive the session, however it ended.
        shared.release_channels();
        let _ = shared.events.send(SessionEvent::Closed { reason, code }).await;
    }

    async fn run_inner(self) -> (CloseCode, String) {
        let Self { stream, config, handler, creds, r#become, size, shared, mut commands, slot } =
            self;

        let mut handle =
            match russh::client::connect_stream(Arc::new(config), stream, handler).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!(error = %e, "ssh handshake failed");
                    return shared
                        .take_reason()
                        .unwrap_or_else(|| (CloseCode::Network, "connection failed".to_owned()));
                }
            };

        // `creds` is moved into the auth round and dropped (zeroized) when it returns.
        let auth = authenticate(&mut handle, creds, &shared).await;
        if let Err(e) = auth {
            let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
            return if shared.is_closing() {
                (CloseCode::User, "closed by user".to_owned())
            } else {
                (e.code(), e.reason().to_owned())
            };
        }

        let handle = Arc::new(handle);
        let channel = match open_shell(&handle, size).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "ssh shell could not be opened");
                let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                return (CloseCode::ServerEnded, "remote shell refused".to_owned());
            }
        };
        let _ = slot.set(Arc::clone(&handle));

        let connected = SessionEvent::Connected {
            protocol: Protocol::Ssh,
            peer_identity: shared.peer(),
            security: None,
        };
        if shared.events.send(connected).await.is_err() {
            return (CloseCode::User, "closed by user".to_owned());
        }

        let end = pump(channel, &mut commands, &shared.events, &shared.audit, r#become).await;
        let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
        (end.code(), end.reason())
    }
}
