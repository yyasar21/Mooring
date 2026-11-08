//! `RdpSession`: the `mooring_core::session::Session` implementation for RDP.
//!
//! `connect` validates its inputs and returns at once; the handshake runs in a driver task
//! whose progress arrives through `next_event`:
//! `Prompt`* → `Connected` → `DesktopResized`+ → `Closed`. Pixels and the cursor never travel
//! as events: they go to the `FrameSink`. Prompts are answered with `send(Answer)` /
//! `send(CredentialAnswer)`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mooring_core::session::{CloseCode, ConnectParams, Session, SessionEvent, SessionInput};
use mooring_core::{validate_host, FrameSink, MooringError, Protocol, SessionAudit};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::active::Command;
use crate::connect::{clamp_desktop, Target};
use crate::creds::from_params;
use crate::driver::Driver;
use crate::options::{AuditSink, RdpOptions};
use crate::shared::{Reply, Shared};

/// Capacity of the event and command channels (back-pressure bound).
pub const CHANNEL_CAPACITY: usize = 256;
/// How long `close` waits for a clean shutdown before aborting the task.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// A live RDP session.
pub struct RdpSession {
    shared: Arc<Shared>,
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
    final_event: Option<SessionEvent>,
    closed: bool,
}

impl std::fmt::Debug for RdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpSession")
            .field("connected", &self.shared.is_connected())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

fn invalid(field: &'static str, reason: &str) -> MooringError {
    MooringError::Invalid { field, reason: reason.to_owned() }
}

impl RdpSession {
    /// Validate and start a session (the constructor R2 calls).
    ///
    /// - `params`: host, port, username and the vault-resolved secret
    ///   (`Password` / `DomainPassword` / `Prompt`; anything else is `Invalid`). `params.size`
    ///   is the initial desktop size (clamped to 200–8192, even width).
    /// - `options`: trust store path, `RdpConnOptions` (validated again here), the OS
    ///   clipboard and timeouts.
    /// - `sink`: where bitmaps and the cursor go; resized by the session.
    /// - `audit`: trust, auth, legacy-security and clipboard events are pushed here; the same
    ///   buffer is drained by `Session::take_audit_events`.
    ///
    /// Returns immediately; errors here are input errors only. Everything that happens on the
    /// wire is reported as events, ending with `Closed { reason, code }`.
    pub async fn connect(
        params: ConnectParams,
        options: RdpOptions,
        sink: FrameSink,
        audit: AuditSink,
    ) -> Result<Self, MooringError> {
        let ConnectParams { host, port, username, secret, r#become, size } = params;
        let host = validate_host(&host)?;
        if port == 0 {
            return Err(invalid("port", "must be 1-65535"));
        }
        if r#become.is_some() {
            return Err(invalid("become", "not supported by rdp"));
        }
        options.conn.validate()?;
        if crate::tls::server_name(&host).is_none() {
            return Err(invalid("host", "not a valid TLS server name"));
        }
        let source = from_params(username.as_deref(), secret)?;

        let RdpOptions {
            known_certs,
            conn,
            clipboard,
            connect_timeout,
            handshake_timeout,
            keepalive,
            client_name,
            trusted_once,
            dialer,
            gateway,
        } = options;
        let policy = conn.clipboard;
        let gateway = conn.gateway.clone().map(|opts| {
            let cfg = gateway.unwrap_or_else(|| crate::gateway::GatewayConfig {
                known_certs: known_certs.with_file_name("known_rdg_certs"),
                credential: Arc::new(crate::gateway::GatewayCredential::SameAsSignIn),
                trusted_once: None,
            });
            crate::gateway::open::GatewayTarget {
                opts,
                known_certs: cfg.known_certs,
                credential: cfg.credential,
                session_pin: cfg.trusted_once,
            }
        });
        let target = Target {
            host,
            port,
            conn,
            known_certs,
            connect_timeout,
            dialer: dialer
                .unwrap_or_else(|| Arc::new(crate::connect::TcpKeepaliveDialer { keepalive })),
            client_name,
            desktop: clamp_desktop(size.width, size.height),
            session_pin: trusted_once,
            gateway,
        };
        let (event_tx, events) = mpsc::channel(CHANNEL_CAPACITY);
        let (commands, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let shared = Arc::new(Shared::new(event_tx, audit));
        let driver = Driver {
            target,
            source,
            shared: Arc::clone(&shared),
            sink,
            commands: command_rx,
            clipboard,
            policy,
            handshake_timeout,
        };
        let task = tokio::spawn(driver.run());
        Ok(Self { shared, events, commands, task: Some(task), final_event: None, closed: false })
    }
}

#[async_trait]
impl Session for RdpSession {
    fn protocol(&self) -> Protocol {
        Protocol::Rdp
    }

    fn take_audit_events(&mut self) -> Vec<SessionAudit> {
        self.shared.audit.take()
    }

    async fn send(&mut self, input: SessionInput) -> Result<(), MooringError> {
        if self.closed {
            return Err(MooringError::Closed);
        }
        input.validate()?;
        match input {
            SessionInput::Answer { id, text } => {
                if self.shared.answer(id, Reply::Text(text)) {
                    Ok(())
                } else {
                    Err(invalid("prompt id", "no open prompt with this id"))
                }
            }
            SessionInput::CredentialAnswer { id, username, domain, password } => {
                if self.shared.answer(id, Reply::Credential { username, domain, password }) {
                    Ok(())
                } else {
                    Err(invalid("prompt id", "no open prompt with this id"))
                }
            }
            SessionInput::Bytes { .. } => Err(invalid("input", "not supported by rdp")),
            // Input before `Connected` has nowhere to go; dropping it keeps the UI from
            // blocking on a full channel during the handshake.
            _ if !self.shared.is_connected() => Ok(()),
            other => {
                self.commands.send(Command::Input(other)).await.map_err(|_| MooringError::Closed)
            }
        }
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, MooringError> {
        if let Some(event) = self.final_event.take() {
            return Ok(Some(event));
        }
        if self.closed {
            return Ok(None);
        }
        // L-21: a panicked driver becomes one `Closed { protocol_error }`, never retried.
        let event =
            mooring_core::driver_task::next_driver_event(&mut self.events, &mut self.task, "RDP")
                .await;
        if matches!(event, Some(SessionEvent::Closed { .. }) | None) {
            self.closed = true;
            self.shared.begin_close();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
        }
        Ok(event)
    }

    async fn close(&mut self) -> Result<(), MooringError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.commands.try_send(Command::Close);
        self.shared.begin_close();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        let deadline = tokio::time::sleep(CLOSE_GRACE);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut task => break,
                event = self.events.recv() => match event {
                    Some(e @ SessionEvent::Closed { .. }) => self.final_event = Some(e),
                    Some(_) => {}
                    None => break,
                },
                () = &mut deadline => {
                    task.abort();
                    break;
                }
            }
        }
        if self.final_event.is_none() {
            self.final_event = Some(SessionEvent::Closed {
                reason: "closed by user".to_owned(),
                code: CloseCode::User,
            });
        }
        Ok(())
    }
}

impl Drop for RdpSession {
    fn drop(&mut self) {
        self.shared.begin_close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
