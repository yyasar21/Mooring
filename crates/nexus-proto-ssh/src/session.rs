//! `SshSession`: the `nexus_core::session::Session` implementation for SSH.
//!
//! `connect` opens TCP and returns at once; the handshake, TOFU prompt, authentication and
//! shell run in a driver task whose progress arrives through `next_event`:
//! `Prompt`* → `Connected` → `Bytes`* → `Closed`. Prompts are answered with `send(Answer)`.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use nexus_core::session::{ConnectParams, Session, SessionEvent, SessionInput};
use nexus_core::{validate_host, NexusError, Protocol};
use russh::client::Handle;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::algos::client_config;
use crate::audit::TrustEvent;
use crate::auth::Credentials;
use crate::channel::Command;
use crate::driver::{Driver, HandleSlot};
use crate::handler::ClientHandler;
use crate::shared::Shared;

/// Capacity of the event and command channels (ADR-0007 back-pressure bound).
pub const CHANNEL_CAPACITY: usize = 256;
/// How long `close` waits for a clean shutdown before aborting the task.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Per-connection options that are not part of `ConnectParams`.
#[derive(Debug, Clone)]
pub struct SshOptions {
    /// The trust store (`$APP_DATA/known_hosts`).
    pub known_hosts_path: PathBuf,
    /// Try the ssh-agent (ADR-0007 default: true).
    pub allow_agent: bool,
    /// Keepalive interval (`ServerAliveInterval`); `None` disables keepalives.
    pub keepalive: Option<Duration>,
    /// Unanswered keepalives before the connection is dropped.
    pub keepalive_max: usize,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
}

impl SshOptions {
    /// ADR-0007 defaults: agent on, keepalive 30 s / 3 misses, 15 s connect timeout.
    pub fn new(known_hosts_path: impl Into<PathBuf>) -> Self {
        Self {
            known_hosts_path: known_hosts_path.into(),
            allow_agent: true,
            keepalive: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            connect_timeout: Duration::from_secs(15),
        }
    }
}

/// A live SSH session.
pub struct SshSession {
    shared: Arc<Shared>,
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
    handle: HandleSlot,
    /// The final `Closed` event when `close` consumed it, replayed once by `next_event`.
    final_event: Option<SessionEvent>,
    closed: bool,
}

impl std::fmt::Debug for SshSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshSession")
            .field("connected", &self.handle.get().is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

fn invalid(field: &'static str, reason: &str) -> NexusError {
    NexusError::Invalid { field, reason: reason.to_owned() }
}

impl SshSession {
    /// Open TCP and start the handshake. The secret in `params` moves into the auth round
    /// and is dropped (zeroized) when it ends.
    pub async fn connect(params: ConnectParams, options: SshOptions) -> Result<Self, NexusError> {
        let ConnectParams { host, port, username, secret, size } = params;
        let host = validate_host(&host)?;
        if port == 0 {
            return Err(invalid("port", "must be 1-65535"));
        }
        let user = username
            .filter(|u| !u.is_empty() && !u.chars().any(char::is_control))
            .ok_or_else(|| invalid("username", "required for ssh"))?;

        let stream = tokio::time::timeout(
            options.connect_timeout,
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| NexusError::Transport("connection timed out".to_owned()))?
        .map_err(|e| NexusError::Transport(format!("connection failed: {}", e.kind())))?;
        let _ = stream.set_nodelay(true);

        let (event_tx, events) = mpsc::channel(CHANNEL_CAPACITY);
        let (commands, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let shared = Arc::new(Shared::new(event_tx));
        let handle: HandleSlot = Arc::new(OnceLock::new());
        let driver = Driver {
            stream,
            config: client_config(options.keepalive, options.keepalive_max),
            handler: ClientHandler::new(host, port, options.known_hosts_path, Arc::clone(&shared)),
            creds: Credentials { user, secret, allow_agent: options.allow_agent },
            size,
            shared: Arc::clone(&shared),
            commands: command_rx,
            slot: Arc::clone(&handle),
        };
        let task = tokio::spawn(driver.run());
        Ok(Self {
            shared,
            events,
            commands,
            task: Some(task),
            handle,
            final_event: None,
            closed: false,
        })
    }

    /// The connected, authenticated russh handle once `Connected` was emitted. Extension
    /// point for port forwarding and SFTP (ADR-0007 part b).
    pub fn handle(&self) -> Option<Arc<Handle<ClientHandler>>> {
        self.handle.get().cloned()
    }

    /// Drain the audit events recorded so far (host key added / rejected / mismatch,
    /// authentication outcome) for the Tauri layer to log.
    pub fn take_audit_events(&mut self) -> Vec<TrustEvent> {
        self.shared.audit.take()
    }
}

#[async_trait]
impl Session for SshSession {
    fn protocol(&self) -> Protocol {
        Protocol::Ssh
    }

    async fn send(&mut self, input: SessionInput) -> Result<(), NexusError> {
        if self.closed {
            return Err(NexusError::Closed);
        }
        let command = match input {
            SessionInput::Answer { id, text } => {
                return if self.shared.broker.answer(id, text) {
                    Ok(())
                } else {
                    Err(invalid("prompt id", "no open prompt with this id"))
                };
            }
            SessionInput::Bytes { data } => Command::Data(data),
            SessionInput::Resize { size } => Command::Resize(size),
            SessionInput::Pointer { .. } | SessionInput::Key { .. } => {
                return Err(invalid("input", "not supported by ssh"));
            }
        };
        self.commands.send(command).await.map_err(|_| NexusError::Closed)
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, NexusError> {
        if let Some(event) = self.final_event.take() {
            return Ok(Some(event));
        }
        if self.closed {
            return Ok(None);
        }
        let event = self.events.recv().await;
        // `Closed` is always the last event; the stream ends after it.
        if matches!(event, Some(SessionEvent::Closed { .. }) | None) {
            self.closed = true;
            self.shared.begin_close();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
        }
        Ok(event)
    }

    async fn close(&mut self) -> Result<(), NexusError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.shared.begin_close();
        let _ = self.commands.try_send(Command::Close);
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
            self.final_event = Some(SessionEvent::Closed { reason: "closed by user".to_owned() });
        }
        Ok(())
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        self.shared.begin_close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
