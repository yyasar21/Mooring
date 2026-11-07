//! `SshSession`: the `mooring_core::session::Session` implementation for SSH.
//!
//! `connect` opens TCP and returns at once; the handshake, TOFU prompt, authentication and
//! shell run in a driver task whose progress arrives through `next_event`:
//! `Prompt`* → `Connected` → `Bytes`* → `Closed`. Prompts are answered with `send(Answer)`.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use mooring_core::session::{CloseCode, ConnectParams, Session, SessionEvent, SessionInput};
use mooring_core::SessionAudit;
use mooring_core::{validate_host, MooringError, Protocol};
use russh::client::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::algos::client_config;
use crate::audit::TrustEvent;
use crate::auth::Credentials;
use crate::channel::Command;
use crate::driver::{Driver, HandleSlot, Transport};
use crate::handler::ClientHandler;
use crate::hops::Hop;
use crate::shared::{CredentialReply, Reply, Shared};

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
    pub(crate) shared: Arc<Shared>,
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
    pub(crate) handle: HandleSlot,
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

fn invalid(field: &'static str, reason: &str) -> MooringError {
    MooringError::Invalid { field, reason: reason.to_owned() }
}

/// `ConnectParams` after validation.
struct Checked {
    host: String,
    port: u16,
    user: String,
    secret: mooring_core::session::ConnectSecret,
    r#become: Option<mooring_core::session::Become>,
    size: mooring_core::session::Size,
}

fn check(params: ConnectParams) -> Result<Checked, MooringError> {
    let ConnectParams { host, port, username, secret, r#become, size } = params;
    let host = validate_host(&host)?;
    if port == 0 {
        return Err(invalid("port", "must be 1-65535"));
    }
    let user = username.filter(|u| !u.is_empty() && !u.chars().any(char::is_control));
    // A `prompt` credential may leave the username to the connect-time form.
    let user = match (&secret, user) {
        (_, Some(u)) => u,
        (mooring_core::session::ConnectSecret::Prompt(_), None) => String::new(),
        (_, None) => return Err(invalid("username", "required for ssh")),
    };
    if let Some(b) = &r#become {
        crate::become_::check(b)?;
    }
    Ok(Checked { host, port, user, secret, r#become, size })
}

impl SshSession {
    /// Open TCP and start the handshake. The secret in `params` moves into the auth round
    /// and is dropped (zeroized) when it ends.
    pub async fn connect(params: ConnectParams, options: SshOptions) -> Result<Self, MooringError> {
        let dialer = mooring_core::TcpDialer::shared(options.connect_timeout);
        Self::connect_via(params, options, dialer).await
    }

    /// Like [`connect`](Self::connect) over `dialer` (ADR-0025: a jump-host chain hands out
    /// a `direct-tcpip` stream of its last hop; the direct path is a `TcpDialer`).
    pub async fn connect_via(
        params: ConnectParams,
        options: SshOptions,
        dialer: mooring_core::SharedDialer,
    ) -> Result<Self, MooringError> {
        let checked = check(params)?;
        let stream =
            tokio::time::timeout(options.connect_timeout, dialer.dial(&checked.host, checked.port))
                .await
                .map_err(|_| MooringError::Transport("connection timed out".to_owned()))?
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::TimedOut => {
                        MooringError::Transport("connection timed out".to_owned())
                    }
                    kind => MooringError::Transport(format!("connection failed: {kind}")),
                })?
                .stream;
        Ok(Self::start(checked, options, Transport::Ready(stream)))
    }

    /// ADR-0025: reach the target through `hops` (1..=3 jump hosts). Returns at once: the
    /// chain is opened inside the session task, so its `HopStatus` events and per-hop prompts
    /// (`hop: Some(i)`) arrive through `next_event` and are answered with `send(Answer)` like
    /// the target's own. A hop failure ends the session with `hop_failed` before anything is
    /// sent to the target; a hop lost later ends it with `hop_lost`. Forwards and SFTP ride
    /// the target session as usual.
    pub fn connect_chain(
        params: ConnectParams,
        options: SshOptions,
        hops: Vec<Hop>,
    ) -> Result<Self, MooringError> {
        if hops.is_empty() || hops.len() > crate::hops::MAX_HOPS {
            return Err(invalid("via", "1 to 3 jump hosts"));
        }
        let checked = check(params)?;
        Ok(Self::start(checked, options, Transport::Chain(hops)))
    }

    fn start(c: Checked, options: SshOptions, transport: Transport) -> Self {
        let Checked { host, port, user, secret, r#become, size } = c;
        let (event_tx, events) = mpsc::channel(CHANNEL_CAPACITY);
        let (commands, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let shared = Arc::new(Shared::new(event_tx));
        let handle: HandleSlot = Arc::new(OnceLock::new());
        let driver = Driver {
            transport,
            target: (host.clone(), port),
            config: client_config(options.keepalive, options.keepalive_max),
            handler: ClientHandler::new(host, port, options.known_hosts_path, Arc::clone(&shared)),
            creds: Credentials { user, secret, allow_agent: options.allow_agent },
            r#become,
            size,
            shared: Arc::clone(&shared),
            commands: command_rx,
            slot: Arc::clone(&handle),
        };
        let task = tokio::spawn(driver.run());
        Self {
            shared,
            events,
            commands,
            task: Some(task),
            handle,
            final_event: None,
            closed: false,
        }
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

    fn take_audit_events(&mut self) -> Vec<SessionAudit> {
        self.shared.audit.take()
    }

    async fn send(&mut self, input: SessionInput) -> Result<(), MooringError> {
        if self.closed {
            return Err(MooringError::Closed);
        }
        let command = match input {
            SessionInput::Answer { id, text } => {
                return if self.shared.broker.answer(id, Reply::Text(text)) {
                    Ok(())
                } else {
                    Err(invalid("prompt id", "no open prompt with this id"))
                };
            }
            SessionInput::CredentialAnswer { id, username, domain, password } => {
                let form = CredentialReply { username, domain, password };
                return if self.shared.broker.answer(id, Reply::Credential(form)) {
                    Ok(())
                } else {
                    Err(invalid("prompt id", "no open prompt with this id"))
                };
            }
            SessionInput::Bytes { data } => Command::Data(data),
            SessionInput::Resize { size } => Command::Resize(size),
            SessionInput::Pointer { .. }
            | SessionInput::Key { .. }
            | SessionInput::Wheel { .. }
            | SessionInput::Unicode { .. }
            | SessionInput::ReleaseAll
            | SessionInput::ClipboardOffer => {
                return Err(invalid("input", "not supported by ssh"));
            }
        };
        self.commands.send(command).await.map_err(|_| MooringError::Closed)
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, MooringError> {
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

    async fn close(&mut self) -> Result<(), MooringError> {
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
            self.final_event = Some(SessionEvent::Closed {
                reason: "closed by user".to_owned(),
                code: CloseCode::User,
            });
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
