//! `VncSession`: the `mooring_core::session::Session` implementation for VNC (ADR-0012).
//!
//! `connect` validates its input and returns at once; the handshake runs in a driver task
//! whose progress arrives through `next_event`: `Prompt`* → `Connected` → `DesktopResized`* →
//! `Closed`. Pixels never travel as events: they go into the caller's `FrameSink`.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mooring_core::frame::FrameSink;
use mooring_core::options::VncConnOptions;
use mooring_core::session::{
    CloseCode, ConnectParams, ConnectSecret, Session, SessionEvent, SessionInput,
};
use mooring_core::{validate_host, MooringError, Protocol, SessionAudit};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::connect::Target;
use crate::driver::{Command, CredSource, Driver};
use crate::security::Credential;
use crate::shared::{AuditLog, Reply, Shared};

/// Capacity of the event and command channels.
pub const CHANNEL_CAPACITY: usize = 256;
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The OS clipboard as the session sees it, implemented by the Tauri layer on top of its
/// `clipboard.rs`; the same trait as `mooring_proto_rdp::LocalClipboard`.
pub use mooring_core::clipboard::{Clipboard, NoClipboard};

/// Per-connection options that are not part of `ConnectParams` (ADR-0012 `VncOptions`).
#[derive(Debug, Clone)]
pub struct VncOptions {
    /// `$APP_DATA/known_vnc_certs`.
    pub known_certs: PathBuf,
    /// The OS clipboard bridge.
    pub clipboard: Arc<dyn Clipboard>,
    /// `connection.options` for VNC.
    pub conn: VncConnOptions,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Whole-handshake timeout (per attempt, prompts excluded).
    pub handshake_timeout: Duration,
    /// Accept exactly this leaf (SHA-256 of the DER) as if pinned, for this session only: the
    /// user said `yes` but the Tauri layer could not write the pin.
    pub trusted_once: Option<[u8; 32]>,
    /// ADR-0025: reach the server through this dialer (a jump-host chain) instead of direct
    /// TCP. `None` = direct TCP. Every attempt (TOFU retry, `VeNCrypt` fallback) dials again.
    pub dialer: Option<mooring_core::SharedDialer>,
}

impl VncOptions {
    /// Defaults: no clipboard bridge, 15 s connect, 30 s handshake.
    pub fn new(known_certs: impl Into<PathBuf>, conn: VncConnOptions) -> Self {
        Self {
            known_certs: known_certs.into(),
            clipboard: Arc::new(NoClipboard),
            conn,
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(30),
            trusted_once: None,
            dialer: None,
        }
    }

    /// Reach the server through `dialer` (ADR-0025 jump hosts).
    #[must_use]
    pub fn via(mut self, dialer: mooring_core::SharedDialer) -> Self {
        self.dialer = Some(dialer);
        self
    }
}

/// Runtime control of a session (Tauri `session_set_view_only`; that command audits).
#[derive(Debug, Clone)]
pub struct VncControl {
    shared: Arc<Shared>,
}

impl VncControl {
    /// Switch view-only on or off. Rust enforces it: inputs are dropped before the socket.
    pub fn set_view_only(&self, on: bool) {
        self.shared.view_only.store(on, Ordering::Relaxed);
    }

    /// Whether view-only is on.
    pub fn view_only(&self) -> bool {
        self.shared.view_only.load(Ordering::Relaxed)
    }

    /// Inputs dropped by view-only so far.
    pub fn dropped_inputs(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

/// A live VNC session.
pub struct VncSession {
    shared: Arc<Shared>,
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
    final_event: Option<SessionEvent>,
    closed: bool,
}

impl std::fmt::Debug for VncSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VncSession").field("closed", &self.closed).finish_non_exhaustive()
    }
}

fn invalid(field: &'static str, reason: &str) -> MooringError {
    MooringError::Invalid { field, reason: reason.to_owned() }
}

fn credential(params: &mut ConnectParams) -> Result<CredSource, MooringError> {
    let user = params.username.take().filter(|u| !u.is_empty() && !u.chars().any(char::is_control));
    let secret = std::mem::replace(&mut params.secret, ConnectSecret::None);
    Ok(CredSource::Ready(match (secret, user) {
        (ConnectSecret::None, _) => Credential::None,
        (ConnectSecret::Password(p), None) => Credential::Password(p),
        (ConnectSecret::Password(password), Some(user))
        | (ConnectSecret::DomainPassword { user, password, .. }, _) => {
            Credential::UserPassword { user, password }
        }
        (ConnectSecret::Prompt(account), _) => return Ok(CredSource::Ask(account)),
        (other, _) => {
            return Err(invalid("credential", &format!("{} is not usable for vnc", other.kind())));
        }
    }))
}

impl VncSession {
    /// Validate and start the session. `audit` receives the session's audit events (also
    /// drained by `take_audit_events`); `sink` receives every pixel.
    pub async fn connect(
        mut params: ConnectParams,
        options: VncOptions,
        sink: FrameSink,
        audit: AuditLog,
    ) -> Result<Self, MooringError> {
        let host = validate_host(&params.host)?;
        if params.port == 0 {
            return Err(invalid("port", "must be 1-65535"));
        }
        options.conn.validate()?;
        let cred = credential(&mut params)?;
        let (event_tx, events) = mpsc::channel(CHANNEL_CAPACITY);
        let (commands, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let shared = Arc::new(Shared::new(event_tx, audit, options.conn.view_only));
        let driver = Driver {
            target: Target {
                host,
                port: params.port,
                conn: options.conn,
                known_certs: options.known_certs,
                connect_timeout: options.connect_timeout,
                handshake_timeout: options.handshake_timeout,
                trusted_once: options.trusted_once,
                dialer: options
                    .dialer
                    .unwrap_or_else(|| mooring_core::TcpDialer::shared(options.connect_timeout)),
            },
            cred,
            sink,
            clipboard: options.clipboard,
            shared: Arc::clone(&shared),
            commands: command_rx,
        };
        let task = tokio::spawn(driver.run());
        Ok(Self { shared, events, commands, task: Some(task), final_event: None, closed: false })
    }

    /// The runtime control handle.
    pub fn control(&self) -> VncControl {
        VncControl { shared: Arc::clone(&self.shared) }
    }
}

#[async_trait]
impl Session for VncSession {
    fn protocol(&self) -> Protocol {
        Protocol::Vnc
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
            SessionInput::CredentialAnswer { id, username, password, .. } => {
                if self.shared.answer(id, Reply::Credential { username, password }) {
                    Ok(())
                } else {
                    Err(invalid("prompt id", "no open prompt with this id"))
                }
            }
            SessionInput::Bytes { .. } => Err(invalid("input", "not supported by vnc")),
            // View-only is decided when the input arrives, so a later toggle never releases
            // queued input. `ReleaseAll` always passes (it only releases held keys).
            other
                if self.shared.view_only.load(Ordering::Relaxed)
                    && !matches!(other, SessionInput::ReleaseAll) =>
            {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(input = ?other, "vnc: view-only, input dropped");
                Ok(())
            }
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
            mooring_core::driver_task::next_driver_event(&mut self.events, &mut self.task, "VNC")
                .await;
        if matches!(event, Some(SessionEvent::Closed { .. }) | None) {
            self.closed = true;
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
        self.shared.cancel_prompt();
        let _ = self.commands.try_send(Command::Close);
        let Some(mut task) = self.task.take() else { return Ok(()) };
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
        // Drain a Closed that raced the task's end.
        while let Ok(e) = self.events.try_recv() {
            if matches!(e, SessionEvent::Closed { .. }) {
                self.final_event = Some(e);
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

impl Drop for VncSession {
    fn drop(&mut self) {
        self.shared.cancel_prompt();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
