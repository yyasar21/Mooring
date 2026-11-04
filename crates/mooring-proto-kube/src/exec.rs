//! [`ExecSession`]: `pods/exec` over WebSocket (`v5.channel.k8s.io`, falling back to v4) as a
//! `mooring_core::session::Session` (ADR-0014 §5, owner decision 3).
//!
//! `tty: true, stdin: true, stdout: true, stderr: false`; the command is one of the five
//! allow-listed shells (no argv). `Bytes` in and out are ≤ 64 KiB, channels are bounded (256,
//! ADR-0007), `Resize` is debounced 100 ms onto channel 4. Channel 3 ends the session:
//! `Success` / non-zero exit / failure → `Closed { server_ended }`. Never reconnects.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt as _, StreamExt as _};
use mooring_core::options::ExecCommand;
use mooring_core::session::{CloseCode, Session, SessionEvent, SessionInput, Size};
use mooring_core::{MooringError, Protocol, SessionAudit};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::audit::{AuditSink, KubeAudit};
use crate::browse::{check_container, check_ns, check_pod};
use crate::client::{KubeClient, KubeWs};
use crate::error::KubeError;
use crate::frame::{channel, decode_exec, encode, encode_resize, ExecFrame, ExecStatus};
use crate::query::encode as qenc;

/// Event / command channel capacity (ADR-0007 back-pressure bound).
pub const CHANNEL_CAPACITY: usize = 256;
/// Largest `Bytes` payload in either direction.
pub const MAX_BYTES: usize = 64 * 1024;
/// Resize debounce.
pub const RESIZE_DEBOUNCE: Duration = Duration::from_millis(100);
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// Sub-protocols offered for exec, preferred first.
pub const EXEC_PROTOCOLS: [&str; 2] = ["v5.channel.k8s.io", "v4.channel.k8s.io"];

/// Where to open the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecTarget {
    /// Namespace (RFC 1123 label).
    pub namespace: String,
    /// Pod (RFC 1123 subdomain).
    pub pod: String,
    /// Container (`None` = the pod's default).
    pub container: Option<String>,
    /// The shell (closed list).
    pub command: ExecCommand,
}

impl ExecTarget {
    /// The `exec` request path.
    pub fn path(&self) -> Result<String, KubeError> {
        check_ns(&self.namespace)?;
        check_pod(&self.pod)?;
        check_container(self.container.as_deref())?;
        let mut p = format!(
            "/api/v1/namespaces/{}/pods/{}/exec?command={}&stdin=true&stdout=true&stderr=false&tty=true",
            self.namespace,
            self.pod,
            qenc(self.command.as_str())
        );
        if let Some(c) = &self.container {
            p.push_str("&container=");
            p.push_str(c);
        }
        Ok(p)
    }
}

enum Command {
    Data(Vec<u8>),
    Resize(Size),
    Close,
}

/// A live exec shell.
pub struct ExecSession {
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
    final_event: Option<SessionEvent>,
    closed: bool,
}

impl std::fmt::Debug for ExecSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecSession").field("closed", &self.closed).finish_non_exhaustive()
    }
}

fn dims(size: Size) -> (u16, u16) {
    let c = |v: u32| u16::try_from(v.clamp(1, 10_000)).unwrap_or(10_000);
    (c(size.width), c(size.height))
}

impl KubeClient {
    /// Open an exec shell. Errors (RBAC, not found, refused, trust) are returned before any
    /// session exists; afterwards everything arrives as events (`Connected` first).
    pub async fn exec(
        &self,
        target: ExecTarget,
        size: Option<Size>,
    ) -> Result<ExecSession, KubeError> {
        let path = target.path()?;
        let (ws, proto) = self.upgrade(&path, &EXEC_PROTOCOLS).await?;
        self.audit.push(KubeAudit::ExecOpened {
            namespace: target.namespace.clone(),
            pod: target.pod.clone(),
            container: target.container.clone(),
            argv0: target.command.as_str(),
        });
        Ok(ExecSession::start(ws, proto, size, target, self.audit.clone()))
    }
}

impl ExecSession {
    pub(crate) fn start(
        ws: KubeWs,
        proto: &'static str,
        size: Option<Size>,
        target: ExecTarget,
        audit: AuditSink,
    ) -> Self {
        let (event_tx, events) = mpsc::channel(CHANNEL_CAPACITY);
        let (commands, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let task = tokio::spawn(async move {
            let (reason, code) = drive(ws, proto, size, &event_tx, command_rx).await;
            audit.push(KubeAudit::ExecClosed {
                namespace: target.namespace,
                pod: target.pod,
                container: target.container,
                code: code_name(code),
            });
            let _ = event_tx.send(SessionEvent::Closed { reason, code }).await;
        });
        Self { events, commands, task: Some(task), final_event: None, closed: false }
    }
}

fn code_name(c: CloseCode) -> &'static str {
    match c {
        CloseCode::User => "user",
        CloseCode::Network => "network",
        CloseCode::AuthFailed => "auth_failed",
        CloseCode::TrustRejected => "trust_rejected",
        CloseCode::TrustMismatch => "trust_mismatch",
        CloseCode::ServerEnded => "server_ended",
        CloseCode::ProtocolError => "protocol_error",
        CloseCode::VaultLocked => "vault_locked",
    }
}

fn status_close(s: Option<ExecStatus>) -> (String, CloseCode) {
    match s {
        Some(ExecStatus::Success) => ("the shell exited".to_owned(), CloseCode::ServerEnded),
        Some(ExecStatus::Exit(n)) => {
            (format!("the shell exited with status {n}"), CloseCode::ServerEnded)
        }
        Some(ExecStatus::Failure(r)) => (format!("exec failed: {r}"), CloseCode::ServerEnded),
        None => ("the connection closed".to_owned(), CloseCode::Network),
    }
}

async fn emit(tx: &mpsc::Sender<SessionEvent>, data: &[u8]) -> bool {
    for piece in data.chunks(MAX_BYTES) {
        if tx.send(SessionEvent::Bytes { data: piece.to_vec() }).await.is_err() {
            return false;
        }
    }
    true
}

async fn drive(
    mut ws: KubeWs,
    proto: &'static str,
    size: Option<Size>,
    tx: &mpsc::Sender<SessionEvent>,
    mut rx: mpsc::Receiver<Command>,
) -> (String, CloseCode) {
    let connected = SessionEvent::Connected {
        protocol: Protocol::Kubernetes,
        peer_identity: None,
        security: Some(proto.to_owned()),
    };
    if tx.send(connected).await.is_err() {
        return ("closed by user".to_owned(), CloseCode::User);
    }
    if let Some(s) = size {
        let (w, h) = dims(s);
        if ws.send(Message::Binary(encode_resize(w, h).into())).await.is_err() {
            return ("the connection closed".to_owned(), CloseCode::Network);
        }
    }
    let mut status: Option<ExecStatus> = None;
    let mut pending_resize: Option<Size> = None;
    let debounce = tokio::time::sleep(RESIZE_DEBOUNCE);
    tokio::pin!(debounce);
    loop {
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(b))) => match decode_exec(&b) {
                    Ok(ExecFrame::Stdout(d) | ExecFrame::Stderr(d)) => {
                        if !emit(tx, d).await {
                            return ("closed by user".to_owned(), CloseCode::User);
                        }
                    }
                    Ok(ExecFrame::Status(s)) => status = Some(s),
                    Ok(ExecFrame::Close(_)) => {}
                    Err(_) => {
                        let _ = ws.close(None).await;
                        return ("the server sent a malformed frame".to_owned(), CloseCode::ProtocolError);
                    }
                },
                Some(Ok(Message::Close(_))) | None => return status_close(status),
                Some(Ok(_)) => {}
                Some(Err(_)) => {
                    return if status.is_some() {
                        status_close(status)
                    } else {
                        ("the connection failed".to_owned(), CloseCode::Network)
                    };
                }
            },
            cmd = rx.recv() => match cmd {
                Some(Command::Data(d)) => {
                    if ws.send(Message::Binary(encode(channel::STDIN, &d).into())).await.is_err() {
                        return status_close(status);
                    }
                }
                Some(Command::Resize(s)) => {
                    if pending_resize.is_none() {
                        debounce.as_mut().reset(tokio::time::Instant::now() + RESIZE_DEBOUNCE);
                    }
                    pending_resize = Some(s);
                }
                Some(Command::Close) | None => {
                    let _ = tokio::time::timeout(Duration::from_secs(2), ws.close(None)).await;
                    return ("closed by user".to_owned(), CloseCode::User);
                }
            },
            () = &mut debounce, if pending_resize.is_some() => {
                if let Some(s) = pending_resize.take() {
                    let (w, h) = dims(s);
                    if ws.send(Message::Binary(encode_resize(w, h).into())).await.is_err() {
                        return status_close(status);
                    }
                }
            }
        }
    }
}

fn invalid(reason: &str) -> MooringError {
    MooringError::Invalid { field: "input", reason: reason.to_owned() }
}

#[async_trait]
impl Session for ExecSession {
    fn protocol(&self) -> Protocol {
        Protocol::Kubernetes
    }

    async fn send(&mut self, input: SessionInput) -> Result<(), MooringError> {
        if self.closed {
            return Err(MooringError::Closed);
        }
        let cmd = match input {
            SessionInput::Bytes { data } if data.len() > MAX_BYTES => {
                return Err(invalid("bytes exceed 64 KiB"));
            }
            SessionInput::Bytes { data } => Command::Data(data),
            SessionInput::Resize { size } => Command::Resize(size),
            _ => return Err(invalid("not supported by kubernetes exec")),
        };
        self.commands.send(cmd).await.map_err(|_| MooringError::Closed)
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, MooringError> {
        if let Some(e) = self.final_event.take() {
            return Ok(Some(e));
        }
        if self.closed {
            return Ok(None);
        }
        let event = self.events.recv().await;
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

    fn take_audit_events(&mut self) -> Vec<SessionAudit> {
        // Kubernetes events live in the cluster's `AuditSink` (`KubeClient::audit`).
        Vec::new()
    }
}

// No `Drop` abort: dropping the session drops the command sender, the driver sees `None`,
// closes the WebSocket (bounded) and records `kube.exec.closed`.
