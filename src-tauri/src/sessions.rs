//! Live session registry and the per-session task (ADR-0004, ADR-0008).
//!
//! One Tokio task owns each `SshSession`. It waits on two things: commands from IPC
//! (`session_send` / `session_close`, each with a reply channel) and the session's next event.
//! Events are base64-encoded into [`WireEvent`]s and pushed to the UI's `Channel`. After every
//! event the task drains the SSH trust events into the audit log. When the session ends, the
//! task removes itself from the registry and writes `session_closed`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::session::{PromptAccount, PromptPurpose, Session, SessionEvent, SessionInput};
use mooring_core::Protocol;
use mooring_proto_ssh::{SshControl, SshSession, TrustEvent};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use crate::error::{IpcError, IpcResult};
use crate::state::{record_audit, SessionRegistry};

/// A session event as the UI receives it: `mooring_core` shape (`kind` tag, `snake_case` fields),
/// byte payloads as base64 strings (ADR-0008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireEvent {
    /// Handshake done.
    Connected {
        /// Protocol name.
        protocol: &'static str,
        /// Host key fingerprint shown to the user.
        peer_identity: Option<String>,
    },
    /// Terminal output, base64.
    Bytes {
        /// Payload.
        data: String,
    },
    /// Screen rectangle, RGBA base64.
    Frame {
        /// X.
        x: u32,
        /// Y.
        y: u32,
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// Pixels.
        rgba: String,
    },
    /// Question for the user.
    Prompt {
        /// Prompt id.
        id: u32,
        /// Safe text.
        message: String,
        /// Hide the answer.
        secret: bool,
        /// `host_key_trust`, `keyboard_interactive`, `credential` or `other` (L-2).
        purpose: PromptPurpose,
        /// Sign-in form for `purpose: credential` (ADR-0009), `null` otherwise.
        account: Option<PromptAccount>,
    },
    /// Session ended (always last).
    Closed {
        /// Safe reason.
        reason: String,
    },
}

impl From<SessionEvent> for WireEvent {
    fn from(e: SessionEvent) -> Self {
        let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
        match e {
            SessionEvent::Connected { protocol, peer_identity } => {
                Self::Connected { protocol: protocol.name(), peer_identity }
            }
            SessionEvent::Bytes { data } => Self::Bytes { data: b64(&data) },
            SessionEvent::Frame { x, y, width, height, rgba } => {
                Self::Frame { x, y, width, height, rgba: b64(&rgba) }
            }
            SessionEvent::Prompt { id, message, secret, purpose, account } => {
                Self::Prompt { id, message, secret, purpose, account }
            }
            SessionEvent::Closed { reason } => Self::Closed { reason },
        }
    }
}

/// Where events go. Returns `false` when the UI side is gone.
pub type EventSink = Arc<dyn Fn(WireEvent) -> bool + Send + Sync>;

/// Session lifecycle as reported by `session_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// TCP open, handshake / TOFU / auth in progress.
    Connecting = 0,
    /// `Connected` emitted.
    Connected = 1,
    /// Ending.
    Closed = 2,
}

impl Phase {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            1 => Self::Connected,
            _ => Self::Closed,
        }
    }

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Closed => "closed",
        }
    }
}

/// Commands from IPC to the session task.
#[derive(Debug)]
pub enum SessionCommand {
    /// Forward user input; the reply carries the session's verdict.
    Input(SessionInput, oneshot::Sender<IpcResult<()>>),
    /// Close the session; replied once the protocol side is shut down.
    Close(oneshot::Sender<()>),
}

/// Running SFTP transfers of one session: transfer id → cancel signal (ADR-0010).
pub type Transfers = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

/// Registry entry for one live session.
#[derive(Debug)]
pub struct SessionHandle {
    /// Forwards and SFTP of the session, usable while the task owns the session (ADR-0010).
    pub control: SshControl,
    /// Running SFTP transfers; cancelled when the session ends.
    pub transfers: Transfers,
    /// Command channel to the task.
    pub commands: mpsc::Sender<SessionCommand>,
    /// Connection the session was opened for.
    pub connection_id: String,
    /// Protocol.
    pub protocol: Protocol,
    /// RFC 3339 open time.
    pub opened_at: String,
    phase: Arc<AtomicU8>,
    task: Option<tokio::task::AbortHandle>,
}

impl SessionHandle {
    /// Current phase.
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    /// Stop the task without a clean close (process exit).
    pub fn abort(&self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

/// Capacity of a session's command queue.
const COMMAND_CAPACITY: usize = 64;

/// Everything the task needs besides the session.
pub struct TaskContext {
    /// Registry key.
    pub session_id: String,
    /// For audit entries.
    pub connection_id: String,
    /// UI channel.
    pub sink: EventSink,
    /// Audit log.
    pub audit: Arc<Mutex<AuditLog>>,
    /// Registry to remove ourselves from.
    pub registry: SessionRegistry,
}

impl std::fmt::Debug for TaskContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskContext")
            .field("session_id", &self.session_id)
            .field("connection_id", &self.connection_id)
            .finish_non_exhaustive()
    }
}

/// Register `session` and start its task. Must be called inside a Tokio runtime.
pub fn spawn(session: SshSession, ctx: TaskContext, opened_at: String) -> IpcResult<()> {
    let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
    let phase = Arc::new(AtomicU8::new(Phase::Connecting as u8));
    let transfers = Transfers::default();
    let mut handle = SessionHandle {
        control: session.control(),
        transfers: Arc::clone(&transfers),
        commands: tx,
        connection_id: ctx.connection_id.clone(),
        protocol: Protocol::Ssh,
        opened_at,
        phase: Arc::clone(&phase),
        task: None,
    };
    let registry = Arc::clone(&ctx.registry);
    let id = ctx.session_id.clone();
    // Hold the registry lock while spawning so the task cannot remove the entry before it
    // exists (it locks the registry only on exit).
    let mut map = registry.lock().map_err(|_| IpcError::poisoned())?;
    let task = tokio::spawn(run(session, rx, ctx, phase, transfers));
    handle.task = Some(task.abort_handle());
    map.insert(id, handle);
    Ok(())
}

/// Write the SSH trust and forward events drained from a session into the audit log.
pub fn audit_trust(audit: &Mutex<AuditLog>, connection: &str, events: Vec<TrustEvent>) {
    for e in events {
        let (host, fingerprint, decision, expected) = match e {
            TrustEvent::HostKeyAdded { host, port, fingerprint, stored, .. } => {
                // N-3: a key that could not be written is trusted for this session only.
                let decision = if stored { "accepted" } else { "accepted_session_only" };
                (format!("{host}:{port}"), fingerprint, decision, None)
            }
            TrustEvent::HostKeyRejected { host, port, fingerprint } => {
                (format!("{host}:{port}"), fingerprint, "rejected", None)
            }
            TrustEvent::HostKeyMismatch { host, port, presented, expected } => {
                (format!("{host}:{port}"), presented, "changed", Some(expected))
            }
            TrustEvent::AuthSucceeded { method } => {
                tracing::info!(method = method.as_str(), "ssh authentication succeeded");
                continue;
            }
            TrustEvent::AuthFailed => {
                tracing::info!("ssh authentication failed");
                continue;
            }
            TrustEvent::BecomeFailed => {
                record_audit(audit, AuditEvent::BecomeFailed { connection: connection.to_owned() });
                continue;
            }
            // ADR-0010: every forward open (with its exposure) and close is audited.
            TrustEvent::ForwardOpened { id, kind, bind, target, exposure } => {
                let (kind, exposure) = (kind.to_owned(), exposure.to_owned());
                let connection = connection.to_owned();
                let event = AuditEvent::ForwardOpened { connection, id, kind, bind, target, exposure };
                record_audit(audit, event);
                continue;
            }
            TrustEvent::ForwardClosed { id, kind, bind, target } => {
                let (connection, kind) = (connection.to_owned(), kind.to_owned());
                record_audit(audit, AuditEvent::ForwardClosed { connection, id, kind, bind, target });
                continue;
            }
        };
        record_audit(
            audit,
            AuditEvent::TrustDecision {
                host,
                fingerprint,
                decision: decision.to_owned(),
                expected,
            },
        );
    }
}

async fn run(
    mut session: SshSession,
    mut commands: mpsc::Receiver<SessionCommand>,
    ctx: TaskContext,
    phase: Arc<AtomicU8>,
    transfers: Transfers,
) {
    let mut reason = String::from("session ended");
    let mut closing = false;
    loop {
        tokio::select! {
            biased;
            cmd = commands.recv(), if !closing => match cmd {
                Some(SessionCommand::Input(input, reply)) => {
                    let r = session.send(input).await.map_err(IpcError::from);
                    let _ = reply.send(r);
                }
                Some(SessionCommand::Close(reply)) => {
                    closing = true;
                    if let Err(e) = session.close().await {
                        tracing::debug!(error = %e, "session close reported an error");
                    }
                    let _ = reply.send(());
                }
                None => {
                    closing = true;
                    let _ = session.close().await;
                }
            },
            event = session.next_event() => {
                audit_trust(&ctx.audit, &ctx.connection_id, session.take_audit_events());
                match event {
                    Ok(Some(event)) => {
                        let last = matches!(event, SessionEvent::Closed { .. });
                        match &event {
                            SessionEvent::Connected { peer_identity, .. } => {
                                phase.store(Phase::Connected as u8, Ordering::Relaxed);
                                record_audit(&ctx.audit, AuditEvent::SessionOpened {
                                    connection: ctx.connection_id.clone(),
                                    protocol: Protocol::Ssh.name().to_owned(),
                                    peer_identity: peer_identity.clone(),
                                });
                            }
                            SessionEvent::Closed { reason: r } => reason.clone_from(r),
                            _ => {}
                        }
                        if !(ctx.sink)(event.into()) && !last {
                            tracing::info!("session event channel gone; closing");
                            closing = true;
                            let _ = session.close().await;
                        }
                        if last {
                            break;
                        }
                    }
                    Ok(None) => {
                        // Stream ended without a visible Closed (consumed during a command).
                        (ctx.sink)(WireEvent::Closed { reason: reason.clone() });
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "session event error");
                        "session failed".clone_into(&mut reason);
                        (ctx.sink)(WireEvent::Closed { reason: reason.clone() });
                        let _ = session.close().await;
                        break;
                    }
                }
            }
        }
    }
    phase.store(Phase::Closed as u8, Ordering::Relaxed);
    // Transfers end with their session (each reports `cancelled` and audits itself).
    let pending: Vec<_> = transfers.lock().map(|mut t| t.drain().collect()).unwrap_or_default();
    for (_, cancel) in pending {
        let _ = cancel.send(());
    }
    audit_trust(&ctx.audit, &ctx.connection_id, session.take_audit_events());
    if let Ok(mut map) = ctx.registry.lock() {
        map.remove(&ctx.session_id);
    }
    // Answer anything still queued so no IPC call waits forever.
    commands.close();
    while let Ok(cmd) = commands.try_recv() {
        match cmd {
            SessionCommand::Input(_, reply) => {
                let _ = reply.send(Err(IpcError::new("session.not_found", "session is closed")));
            }
            SessionCommand::Close(reply) => {
                let _ = reply.send(());
            }
        }
    }
    record_audit(&ctx.audit, AuditEvent::SessionClosed { connection: ctx.connection_id, reason });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_events_are_base64_and_snake_case() {
        let e = WireEvent::from(SessionEvent::Bytes { data: b"hi\r\n".to_vec() });
        assert_eq!(
            serde_json::to_string(&e).expect("json"),
            r#"{"kind":"bytes","data":"aGkNCg=="}"#
        );
        let e = WireEvent::from(SessionEvent::Connected {
            protocol: Protocol::VsphereConsole,
            peer_identity: Some("ssh-ed25519 SHA256:x".into()),
        });
        let json = serde_json::to_string(&e).expect("json");
        assert!(json.contains(r#""protocol":"vsphere-console""#), "{json}");
        assert!(json.contains(r#""peer_identity":"ssh-ed25519 SHA256:x""#), "{json}");
        let e = WireEvent::from(SessionEvent::Frame {
            x: 1,
            y: 2,
            width: 1,
            height: 1,
            rgba: vec![0; 4],
        });
        assert!(serde_json::to_string(&e).expect("json").contains(r#""rgba":"AAAAAA==""#));
    }

    #[test]
    fn phases_round_trip() {
        for p in [Phase::Connecting, Phase::Connected, Phase::Closed] {
            assert_eq!(Phase::from_u8(p as u8), p);
        }
        assert_eq!(Phase::Connecting.as_str(), "connecting");
    }

    #[test]
    fn become_failure_is_audited_with_the_connection() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("audit.jsonl");
        let log = Mutex::new(AuditLog::open(&path).expect("open"));
        audit_trust(&log, "conn-1", vec![TrustEvent::BecomeFailed]);
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains(r#""event":"become_failed""#), "{text}");
        assert!(text.contains(r#""connection":"conn-1""#), "{text}");
    }

    #[test]
    fn forward_events_are_audited_with_exposure() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("audit.jsonl");
        let log = Mutex::new(AuditLog::open(&path).expect("open"));
        let (bind, target) = ("0.0.0.0:8080".to_owned(), "db.example.test:5432".to_owned());
        let opened = TrustEvent::ForwardOpened {
            id: "fwd-1".into(),
            kind: "local",
            bind: bind.clone(),
            target: target.clone(),
            exposure: "external",
        };
        let closed = TrustEvent::ForwardClosed { id: "fwd-1".into(), kind: "local", bind, target };
        audit_trust(&log, "conn-1", vec![opened, closed]);
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].contains(r#""event":"forward_opened""#), "{text}");
        assert!(lines[0].contains(r#""exposure":"external""#), "{text}");
        assert!(lines[1].contains(r#""event":"forward_closed""#), "{text}");
        assert!(AuditLog::verify(&path).expect("verify").ok());
    }
}
