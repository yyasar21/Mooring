//! Live session registry (ADR-0004, ADR-0008, ADR-0011).
//!
//! One Tokio task owns each session ([`crate::session_task`]). It waits on two things:
//! commands from IPC (`session_send` / `session_close`, each with a reply channel) and the
//! session's next event. Events become [`WireEvent`]s on the UI's `Channel`; graphical
//! sessions additionally push MFR1 frames over a raw channel ([`crate::frame_pump`]). After
//! every event the task drains the session's audit events into the audit log. When the
//! session ends, the task removes itself from the registry and writes `session_closed`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use mooring_audit::AuditLog;
use mooring_core::frame::FrameSink;
use mooring_core::known_certs::CertificateInfo;
use mooring_core::session::{CloseCode, PromptAccount, PromptPurpose, SessionEvent, SessionInput};
use mooring_core::Protocol;
use mooring_proto_ssh::{SshControl, SshSession};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use crate::error::{IpcError, IpcResult};
use crate::frame_pump::FrameFlow;
use crate::state::SessionRegistry;

pub use crate::session_audit::{audit_session, audit_trust};

/// A session event as the UI receives it: `mooring_core` shape (`kind` tag, `snake_case` fields),
/// byte payloads as base64 strings (ADR-0008). Pixels never travel here (ADR-0011).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireEvent {
    /// Handshake done.
    Connected {
        /// Protocol name.
        protocol: &'static str,
        /// Host key / certificate fingerprint shown to the user.
        peer_identity: Option<String>,
        /// `nla` | `tls` (RDP), `vencrypt-x509` | `vnc-auth` | `none` (VNC), `null` for SSH.
        security: Option<String>,
    },
    /// Terminal output, base64.
    Bytes {
        /// Payload.
        data: String,
    },
    /// The remote desktop size changed.
    DesktopResized {
        /// Width in pixels.
        width: u32,
        /// Height in pixels.
        height: u32,
    },
    /// Question for the user.
    Prompt {
        /// Prompt id.
        id: u32,
        /// Safe text.
        message: String,
        /// Hide the answer.
        secret: bool,
        /// `host_key_trust`, `certificate_trust`, `keyboard_interactive`, `credential` or
        /// `other` (L-2).
        purpose: PromptPurpose,
        /// Sign-in form for `purpose: credential` (ADR-0009), `null` otherwise.
        account: Option<PromptAccount>,
        /// The server certificate for `purpose: certificate_trust`, `null` otherwise.
        certificate: Option<CertificateInfo>,
    },
    /// The connection dropped; attempt `attempt` (1-based, ≤ 6) starts in `delay_ms`
    /// (ADR-0011 `Reconnecting { attempt, delayMs }`; `snake_case` like every event field).
    Reconnecting {
        /// Attempt number.
        attempt: u32,
        /// Delay before the attempt, in milliseconds.
        delay_ms: u64,
    },
    /// Another view took the session over (ADR-0013 `session_attach`); this view shows a
    /// placeholder. Nothing else arrives on this channel until it attaches again.
    Detached,
    /// The detached view went away or `window_attach` ran: this (`main`) view has the session
    /// again. It should call `session_attach` with fresh channels (a full frame follows).
    Attached,
    /// Session ended (always last).
    Closed {
        /// Safe reason.
        reason: String,
        /// Machine-readable cause (`network`, `trust_mismatch`, ...).
        code: CloseCode,
    },
}

impl From<SessionEvent> for WireEvent {
    fn from(e: SessionEvent) -> Self {
        match e {
            SessionEvent::Connected { protocol, peer_identity, security } => {
                Self::Connected { protocol: protocol.name(), peer_identity, security }
            }
            SessionEvent::Bytes { data } => {
                Self::Bytes { data: base64::engine::general_purpose::STANDARD.encode(data) }
            }
            SessionEvent::DesktopResized { width, height } => {
                Self::DesktopResized { width, height }
            }
            SessionEvent::Prompt { id, message, secret, purpose, account, certificate } => {
                Self::Prompt { id, message, secret, purpose, account, certificate }
            }
            SessionEvent::Closed { reason, code } => Self::Closed { reason, code },
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
    /// Waiting for a reconnect attempt (graphical sessions).
    Reconnecting = 3,
}

impl Phase {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            1 => Self::Connected,
            3 => Self::Reconnecting,
            _ => Self::Closed,
        }
    }

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Closed => "closed",
            Self::Reconnecting => "reconnecting",
        }
    }
}

/// Shared phase cell of one session.
#[derive(Debug, Clone, Default)]
pub struct PhaseCell(Arc<AtomicU8>);

impl PhaseCell {
    /// Current phase.
    pub fn get(&self) -> Phase {
        Phase::from_u8(self.0.load(Ordering::Relaxed))
    }

    /// Set the phase.
    pub fn set(&self, p: Phase) {
        self.0.store(p as u8, Ordering::Relaxed);
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

/// One running SFTP transfer: its cancel signal and its latest progress (for
/// `sftp_transfers`, review 4 M-10).
#[derive(Debug)]
pub struct TransferEntry {
    /// Fires the cancellation; the transfer then reports `cancelled` itself.
    pub cancel: oneshot::Sender<()>,
    /// Start order, so listings are stable.
    pub seq: u64,
    /// Bytes done and the size hint, updated after every block.
    pub progress: Arc<Mutex<(u64, Option<u64>)>>,
}

/// Running SFTP transfers of one session by transfer id (ADR-0010).
pub type Transfers = Arc<Mutex<HashMap<String, TransferEntry>>>;

/// What IPC can reach of a graphical session besides its command queue.
#[derive(Debug, Clone)]
pub struct GraphicalControl {
    /// The framebuffer (`session_screenshot`).
    pub frames: FrameSink,
    /// Frame credits (`session_frame_ack`).
    pub flow: FrameFlow,
    /// View-only switch (VNC `viewOnly`, `session_set_view_only`).
    pub view_only: Arc<std::sync::atomic::AtomicBool>,
}

/// Protocol-specific control (ADR-0011 `enum Control`).
#[derive(Debug, Clone)]
pub enum Control {
    /// Forwards and SFTP of an SSH session (ADR-0010).
    Ssh(SshControl),
    /// Frames of an RDP / VNC session.
    Graphical(GraphicalControl),
}

/// Registry entry for one live session.
#[derive(Debug)]
pub struct SessionHandle {
    /// Protocol-specific control, usable while the task owns the session.
    pub control: Control,
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
    /// Which view gets events and frames (ADR-0013 detach).
    pub route: Arc<crate::route::Route>,
    phase: PhaseCell,
    task: Option<tokio::task::AbortHandle>,
}

impl SessionHandle {
    /// Current phase.
    pub fn phase(&self) -> Phase {
        self.phase.get()
    }

    /// The SSH control, `None` for graphical sessions.
    pub fn ssh(&self) -> Option<&SshControl> {
        match &self.control {
            Control::Ssh(c) => Some(c),
            Control::Graphical(_) => None,
        }
    }

    /// The graphical control, `None` for SSH sessions.
    pub fn graphical(&self) -> Option<&GraphicalControl> {
        match &self.control {
            Control::Graphical(g) => Some(g),
            Control::Ssh(_) => None,
        }
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
    /// UI channel ([`crate::route::Route::event_sink`] in the app).
    pub sink: EventSink,
    /// The session's view routing.
    pub route: Arc<crate::route::Route>,
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

/// Register a handle and start `task(rx, phase, transfers)`. The registry lock is held while
/// spawning so the task cannot remove the entry before it exists (it locks only on exit).
fn register<F>(
    ctx_registry: &SessionRegistry,
    id: String,
    handle: (Control, String, Protocol, String, Arc<crate::route::Route>),
    task: impl FnOnce(mpsc::Receiver<SessionCommand>, PhaseCell, Transfers) -> F,
) -> IpcResult<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
    let (control, connection_id, protocol, opened_at, route) = handle;
    let phase = PhaseCell::default();
    let transfers = Transfers::default();
    let mut handle = SessionHandle {
        control,
        transfers: Arc::clone(&transfers),
        commands: tx,
        connection_id,
        protocol,
        opened_at,
        route,
        phase: phase.clone(),
        task: None,
    };
    let mut map = ctx_registry.lock().map_err(|_| IpcError::poisoned())?;
    // N-28 (a): concurrent opens all passed the early check before their connect `await`.
    room_for_one(map.len())?;
    let task = tokio::spawn(task(rx, phase, transfers));
    handle.task = Some(task.abort_handle());
    map.insert(id, handle);
    Ok(())
}

/// The session cap, checked again under the registry lock.
fn room_for_one(open: usize) -> IpcResult<()> {
    if open >= crate::commands::sessions::MAX_SESSIONS {
        return Err(IpcError::session_failed("too many open sessions"));
    }
    Ok(())
}

/// Register an SSH `session` and start its task. Must be called inside a Tokio runtime.
pub fn spawn(session: SshSession, ctx: TaskContext, opened_at: String) -> IpcResult<()> {
    let registry = Arc::clone(&ctx.registry);
    let id = ctx.session_id.clone();
    let route = Arc::clone(&ctx.route);
    let meta =
        (Control::Ssh(session.control()), ctx.connection_id.clone(), Protocol::Ssh, opened_at, route);
    register(&registry, id, meta, move |rx, phase, transfers| {
        crate::session_task::run_ssh(session, rx, ctx, phase, transfers)
    })
}

/// Register a graphical session (already connected over TCP) and start its task, which owns
/// the frame pump and the reconnect loop.
pub fn spawn_graphical(
    task: crate::graphical_task::GraphicalTask,
    ctx: TaskContext,
    opened_at: String,
) -> IpcResult<()> {
    let registry = Arc::clone(&ctx.registry);
    let id = ctx.session_id.clone();
    let control = Control::Graphical(task.control());
    let meta = (control, ctx.connection_id.clone(), task.protocol(), opened_at, Arc::clone(&ctx.route));
    register(&registry, id, meta, move |rx, phase, _transfers| task.run(rx, ctx, phase))
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
            protocol: Protocol::Rdp,
            peer_identity: Some("x509 SHA256:ab".into()),
            security: Some("nla".into()),
        });
        let json = serde_json::to_string(&e).expect("json");
        assert!(json.contains(r#""protocol":"rdp""#), "{json}");
        assert!(json.contains(r#""security":"nla""#), "{json}");
        let e = WireEvent::from(SessionEvent::Closed {
            reason: "gone".into(),
            code: CloseCode::TrustMismatch,
        });
        assert_eq!(
            serde_json::to_string(&e).expect("json"),
            r#"{"kind":"closed","reason":"gone","code":"trust_mismatch"}"#
        );
        let e = WireEvent::Reconnecting { attempt: 2, delay_ms: 1900 };
        assert_eq!(
            serde_json::to_string(&e).expect("json"),
            r#"{"kind":"reconnecting","attempt":2,"delay_ms":1900}"#
        );
        let e = WireEvent::from(SessionEvent::DesktopResized { width: 1280, height: 720 });
        assert_eq!(
            serde_json::to_string(&e).expect("json"),
            r#"{"kind":"desktop_resized","width":1280,"height":720}"#
        );
    }

    #[test]
    fn phases_round_trip() {
        for p in [Phase::Connecting, Phase::Connected, Phase::Closed, Phase::Reconnecting] {
            assert_eq!(Phase::from_u8(p as u8), p);
        }
        assert_eq!(Phase::Reconnecting.as_str(), "reconnecting");
        assert_eq!(Phase::from_u8(9), Phase::Closed);
    }

    #[test]
    fn the_cap_is_rechecked_under_the_registry_lock() {
        let max = crate::commands::sessions::MAX_SESSIONS;
        assert!(super::room_for_one(max - 1).is_ok());
        assert_eq!(super::room_for_one(max).expect_err("full").code, "session.failed");
    }
}
