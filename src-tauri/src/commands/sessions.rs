//! Session commands (ADR-0008 §Sessions). `session_open` resolves the connection and its
//! effective credential, opens the secret (vault must be unlocked), and hands it to the protocol
//! crate exactly once (ADR-0004). RDP and VNC (ADR-0011/0012) open through
//! [`crate::session_factory`] and get a raw frame channel.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use mooring_audit::AuditEvent;
use mooring_core::known_certs::CertProtocol;
use mooring_core::session::{SessionInput, Size};
use mooring_core::{Protocol, ProtocolOptions};
use mooring_proto_ssh::{SshOptions, SshSession};
use serde::Serialize;
use tauri::ipc::{Channel, JavaScriptChannelId};
use tauri::{Runtime, State, Webview};
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::clipboard::RemoteClipboard;
use crate::commands::connect_plan::{self, Plan};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::frame_pump::{FrameFlow, FrameOut};
use crate::graphical_task::{GraphicalTask, Launcher};
use crate::route::{Route, Sinks};
use crate::sessions::{self, EventSink, SessionCommand, TaskContext, WireEvent};
use crate::state::AppState;

pub use crate::commands::session_input::{
    check_desktop, check_size, decode_input, WireInput, MAX_ANSWER_BYTES, MAX_DIMENSION,
    MAX_INPUT_BYTES,
};

/// Most concurrent sessions.
pub const MAX_SESSIONS: usize = 64;

/// `{ sessionId }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opened {
    /// New session id.
    pub session_id: String,
}

/// One row of `session_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    /// Session id.
    pub session_id: String,
    /// Connection.
    pub connection_id: String,
    /// Protocol name.
    pub protocol: &'static str,
    /// `connecting` | `connected` | `closed`.
    pub state: &'static str,
    /// RFC 3339.
    pub opened_at: String,
    /// ADR-0014 K4: `cluster` | `exec` for Kubernetes sessions, absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    /// ADR-0014 K4: the cluster session of an `exec` session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    /// ADR-0026 §2: dynamic secret leases of the session (expiry only, never ids).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub leases: Vec<LeaseInfoDto>,
}

/// One lease of a session on the wire (the header chip "lease expires in …").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseInfoDto {
    /// `database` | `pki`.
    pub engine: &'static str,
    /// Seconds left (`None`: no TTL reported).
    pub expires_in_seconds: Option<u64>,
    /// Renewed automatically at 2/3 of its TTL.
    pub renewable: bool,
    /// `active` | `renew_failed` | `expired`.
    pub state: &'static str,
}

impl From<&mooring_secrets::LeaseStatus> for LeaseInfoDto {
    fn from(l: &mooring_secrets::LeaseStatus) -> Self {
        Self {
            engine: l.engine.name(),
            expires_in_seconds: l.expires_in.map(|d| d.as_secs()),
            renewable: l.renewable,
            state: l.state,
        }
    }
}

/// `session_open` for SSH (no frame channel); see [`open_with`].
pub async fn open(
    state: &AppState,
    connection_id: &str,
    size: Size,
    sink: EventSink,
) -> IpcResult<Opened> {
    open_with(state, connection_id, size, sink, None).await
}

fn is_graphical(p: Protocol) -> bool {
    matches!(p, Protocol::Rdp | Protocol::Vnc)
}

/// Path of the certificate pin store for a graphical protocol.
pub fn known_certs_path(state: &AppState, protocol: CertProtocol) -> std::path::PathBuf {
    state.data_dir.join(protocol.file_name())
}

/// `session_open`: resolve, connect (TCP only; handshake continues in the session task), and
/// register. Events go to `sink`, MFR1 frames of RDP/VNC to `frames` (required for them,
/// refused for SSH). Must run inside a Tokio runtime.
pub async fn open_with(
    state: &AppState,
    connection_id: &str,
    size: Size,
    sink: EventSink,
    frames: Option<FrameOut>,
) -> IpcResult<Opened> {
    let size = check_size(size)?;
    if state.sessions.lock().map_err(|_| IpcError::poisoned())?.len() >= MAX_SESSIONS {
        return Err(IpcError::session_failed("too many open sessions"));
    }
    let id = dto::connection_id("connectionId", connection_id)?;
    let protocol = state.with_ready(|_, store| Ok(store.get_connection(id)?.protocol))?;
    let connection = id.to_string();
    let session_id = uuid::Uuid::new_v4().to_string();
    // ADR-0013: the task writes through the route, so a detached view can take it over.
    let route = Route::new(Sinks { events: sink, frames: frames.clone() });
    let ctx = TaskContext {
        session_id: session_id.clone(),
        connection_id: connection.clone(),
        sink: route.event_sink(),
        route: Arc::clone(&route),
        audit: Arc::clone(&state.audit),
        registry: Arc::clone(&state.sessions),
        secrets: Some(Arc::clone(&state.secrets)),
    };
    let opened_at = dto::ts(OffsetDateTime::now_utc());
    if is_graphical(protocol) {
        if frames.is_none() {
            return Err(IpcError::invalid("onFrame", "required for rdp and vnc"));
        }
        let task = graphical(state, connection, &session_id, check_desktop(size)?, protocol, route.frame_out())
            .await
            .inspect_err(|_| state.secrets.release_session(&session_id, "closed"))?;
        let control = task.control();
        route.set_on_switch(Arc::new(move || {
            control.flow.reset();
            control.frames.invalidate();
        }));
        sessions::spawn_graphical(task, ctx, opened_at)?;
        return Ok(Opened { session_id });
    }
    if frames.is_some() {
        return Err(IpcError::invalid("onFrame", "only rdp and vnc sessions send frames"));
    }
    let planned = connect_plan::plan(&state.ready(), connection_id, size, &session_id).await;
    let Plan { params, used, hops, .. } = planned.inspect_err(|_| {
        state.secrets.release_session(&session_id, "closed");
    })?;
    for cred in used {
        state.audit(AuditEvent::CredentialUsed {
            credential: cred,
            purpose: "connect".to_owned(),
            connection: Some(connection.clone()),
        });
    }
    let mut options = SshOptions::new(state.known_hosts_path());
    options.allow_agent = state.settings.ssh_allow_agent;
    let session = if hops.is_empty() {
        SshSession::connect(params, options).await
    } else {
        // ADR-0025: the chain opens inside the session task; hop events come first.
        SshSession::connect_chain(params, options, hop_settings(state).hops(hops))
    }
    .map_err(|e| {
        tracing::info!(error = %e, "ssh connect failed");
        state.secrets.release_session(&session_id, "closed");
        IpcError::from(e)
    })?;
    sessions::spawn(session, ctx, opened_at)?;
    Ok(Opened { session_id })
}

/// The jump-host settings of this app (ADR-0025).
pub fn hop_settings(state: &AppState) -> crate::hop_chain::HopSettings {
    crate::hop_chain::HopSettings {
        known_hosts: state.known_hosts_path(),
        allow_agent: state.settings.ssh_allow_agent,
    }
}

async fn graphical(
    state: &AppState,
    connection_id: String,
    session_id: &str,
    size: Size,
    protocol: Protocol,
    out: FrameOut,
) -> IpcResult<GraphicalTask> {
    let cert = if protocol == Protocol::Vnc { CertProtocol::Vnc } else { CertProtocol::Rdp };
    let clipboard =
        RemoteClipboard::new(Arc::clone(&state.settings.clipboard), Arc::clone(&state.remote_clipboard))
            .with_guard(crate::clipboard::RemoteGuard {
                ready: state.ready(),
                audit: Arc::clone(&state.audit),
                connection: connection_id.clone(),
                copied: Arc::clone(&state.copied_credential),
                blocked: Arc::default(),
            });
    let launcher = Launcher {
        session_id: session_id.to_owned(),
        ready: state.ready(),
        factory: Arc::clone(&state.settings.graphical),
        connection_id,
        size: Arc::new(Mutex::new(size)),
        known_certs: known_certs_path(state, cert),
        clipboard: Arc::new(clipboard),
        frames: mooring_core::frame::FrameSink::new(),
        audit: Arc::clone(&state.audit),
        hops: hop_settings(state),
    };
    let first = launcher.connect(None).await.inspect_err(|e| {
        tracing::info!(code = e.code, protocol = protocol.name(), "graphical connect failed");
    })?;
    let view_only = matches!(&first.options, ProtocolOptions::Vnc(o) if o.view_only);
    Ok(GraphicalTask {
        first,
        launcher,
        flow: FrameFlow::default(),
        out,
        reconnect_unit: state.settings.reconnect_unit,
        view_only: Arc::new(AtomicBool::new(view_only)),
    })
}

fn command_sender(
    state: &AppState,
    session_id: &str,
) -> IpcResult<(tokio::sync::mpsc::Sender<SessionCommand>, Protocol)> {
    if session_id.len() > 64 {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    map.get(session_id)
        .map(|h| (h.commands.clone(), h.protocol))
        .ok_or_else(|| IpcError::new("session.not_found", "session not found"))
}

fn connection_of(state: &AppState, session_id: &str) -> IpcResult<String> {
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    map.get(session_id)
        .map(|h| h.connection_id.clone())
        .ok_or_else(|| IpcError::new("session.not_found", "session not found"))
}

fn gone() -> IpcError {
    IpcError::new("session.not_found", "session is closed")
}

/// `session_send({ sessionId, input })`. A sign-in form answer is audited as
/// `credential_prompted {connection, username}` (never the password).
pub async fn send(state: &AppState, session_id: &str, input: WireInput) -> IpcResult<()> {
    let (tx, protocol) = command_sender(state, session_id)?;
    let input = decode_input(input)?;
    if let SessionInput::Resize { size } = &input {
        if is_graphical(protocol) {
            check_desktop(*size)?;
        }
    }
    if let SessionInput::CredentialAnswer { username, .. } = &input {
        if !username.is_empty() {
            let connection = connection_of(state, session_id)?;
            state.audit(AuditEvent::CredentialPrompted { connection, username: username.clone() });
        }
    }
    let (reply, rx) = oneshot::channel();
    tx.send(SessionCommand::Input(input, reply)).await.map_err(|_| gone())?;
    rx.await.map_err(|_| gone())?
}

/// `session_close({ sessionId })`. The task writes `session_closed` and leaves the registry.
pub async fn close(state: &AppState, session_id: &str) -> IpcResult<()> {
    let (tx, _) = command_sender(state, session_id)?;
    let (reply, rx) = oneshot::channel();
    tx.send(SessionCommand::Close(reply)).await.map_err(|_| gone())?;
    // The task may finish before replying; either way the session is closed.
    let _ = rx.await;
    Ok(())
}

/// `session_list()`.
pub fn list(state: &AppState) -> IpcResult<Vec<SessionInfo>> {
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    let mut out: Vec<SessionInfo> = map
        .iter()
        .map(|(id, h)| SessionInfo {
            session_id: id.clone(),
            connection_id: h.connection_id.clone(),
            protocol: h.protocol.name(),
            state: h.phase().as_str(),
            opened_at: h.opened_at.clone(),
            kind: crate::kube_sessions::list_kind(&h.control).map(|k| k.0),
            parent_session_id: crate::kube_sessions::list_kind(&h.control).and_then(|k| k.1),
            leases: state.secrets.lease_status(id).iter().map(LeaseInfoDto::from).collect(),
        })
        .collect();
    out.sort_by(|a, b| a.opened_at.cmp(&b.opened_at).then(a.session_id.cmp(&b.session_id)));
    Ok(out)
}

// ------------------------------------------------------------------ Tauri wrappers

/// `session_open({ connectionId, size, onEvent, onFrame? })`. `onFrame` receives raw MFR1
/// bytes (`InvokeResponseBody::Raw`, an `ArrayBuffer` in the UI), never JSON. Only the main
/// window may open sessions (remote web windows get `ipc.forbidden`, ADR-0013).
#[tauri::command]
pub async fn session_open<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, AppState>,
    connection_id: String,
    size: Size,
    on_event: Channel<WireEvent>,
    on_frame: Option<JavaScriptChannelId>,
) -> IpcResult<Opened> {
    if webview.label() != crate::navigation::MAIN_WINDOW {
        return Err(IpcError::new("ipc.forbidden", "this window cannot open sessions"));
    }
    let frames = on_frame.map(|id| crate::commands::detach::frame_channel(&webview, id));
    let sink: EventSink = Arc::new(move |e| on_event.send(e).is_ok());
    open_with(&state, &connection_id, size, sink, frames).await
}

/// `session_send({ sessionId, input })`.
#[tauri::command]
pub async fn session_send(
    state: State<'_, AppState>,
    session_id: String,
    input: WireInput,
) -> IpcResult<()> {
    send(&state, &session_id, input).await
}

/// `session_close({ sessionId })`.
#[tauri::command]
pub async fn session_close(state: State<'_, AppState>, session_id: String) -> IpcResult<()> {
    close(&state, &session_id).await
}

/// `session_list()`.
#[tauri::command]
pub fn session_list(state: State<'_, AppState>) -> IpcResult<Vec<SessionInfo>> {
    list(&state)
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
