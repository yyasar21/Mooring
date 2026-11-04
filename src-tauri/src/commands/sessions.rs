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
use tauri::ipc::{Channel, InvokeResponseBody, JavaScriptChannelId};
use tauri::{Runtime, State, Webview};
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::clipboard::RemoteClipboard;
use crate::commands::connect_plan::{self, Plan};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::frame_pump::{FrameFlow, FrameOut};
use crate::graphical_task::{GraphicalTask, Launcher};
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
    let ctx = TaskContext {
        session_id: session_id.clone(),
        connection_id: connection.clone(),
        sink,
        audit: Arc::clone(&state.audit),
        registry: Arc::clone(&state.sessions),
    };
    let opened_at = dto::ts(OffsetDateTime::now_utc());
    if is_graphical(protocol) {
        let out = frames.ok_or_else(|| IpcError::invalid("onFrame", "required for rdp and vnc"))?;
        let task = graphical(state, connection, check_desktop(size)?, protocol, out).await?;
        sessions::spawn_graphical(task, ctx, opened_at)?;
        return Ok(Opened { session_id });
    }
    if frames.is_some() {
        return Err(IpcError::invalid("onFrame", "only rdp and vnc sessions send frames"));
    }
    let Plan { params, used, .. } = connect_plan::plan(&state.ready(), connection_id, size)?;
    for cred in used {
        state.audit(AuditEvent::CredentialUsed {
            credential: cred,
            purpose: "connect".to_owned(),
            connection: Some(connection.clone()),
        });
    }
    let mut options = SshOptions::new(state.known_hosts_path());
    options.allow_agent = state.settings.ssh_allow_agent;
    let session = SshSession::connect(params, options).await.map_err(|e| {
        tracing::info!(error = %e, "ssh connect failed");
        IpcError::from(e)
    })?;
    sessions::spawn(session, ctx, opened_at)?;
    Ok(Opened { session_id })
}

async fn graphical(
    state: &AppState,
    connection_id: String,
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
        ready: state.ready(),
        factory: Arc::clone(&state.settings.graphical),
        connection_id,
        size: Arc::new(Mutex::new(size)),
        known_certs: known_certs_path(state, cert),
        clipboard: Arc::new(clipboard),
        frames: mooring_core::frame::FrameSink::new(),
        audit: Arc::clone(&state.audit),
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
    let frames = on_frame.map(|id| {
        let channel: Channel<InvokeResponseBody> = id.channel_on(webview.clone());
        let out: FrameOut = Arc::new(move |bytes| channel.send(InvokeResponseBody::Raw(bytes)).is_ok());
        out
    });
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

/// `window_detach({ sessionId })`: reserved for A2 (ADR-0008); always `ipc.unknown`.
#[tauri::command]
pub fn window_detach(session_id: String) -> IpcResult<()> {
    let _ = session_id;
    Err(IpcError::new("ipc.unknown", "detaching a session is not available in this version"))
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
