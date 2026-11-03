//! Session commands (ADR-0008 §Sessions). `session_open` resolves the connection and its
//! effective credential, opens the secret (vault must be unlocked), and hands it to the protocol
//! crate exactly once (ADR-0004). Only SSH is available in A1.

use std::sync::Arc;

use base64::Engine as _;
use mooring_audit::AuditEvent;
use mooring_core::session::{SessionInput, Size};
use mooring_proto_ssh::{SshOptions, SshSession};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::State;
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::commands::connect_plan::{self, Plan};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::sessions::{self, EventSink, SessionCommand, TaskContext, WireEvent};
use crate::state::AppState;

/// Largest terminal size accepted (columns / rows, or pixels for graphical protocols).
pub const MAX_DIMENSION: u32 = 16_384;
/// Largest `Bytes` input per call (decoded).
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Longest prompt answer (bytes).
pub const MAX_ANSWER_BYTES: usize = 4096;
/// Most concurrent sessions.
pub const MAX_SESSIONS: usize = 64;

/// `SessionInput` as the UI sends it: `kind` tag, base64 bytes, answer text wrapped at once.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireInput {
    /// Keystrokes, base64.
    Bytes {
        /// Payload.
        data: String,
    },
    /// New size.
    Resize {
        /// Size.
        size: Size,
    },
    /// Pointer (graphical).
    Pointer {
        /// X.
        x: u32,
        /// Y.
        y: u32,
        /// Buttons.
        buttons: u8,
    },
    /// Key (graphical).
    Key {
        /// Scancode.
        scancode: u32,
        /// Pressed.
        pressed: bool,
    },
    /// Prompt answer; never logged or echoed.
    Answer {
        /// Prompt id.
        id: u32,
        /// Answer.
        text: SecretString,
    },
    /// Sign-in form answer for a `credential` prompt (ADR-0009). Empty username and password
    /// mean the user cancelled.
    CredentialAnswer {
        /// Prompt id.
        id: u32,
        /// Username as typed.
        username: String,
        /// Domain, when asked.
        #[serde(default)]
        domain: Option<String>,
        /// Password; never logged or echoed.
        password: SecretString,
    },
}

impl std::fmt::Debug for WireInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Bytes { .. } => "bytes",
            Self::Resize { .. } => "resize",
            Self::Pointer { .. } => "pointer",
            Self::Key { .. } => "key",
            Self::Answer { .. } => "answer",
            Self::CredentialAnswer { .. } => "credential_answer",
        };
        write!(f, "WireInput({kind}, <redacted>)")
    }
}

fn check_size(size: Size) -> IpcResult<Size> {
    if size.width == 0
        || size.height == 0
        || size.width > MAX_DIMENSION
        || size.height > MAX_DIMENSION
    {
        return Err(IpcError::invalid("size", "width and height must be 1..=16384"));
    }
    Ok(size)
}

/// Validate and decode one input.
pub fn decode_input(input: WireInput) -> IpcResult<SessionInput> {
    Ok(match input {
        WireInput::Bytes { data } => {
            // base64 is 4/3 the decoded size; refuse before allocating.
            if data.len() > MAX_INPUT_BYTES.div_ceil(3) * 4 {
                return Err(IpcError::invalid("data", "larger than 64 KiB"));
            }
            let data = base64::engine::general_purpose::STANDARD
                .decode(data.as_bytes())
                .map_err(|_| IpcError::invalid("data", "not base64"))?;
            SessionInput::Bytes { data }
        }
        WireInput::Resize { size } => SessionInput::Resize { size: check_size(size)? },
        WireInput::Pointer { x, y, buttons } => SessionInput::Pointer { x, y, buttons },
        WireInput::Key { scancode, pressed } => SessionInput::Key { scancode, pressed },
        WireInput::Answer { id, text } => {
            if secrecy::ExposeSecret::expose_secret(&text).len() > MAX_ANSWER_BYTES {
                return Err(IpcError::invalid("text", "longer than 4096 bytes"));
            }
            SessionInput::Answer { id, text }
        }
        WireInput::CredentialAnswer { id, username, domain, password } => {
            if secrecy::ExposeSecret::expose_secret(&password).len() > MAX_ANSWER_BYTES {
                return Err(IpcError::invalid("password", "longer than 4096 bytes"));
            }
            let username = username.trim().to_owned();
            let domain = domain.map(|d| d.trim().to_owned()).filter(|d| !d.is_empty());
            let bad = |s: &str, max: usize| {
                s.len() > max || s.chars().any(mooring_core::credential::is_forbidden)
            };
            if bad(&username, 256) || domain.as_deref().is_some_and(|d| bad(d, 253)) {
                return Err(IpcError::invalid("username", "too long or has control characters"));
            }
            SessionInput::CredentialAnswer { id, username, domain, password }
        }
    })
}

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

/// `session_open`: resolve, connect (TCP only; handshake continues in the session task), and
/// register. Events go to `sink`. Must run inside a Tokio runtime.
pub async fn open(
    state: &AppState,
    connection_id: &str,
    size: Size,
    sink: EventSink,
) -> IpcResult<Opened> {
    let size = check_size(size)?;
    if state.sessions.lock().map_err(|_| IpcError::poisoned())?.len() >= MAX_SESSIONS {
        return Err(IpcError::session_failed("too many open sessions"));
    }
    let Plan { params, used } = connect_plan::plan(state, connection_id, size)?;
    let connection = dto::connection_id("connectionId", connection_id)?.to_string();
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
    let session_id = uuid::Uuid::new_v4().to_string();
    let ctx = TaskContext {
        session_id: session_id.clone(),
        connection_id: connection,
        sink,
        audit: Arc::clone(&state.audit),
        registry: Arc::clone(&state.sessions),
    };
    sessions::spawn(session, ctx, dto::ts(OffsetDateTime::now_utc()))?;
    Ok(Opened { session_id })
}

fn command_sender(
    state: &AppState,
    session_id: &str,
) -> IpcResult<tokio::sync::mpsc::Sender<SessionCommand>> {
    if session_id.len() > 64 {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    map.get(session_id)
        .map(|h| h.commands.clone())
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
    let tx = command_sender(state, session_id)?;
    let input = decode_input(input)?;
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
    let tx = command_sender(state, session_id)?;
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

/// `session_open({ connectionId, size, onEvent })`.
#[tauri::command]
pub async fn session_open(
    state: State<'_, AppState>,
    connection_id: String,
    size: Size,
    on_event: Channel<WireEvent>,
) -> IpcResult<Opened> {
    let sink: EventSink = Arc::new(move |e| on_event.send(e).is_ok());
    open(&state, &connection_id, size, sink).await
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
