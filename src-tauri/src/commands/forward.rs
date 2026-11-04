//! Port forwarding commands (ADR-0010 §Port forwarding). Each call is routed through the
//! session registry to the session's `SshControl`; the crate enforces the limits (64 forwards,
//! 128 connections each) and the exposure policy, this layer validates the wire shape and
//! audits every open (with its `exposure`) and close.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mooring_core::MooringError;
use mooring_proto_ssh::{Exposure, ForwardId, ForwardInfo, ForwardKind, SshControl};
use serde::{Deserialize, Serialize};
use tauri::State;
use time::OffsetDateTime;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::sessions;
use crate::state::AppState;

/// Longest host name accepted in `bind` / `target` (DNS limit).
const MAX_HOST: usize = 253;
/// Longest `forwardId` accepted.
const MAX_FORWARD_ID: usize = 32;

/// `{ host, port }` as the UI sends it. The port is `u32` so an out-of-range value is an
/// `input.invalid` from this layer, not a deserialisation failure.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireEndpoint {
    /// Host or IP literal.
    pub host: String,
    /// Port.
    pub port: u32,
}

/// `{ host, port }` as the UI receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    /// Host or IP literal.
    pub host: String,
    /// Port.
    pub port: u16,
}

/// Arguments of `forward_open` besides `sessionId`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardRequest {
    /// `local` | `remote` | `dynamic`.
    pub kind: String,
    /// Listener address (local side for local/dynamic, server side for remote).
    pub bind: WireEndpoint,
    /// Target; required for local/remote, absent for dynamic.
    #[serde(default)]
    pub target: Option<WireEndpoint>,
    /// `loopback` (default) | `external`.
    #[serde(default)]
    pub exposure: Option<String>,
}

/// `ForwardInfo` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardDto {
    /// `fwd-<n>`.
    pub id: String,
    /// `local` | `remote` | `dynamic`.
    pub kind: &'static str,
    /// Bound address (allocated port when 0 was asked).
    pub bind: Endpoint,
    /// Target, `null` for dynamic.
    pub target: Option<Endpoint>,
    /// `loopback` | `external`.
    pub exposure: &'static str,
    /// RFC 3339.
    pub opened_at: String,
    /// Live connections through the forward.
    pub connections: usize,
}

impl From<ForwardInfo> for ForwardDto {
    fn from(f: ForwardInfo) -> Self {
        Self {
            id: f.id.to_string(),
            kind: f.kind.as_str(),
            bind: Endpoint { host: f.bind_host, port: f.port },
            target: f.target_addr.map(|(host, port)| Endpoint { host, port }),
            exposure: f.exposure.as_str(),
            opened_at: dto::ts(OffsetDateTime::from(f.opened_at)),
            connections: f.connections,
        }
    }
}

/// The session's control and connection id; `session.not_found` when it is not live.
pub(crate) fn control_of(state: &AppState, session_id: &str) -> IpcResult<(SshControl, String)> {
    if session_id.is_empty() || session_id.len() > 64 {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    map.get(session_id)
        .map(|h| (h.control.clone(), h.connection_id.clone()))
        .ok_or_else(|| IpcError::new("session.not_found", "session not found"))
}

/// Errors shared by the forward and SFTP commands.
pub(crate) fn session_error(e: MooringError) -> IpcError {
    match e {
        MooringError::Closed => IpcError::new("session.not_found", "session is closed"),
        MooringError::Protocol { reason, .. } if reason == "not connected" => {
            IpcError::new("session.not_connected", "the session is not connected yet")
        }
        other => IpcError::from(other),
    }
}

fn forward_error(e: MooringError) -> IpcError {
    match e {
        MooringError::Invalid { field: "forward", reason } => IpcError::new("forward.limit", reason),
        MooringError::NotFound { kind: "forward", .. } => {
            IpcError::new("forward.not_found", "forward not found")
        }
        MooringError::Transport(reason) if reason.starts_with("bind failed") => {
            IpcError::new("forward.bind", reason)
        }
        MooringError::Protocol { reason, .. }
            if reason == "remote forward refused" || reason == "server allocated no port" =>
        {
            IpcError::new("forward.bind", reason)
        }
        other => session_error(other),
    }
}

fn kind(raw: &str) -> IpcResult<ForwardKind> {
    match raw {
        "local" => Ok(ForwardKind::Local),
        "remote" => Ok(ForwardKind::Remote),
        "dynamic" => Ok(ForwardKind::Dynamic),
        _ => Err(IpcError::invalid("kind", "expected local, remote or dynamic")),
    }
}

fn exposure(raw: Option<&str>) -> IpcResult<Exposure> {
    match raw {
        None | Some("loopback") => Ok(Exposure::Loopback),
        Some("external") => Ok(Exposure::External),
        Some(_) => Err(IpcError::invalid("exposure", "expected loopback or external")),
    }
}

fn port(field: &str, raw: u32, allow_zero: bool) -> IpcResult<u16> {
    match u16::try_from(raw) {
        Ok(0) if !allow_zero => Err(IpcError::invalid(field, "must be 1-65535")),
        Ok(p) => Ok(p),
        Err(_) => Err(IpcError::invalid(field, "must be 0-65535")),
    }
}

fn host(field: &str, raw: &str) -> IpcResult<String> {
    if raw.is_empty() || raw.len() > MAX_HOST || raw.chars().any(|c| c.is_control() || c == ' ') {
        return Err(IpcError::invalid(field, "not a host name or address"));
    }
    Ok(raw.to_owned())
}

/// A socket address on this machine: an IP literal or `localhost`.
fn local_addr(field: &str, e: &WireEndpoint, allow_zero: bool) -> IpcResult<SocketAddr> {
    let h = host(field, &e.host)?;
    let ip = if h.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        let bare = h.trim_start_matches('[').trim_end_matches(']');
        bare.parse().map_err(|_| IpcError::invalid(field, "must be an IP address or localhost"))?
    };
    Ok(SocketAddr::new(ip, port(field, e.port, allow_zero)?))
}

/// A validated `forward_open` request.
enum Plan {
    Local(SocketAddr, (String, u16)),
    Remote((String, u16), SocketAddr),
    Dynamic(SocketAddr),
}

fn plan(req: &ForwardRequest) -> IpcResult<Plan> {
    Ok(match (kind(&req.kind)?, &req.target) {
        (ForwardKind::Dynamic, Some(_)) => {
            return Err(IpcError::invalid("target", "a dynamic forward has no target"));
        }
        (ForwardKind::Local | ForwardKind::Remote, None) => {
            return Err(IpcError::invalid("target", "required"));
        }
        (ForwardKind::Local, Some(t)) => Plan::Local(
            local_addr("bind", &req.bind, true)?,
            (host("target", &t.host)?, port("target port", t.port, false)?),
        ),
        (ForwardKind::Remote, Some(t)) => Plan::Remote(
            (host("bind", &req.bind.host)?, port("bind port", req.bind.port, true)?),
            local_addr("target", t, false)?,
        ),
        (ForwardKind::Dynamic, None) => Plan::Dynamic(local_addr("bind", &req.bind, true)?),
    })
}

/// `forward_open`: validate, open through the session, audit, return the listed forward.
pub async fn open(state: &AppState, session_id: &str, req: ForwardRequest) -> IpcResult<ForwardDto> {
    let plan = plan(&req)?;
    let exposure = exposure(req.exposure.as_deref())?;
    let (control, connection) = control_of(state, session_id)?;
    let result = match plan {
        Plan::Local(bind, target) => control.forward_local(bind, target, exposure).await,
        Plan::Remote(bind, target) => control.forward_remote(bind, target, exposure).await,
        Plan::Dynamic(bind) => control.forward_dynamic(bind, exposure).await,
    };
    sessions::audit_trust(&state.audit, &connection, control.take_audit_events());
    let id = result.map_err(forward_error)?;
    if exposure == Exposure::External {
        tracing::warn!(forward = %id, "forward opened with external exposure");
    }
    control
        .forwards()
        .into_iter()
        .find(|f| f.id == id)
        .map(ForwardDto::from)
        // Closed between open and list (session ended): report it as gone.
        .ok_or_else(|| IpcError::new("forward.not_found", "forward closed"))
}

/// `forward_close({ sessionId, forwardId })`.
pub async fn close(state: &AppState, session_id: &str, forward_id: &str) -> IpcResult<()> {
    if forward_id.len() > MAX_FORWARD_ID {
        return Err(IpcError::invalid("forwardId", "expected fwd-<number>"));
    }
    let id: ForwardId =
        forward_id.parse().map_err(|_| IpcError::invalid("forwardId", "expected fwd-<number>"))?;
    let (control, connection) = control_of(state, session_id)?;
    let result = control.forward_close(id).await;
    sessions::audit_trust(&state.audit, &connection, control.take_audit_events());
    result.map_err(forward_error)
}

/// `forward_list({ sessionId })`, ordered by id.
pub fn list(state: &AppState, session_id: &str) -> IpcResult<Vec<ForwardDto>> {
    let (control, _) = control_of(state, session_id)?;
    Ok(control.forwards().into_iter().map(ForwardDto::from).collect())
}

/// Close every `external` forward of every session (each audited `forward_closed`). Called on
/// every vault lock (review 4 M-10, amends ADR-0006): a LAN-reachable listener must not keep
/// running while nobody can see it. Loopback forwards survive, as sessions do. Returns how
/// many were closed.
pub fn close_external(state: &AppState) -> usize {
    let live: Vec<(SshControl, String)> = match state.sessions.lock() {
        Ok(map) => map.values().map(|h| (h.control.clone(), h.connection_id.clone())).collect(),
        Err(_) => return 0,
    };
    let mut closed = 0;
    for (control, connection) in live {
        let n = control.close_external_forwards();
        if n > 0 {
            sessions::audit_trust(&state.audit, &connection, control.take_audit_events());
            closed += n;
        }
    }
    if closed > 0 {
        tracing::info!(closed, "external forwards closed on lock");
    }
    closed
}

// ------------------------------------------------------------------ Tauri wrappers

/// `forward_open({ sessionId, kind, bind, target?, exposure })`.
#[tauri::command]
pub async fn forward_open(
    state: State<'_, AppState>,
    session_id: String,
    kind: String,
    bind: WireEndpoint,
    target: Option<WireEndpoint>,
    exposure: Option<String>,
) -> IpcResult<ForwardDto> {
    open(&state, &session_id, ForwardRequest { kind, bind, target, exposure }).await
}

/// `forward_close({ sessionId, forwardId })`.
#[tauri::command]
pub async fn forward_close(
    state: State<'_, AppState>,
    session_id: String,
    forward_id: String,
) -> IpcResult<()> {
    close(&state, &session_id, &forward_id).await
}

/// `forward_list({ sessionId })`.
#[tauri::command]
pub fn forward_list(state: State<'_, AppState>, session_id: String) -> IpcResult<Vec<ForwardDto>> {
    list(&state, &session_id)
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
