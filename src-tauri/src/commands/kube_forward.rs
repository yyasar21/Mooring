//! Pod port-forwards (ADR-0014 §5, K4) behind the ADR-0010 `forward_open` / `forward_close` /
//! `forward_list` commands: on a cluster session `kind` is `pod` and `target` is
//! `{ namespace, pod, port }`. Loopback only in A3 (`exposure: "external"` is refused); each
//! forward is audited `kube_forward_opened` / `kube_forward_closed` and ends with its cluster
//! session (so also on a vault lock).

use std::net::SocketAddr;

use mooring_proto_kube::{PodForward, PodTarget};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::commands::forward::Endpoint;
use crate::commands::kube::{client_of, cluster_of, namespace, pod_name};
use crate::commands::kube_wire::kube_error;
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::kube_sessions::ForwardEntry;
use crate::state::AppState;

/// Forwards per cluster session (ADR-0010 value).
pub const MAX_FORWARDS: usize = 64;

/// `target` of a pod forward as the UI sends it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodTargetWire {
    /// Namespace.
    pub namespace: String,
    /// Pod.
    pub pod: String,
    /// Container port (1..=65535).
    pub port: u32,
}

/// A pod forward on the wire (same fields as `ForwardDto`, pod target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PodForwardDto {
    /// `fwd-<n>`.
    pub id: String,
    /// `pod`.
    pub kind: &'static str,
    /// Bound local address.
    pub bind: Endpoint,
    /// Pod side.
    pub target: PodTargetWire,
    /// `loopback`.
    pub exposure: &'static str,
    /// RFC 3339.
    pub opened_at: String,
    /// Live connections.
    pub connections: usize,
}

fn dto(id: u64, e: &ForwardEntry) -> PodForwardDto {
    let addr = e.forward.local_addr();
    let t = e.forward.target();
    PodForwardDto {
        id: format!("fwd-{id}"),
        kind: "pod",
        bind: Endpoint { host: addr.ip().to_string(), port: addr.port() },
        target: PodTargetWire { namespace: t.namespace.clone(), pod: t.pod.clone(), port: u32::from(t.port) },
        exposure: "loopback",
        opened_at: e.opened_at.clone(),
        connections: e.forward.connections(),
    }
}

/// `forward_open({ sessionId, kind: "pod", bind, target, exposure })`.
pub async fn open(
    state: &AppState,
    session_id: &str,
    bind: SocketAddr,
    target: PodTargetWire,
    exposure: Option<&str>,
) -> IpcResult<PodForwardDto> {
    match exposure {
        None | Some("loopback") => {}
        Some("external") => {
            return Err(IpcError::invalid("exposure", "pod forwards are loopback only in this version"));
        }
        Some(_) => return Err(IpcError::invalid("exposure", "expected loopback or external")),
    }
    if !bind.ip().is_loopback() {
        return Err(IpcError::invalid("bind", "pod forwards bind to loopback only"));
    }
    let ns = namespace(&target.namespace)?.to_owned();
    let pod = pod_name(&target.pod)?.to_owned();
    let port = match u16::try_from(target.port) {
        Ok(p) if p > 0 => p,
        _ => return Err(IpcError::invalid("target port", "must be 1-65535")),
    };
    let (ctrl, client) = client_of(state, session_id)?;
    if ctrl.forwards().len() >= MAX_FORWARDS {
        return Err(IpcError::new("forward.limit", "too many forwards on this session"));
    }
    let n = ctrl.next_id();
    let result = PodForward::open(&client, &format!("fwd-{n}"), bind, PodTarget { namespace: ns, pod, port }).await;
    ctrl.drain_audit();
    let forward = result.map_err(|e| match e {
        mooring_proto_kube::KubeError::Invalid(r) if r.starts_with("could not bind") => {
            IpcError::new("forward.bind", r)
        }
        other => kube_error(&other),
    })?;
    let entry = ForwardEntry { forward, opened_at: dto::ts(OffsetDateTime::now_utc()) };
    let out = dto(n, &entry);
    let mut map = ctrl.forwards();
    if ctrl.ended() {
        drop(map);
        drop(entry);
        ctrl.drain_audit();
        return Err(IpcError::new("session.not_found", "session is closed"));
    }
    map.insert(n, entry);
    Ok(out)
}

/// `forward_close` on a cluster session.
pub fn close(state: &AppState, session_id: &str, forward_id: &str) -> IpcResult<()> {
    let n: u64 = forward_id
        .strip_prefix("fwd-")
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| IpcError::invalid("forwardId", "expected fwd-<number>"))?;
    let ctrl = cluster_of(state, session_id)?;
    let entry = ctrl.forwards().remove(&n);
    let entry = entry.ok_or_else(|| IpcError::new("forward.not_found", "forward not found"))?;
    drop(entry);
    ctrl.drain_audit();
    Ok(())
}

/// `forward_list` on a cluster session, by id.
pub fn list(state: &AppState, session_id: &str) -> IpcResult<Vec<PodForwardDto>> {
    let ctrl = cluster_of(state, session_id)?;
    let map = ctrl.forwards();
    Ok(map.iter().map(|(n, e)| dto(*n, e)).collect())
}

/// Whether `session_id` names a Kubernetes cluster session (forward commands dispatch on it).
pub fn is_cluster(state: &AppState, session_id: &str) -> bool {
    cluster_of(state, session_id).is_ok()
}
