//! Kubernetes commands (ADR-0014 §6, task K4). Read-only by construction: every request goes
//! through `mooring-proto-kube`'s `ReadOnlyGuard`; a refusal is `kube.refused` and audited
//! `kube_request_refused`. The cluster audit queue is drained after every command.
//!
//! `kube_open` returns at once; connection, the certificate prompt, the RBAC pre-flight and
//! the end arrive on `onEvent` ([`ClusterEvent`]). `kube_access`, `kube_namespaces` and
//! `kube_pods` are passive (`ipc-passive.json`).

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_core::credential::kubeconfig::{is_dns_label, is_dns_subdomain};
use mooring_core::credential::CredentialFields;
use mooring_core::known_certs::CertProtocol;
use mooring_core::options::ExecCommand;
use mooring_core::session::Size;
use mooring_proto_kube::{ExecTarget, Listing, PodSummary};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{Runtime, State, Webview};
use time::OffsetDateTime;

use crate::commands::connect_plan;
use crate::commands::kube_cluster::{self, ClusterSink, ClusterStart};
use crate::commands::kube_wire::{kube_error, AccessDto, ClusterEvent};
use crate::commands::sessions::{check_size, known_certs_path, Opened, MAX_SESSIONS};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::kube_sessions::{run_exec, KubeControl, KubeRole};
use crate::route::{Route, Sinks};
use crate::sessions::{self, Control, EventSink, TaskContext, WireEvent};
use crate::state::AppState;

/// Longest label selector accepted.
const MAX_SELECTOR: usize = 1024;

fn noop_sink() -> EventSink {
    Arc::new(|_| true)
}

fn room(state: &AppState) -> IpcResult<()> {
    if state.sessions.lock().map_err(|_| IpcError::poisoned())?.len() >= MAX_SESSIONS {
        return Err(IpcError::session_failed("too many open sessions"));
    }
    Ok(())
}

/// The cluster control of `session_id`.
pub fn cluster_of(state: &AppState, session_id: &str) -> IpcResult<KubeControl> {
    if session_id.is_empty() || session_id.len() > 64 {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    let h = map.get(session_id).ok_or_else(|| IpcError::new("session.not_found", "session not found"))?;
    match &h.control {
        Control::Kube(KubeRole::Cluster(c)) => Ok(c.clone()),
        _ => Err(IpcError::invalid("sessionId", "not a Kubernetes cluster session")),
    }
}

/// The connected client of `session_id`.
pub fn client_of(state: &AppState, session_id: &str) -> IpcResult<(KubeControl, mooring_proto_kube::KubeClient)> {
    let ctrl = cluster_of(state, session_id)?;
    let client = ctrl
        .client()
        .ok_or_else(|| IpcError::new("session.not_connected", "the cluster session is not connected yet"))?;
    Ok((ctrl, client))
}

/// A namespace argument.
pub fn namespace(raw: &str) -> IpcResult<&str> {
    if is_dns_label(raw) { Ok(raw) } else { Err(IpcError::invalid("namespace", "must be an RFC 1123 label")) }
}

/// A pod name argument.
pub fn pod_name(raw: &str) -> IpcResult<&str> {
    if is_dns_subdomain(raw) { Ok(raw) } else { Err(IpcError::invalid("pod", "must be an RFC 1123 subdomain")) }
}

/// An optional container argument (`null` / empty = the pod's default).
pub fn container(raw: Option<&str>) -> IpcResult<Option<String>> {
    match raw {
        None | Some("") => Ok(None),
        Some(c) if is_dns_label(c) => Ok(Some(c.to_owned())),
        Some(_) => Err(IpcError::invalid("container", "must be an RFC 1123 label")),
    }
}

/// `kube_open({ connectionId, onEvent })` → `{ sessionId }` of the cluster session. Credential
/// and option errors fail here; everything after that arrives on `sink`.
pub fn open(state: &AppState, connection_id: &str, sink: ClusterSink) -> IpcResult<Opened> {
    room(state)?;
    let plan = connect_plan::kube(&state.ready(), connection_id)?;
    for cred in &plan.used {
        state.audit(AuditEvent::CredentialUsed {
            credential: cred.clone(),
            purpose: "connect".to_owned(),
            connection: Some(plan.connection_id.clone()),
        });
    }
    let connection = plan.connection_id.clone();
    let ctrl = KubeControl::new(
        connection.clone(),
        Arc::clone(&state.audit),
        Arc::clone(&state.sessions),
        plan.options.exec_command,
    );
    let session_id = uuid::Uuid::new_v4().to_string();
    let route = Route::new(Sinks { events: noop_sink(), frames: None });
    let ctx = TaskContext {
        session_id: session_id.clone(),
        connection_id: connection.clone(),
        sink: noop_sink(),
        route: Arc::clone(&route),
        audit: Arc::clone(&state.audit),
        registry: Arc::clone(&state.sessions),
    };
    let start = ClusterStart {
        ctrl: ctrl.clone(),
        plan,
        known_certs: known_certs_path(state, CertProtocol::Kube),
        sink,
        ctx,
    };
    let meta = (Control::Kube(KubeRole::Cluster(ctrl)), connection, dto::ts(OffsetDateTime::now_utc()), route);
    sessions::spawn_kube(&state.sessions, session_id.clone(), meta, move |rx, phase| {
        kube_cluster::run(start, rx, phase)
    })?;
    Ok(Opened { session_id })
}

/// `kube_access({ sessionId, namespace })` (passive): the cached pre-flight, else a new one.
pub async fn access(state: &AppState, session_id: &str, ns: &str) -> IpcResult<AccessDto> {
    let ns = namespace(ns)?;
    let (ctrl, client) = client_of(state, session_id)?;
    if let Some(a) = ctrl.access(ns) {
        return Ok(a);
    }
    let r = client.preflight(ns).await;
    ctrl.drain_audit();
    let a = AccessDto::from(&r.map_err(|e| kube_error(&e))?);
    ctrl.cache_access(ns, a);
    Ok(a)
}

/// `kube_contexts({ credentialId })` → `{ contexts, selected }`: names only, from the stored
/// (non-secret) fields of a `kubeconfig` credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Contexts {
    /// Context names.
    pub contexts: Vec<String>,
    /// The credential's selected context, `null` = `current-context`.
    pub selected: Option<String>,
}

/// `kube_contexts`.
pub fn contexts(state: &AppState, credential_id: &str) -> IpcResult<Contexts> {
    let id = dto::credential_id("credentialId", credential_id)?;
    state.with_ready(|_, store| match store.get_credential(id)?.fields {
        CredentialFields::Kubeconfig(f) => Ok(Contexts { contexts: f.contexts, selected: f.context }),
        _ => Err(IpcError::invalid("credentialId", "not a kubeconfig credential")),
    })
}

/// `kube_namespaces({ sessionId })` (passive).
pub async fn namespaces(state: &AppState, session_id: &str) -> IpcResult<Listing<String>> {
    let (ctrl, client) = client_of(state, session_id)?;
    let r = client.namespaces().await;
    ctrl.drain_audit();
    r.map_err(|e| kube_error(&e))
}

/// `kube_pods({ sessionId, namespace, labelSelector? })` (passive). Pages (`limit=500` +
/// `continue`, ≤ 10 pages) are followed in Rust; `truncated` says the list was cut.
pub async fn pods(
    state: &AppState,
    session_id: &str,
    ns: &str,
    label_selector: Option<&str>,
) -> IpcResult<Listing<PodSummary>> {
    let ns = namespace(ns)?;
    let selector = label_selector.filter(|s| !s.is_empty());
    if selector.is_some_and(|s| s.len() > MAX_SELECTOR) {
        return Err(IpcError::invalid("labelSelector", "longer than 1024 bytes"));
    }
    let (ctrl, client) = client_of(state, session_id)?;
    let r = client.pods(ns, selector).await;
    ctrl.drain_audit();
    r.map_err(|e| kube_error(&e))
}

/// `kube_pod({ sessionId, namespace, pod })`.
pub async fn pod(state: &AppState, session_id: &str, ns: &str, pod: &str) -> IpcResult<PodSummary> {
    let (ns, pod) = (namespace(ns)?, pod_name(pod)?);
    let (ctrl, client) = client_of(state, session_id)?;
    let r = client.pod(ns, pod).await;
    ctrl.drain_audit();
    r.map_err(|e| kube_error(&e))
}

/// Arguments of `kube_exec_open` besides `sessionId` and `onEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    /// Namespace.
    pub namespace: String,
    /// Pod.
    pub pod: String,
    /// Container, `null` = the pod's default.
    #[serde(default)]
    pub container: Option<String>,
    /// One of the five allow-listed shells; `null` = the connection's `execCommand`.
    #[serde(default)]
    pub command: Option<String>,
    /// Terminal size.
    pub size: Size,
}

fn exec_command(raw: Option<&str>, default: ExecCommand) -> IpcResult<ExecCommand> {
    match raw {
        None => Ok(default),
        Some(c) => ExecCommand::ALL
            .into_iter()
            .find(|e| e.as_str() == c)
            .ok_or_else(|| IpcError::invalid("command", "must be one of /bin/sh, /bin/bash, /bin/ash, sh, bash")),
    }
}

/// `kube_exec_open({ sessionId, namespace, pod, container?, command?, size, onEvent })` →
/// `{ sessionId }` of a new terminal session (`session_send` / `session_close` as for SSH).
pub async fn exec_open(state: &AppState, session_id: &str, req: ExecRequest, sink: EventSink) -> IpcResult<Opened> {
    let size = check_size(req.size)?;
    let (ns, pod) = (namespace(&req.namespace)?.to_owned(), pod_name(&req.pod)?.to_owned());
    let container = container(req.container.as_deref())?;
    room(state)?;
    let (ctrl, client) = client_of(state, session_id)?;
    let command = exec_command(req.command.as_deref(), ctrl.exec_command())?;
    let target = ExecTarget { namespace: ns, pod, container, command };
    let session = crate::session_factory::kube_exec(&client, target, size).await;
    ctrl.drain_audit();
    let session = session.map_err(|e| kube_error(&e))?;
    let exec_id = uuid::Uuid::new_v4().to_string();
    let route = Route::new(Sinks { events: sink, frames: None });
    let ctx = TaskContext {
        session_id: exec_id.clone(),
        connection_id: ctrl.connection_id().to_owned(),
        sink: route.event_sink(),
        route: Arc::clone(&route),
        audit: Arc::clone(&state.audit),
        registry: Arc::clone(&state.sessions),
    };
    let role = KubeRole::Exec { parent: session_id.to_owned() };
    let meta = (Control::Kube(role), ctrl.connection_id().to_owned(), dto::ts(OffsetDateTime::now_utc()), route);
    let parent = ctrl.clone();
    sessions::spawn_kube(&state.sessions, exec_id.clone(), meta, move |rx, phase| {
        run_exec(session, rx, ctx, phase, parent)
    })?;
    ctrl.exec_started(&exec_id);
    if ctrl.ended() {
        // The cluster ended while the shell opened: it goes with it.
        let _ = crate::commands::sessions::close(state, &exec_id).await;
    }
    Ok(Opened { session_id: exec_id })
}

/// `check_credential(kind)` at save time (`connection_create/update`,
/// `connection_options_set`): a conflict that the options *state* (`server`/`caPem` with a
/// `kubeconfig`, `context` with a `kube_token`) is refused; a `kube_token` connection whose
/// `server`/`caPem` are not set yet is accepted (the form sets options after creating the
/// connection) and refused at `kube_open`.
pub(crate) fn save_check(store: &mooring_store::Store, id: mooring_core::ConnectionId) -> IpcResult<()> {
    use mooring_core::credential::CredentialKind;
    let c = store.get_connection(id)?;
    if c.protocol != mooring_core::Protocol::Kubernetes {
        return Ok(());
    }
    let mooring_core::ProtocolOptions::Kube(o) = store.connection_options(id)? else { return Ok(()) };
    let Some(r) = store.resolve_credential(id, mooring_core::Role::Primary)? else { return Ok(()) };
    let kind = r.fields.kind();
    let incomplete = kind == CredentialKind::KubeToken && o.context.is_none() && (o.server.is_none() || o.ca_pem.is_none());
    match o.check_credential(kind) {
        Err(_) if incomplete => Ok(()),
        other => Ok(other?),
    }
}

// ------------------------------------------------------------------ Tauri wrappers

fn main_only<R: Runtime>(webview: &Webview<R>) -> IpcResult<()> {
    if webview.label() == crate::navigation::MAIN_WINDOW {
        Ok(())
    } else {
        Err(IpcError::new("ipc.forbidden", "this window cannot open sessions"))
    }
}

/// `kube_open({ connectionId, onEvent })`.
#[tauri::command]
pub fn kube_open<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, AppState>,
    connection_id: String,
    on_event: Channel<ClusterEvent>,
) -> IpcResult<Opened> {
    main_only(&webview)?;
    let sink: ClusterSink = Arc::new(move |e| on_event.send(e).is_ok());
    open(&state, &connection_id, sink)
}

/// `kube_access({ sessionId, namespace })`.
#[tauri::command]
pub async fn kube_access(state: State<'_, AppState>, session_id: String, namespace: String) -> IpcResult<AccessDto> {
    access(&state, &session_id, &namespace).await
}

/// `kube_contexts({ credentialId })`.
#[tauri::command]
pub fn kube_contexts(state: State<'_, AppState>, credential_id: String) -> IpcResult<Contexts> {
    contexts(&state, &credential_id)
}

/// `kube_namespaces({ sessionId })`.
#[tauri::command]
pub async fn kube_namespaces(state: State<'_, AppState>, session_id: String) -> IpcResult<Listing<String>> {
    namespaces(&state, &session_id).await
}

/// `kube_pods({ sessionId, namespace, labelSelector? })`.
#[tauri::command]
pub async fn kube_pods(
    state: State<'_, AppState>,
    session_id: String,
    namespace: String,
    label_selector: Option<String>,
) -> IpcResult<Listing<PodSummary>> {
    pods(&state, &session_id, &namespace, label_selector.as_deref()).await
}

/// `kube_pod({ sessionId, namespace, pod })`.
#[tauri::command]
pub async fn kube_pod(state: State<'_, AppState>, session_id: String, namespace: String, pod: String) -> IpcResult<PodSummary> {
    self::pod(&state, &session_id, &namespace, &pod).await
}

/// `kube_exec_open({ sessionId, namespace, pod, container?, command?, size, onEvent })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn kube_exec_open<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, AppState>,
    session_id: String,
    namespace: String,
    pod: String,
    container: Option<String>,
    command: Option<String>,
    size: Size,
    on_event: Channel<WireEvent>,
) -> IpcResult<Opened> {
    main_only(&webview)?;
    let sink: EventSink = Arc::new(move |e| on_event.send(e).is_ok());
    let req = ExecRequest { namespace, pod, container, command, size };
    exec_open(&state, &session_id, req, sink).await
}

#[cfg(test)]
#[path = "kube_tests.rs"]
mod tests;
