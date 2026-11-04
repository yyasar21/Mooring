//! Pod log streams (ADR-0014 §5, K4): `kube_logs_open` starts a pump task that sends
//! sanitised, base64 [`LogChunkDto`]s to `onChunk` until the stream ends, the byte cap
//! (`maxLogBytes`) stops it (`end { truncated: true, reason: "kube.stream_limit" }`), the UI
//! calls `kube_logs_close`, or the cluster session ends. At most 8 per cluster
//! (`kube.stream_limit`). Audited `kube_logs_opened` / `kube_logs_closed`.

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_proto_kube::{LogChunk, LogParams};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::State;

use crate::commands::kube::{client_of, cluster_of, container, namespace, pod_name};
use crate::commands::kube_wire::{kube_error, logs_closed, LogChunkDto};
use crate::error::{IpcError, IpcResult};
use crate::kube_sessions::LogEntry;
use crate::state::AppState;

/// Where log chunks go; `false` when the UI side is gone.
pub type ChunkSink = Arc<dyn Fn(LogChunkDto) -> bool + Send + Sync>;

/// `tailLines` cap per request (ADR-0014 §5).
const MAX_TAIL: u32 = 10_000;
/// `sinceSeconds` cap (one year).
const MAX_SINCE: u64 = 366 * 24 * 3600;

/// Arguments of `kube_logs_open` besides `sessionId` and `onChunk`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogsRequest {
    /// Namespace.
    pub namespace: String,
    /// Pod.
    pub pod: String,
    /// Container, `null` = the pod's default.
    #[serde(default)]
    pub container: Option<String>,
    /// Keep streaming.
    #[serde(default)]
    pub follow: bool,
    /// `null` = the connection's `logTailLines` (clamped to 10 000).
    #[serde(default)]
    pub tail_lines: Option<u32>,
    /// 1 ..= one year.
    #[serde(default)]
    pub since_seconds: Option<u64>,
    /// RFC 3339 prefixes.
    #[serde(default)]
    pub timestamps: bool,
}

/// `{ streamId }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamOpened {
    /// `log-<n>`.
    pub stream_id: String,
}

fn params(req: &LogsRequest) -> IpcResult<LogParams> {
    if req.tail_lines.is_some_and(|t| t == 0 || t > MAX_TAIL) {
        return Err(IpcError::invalid("tailLines", "must be 1..=10000"));
    }
    if req.since_seconds.is_some_and(|s| s == 0 || s > MAX_SINCE) {
        return Err(IpcError::invalid("sinceSeconds", "must be 1 second to one year"));
    }
    Ok(LogParams {
        container: container(req.container.as_deref())?,
        follow: req.follow,
        tail_lines: req.tail_lines,
        since_seconds: req.since_seconds,
        timestamps: req.timestamps,
    })
}

/// `kube_logs_open`.
pub async fn open(state: &AppState, session_id: &str, req: LogsRequest, sink: ChunkSink) -> IpcResult<StreamOpened> {
    let (ns, pod) = (namespace(&req.namespace)?.to_owned(), pod_name(&req.pod)?.to_owned());
    let p = params(&req)?;
    let (ctrl, client) = client_of(state, session_id)?;
    let result = client.logs(&ns, &pod, p.clone()).await;
    ctrl.drain_audit();
    let mut stream = result.map_err(|e| kube_error(&e))?;
    let id = format!("log-{}", ctrl.next_id());
    let target = (ns, pod, p.container);
    ctrl.audit(AuditEvent::KubeLogsOpened {
        connection: ctrl.connection_id().to_owned(),
        stream: id.clone(),
        namespace: target.0.clone(),
        pod: target.1.clone(),
        container: target.2.clone(),
        follow: p.follow,
    });
    let mut logs = ctrl.logs();
    if ctrl.ended() {
        return Err(IpcError::new("session.not_found", "session is closed"));
    }
    let (pump_ctrl, pump_id) = (ctrl.clone(), id.clone());
    let task = tokio::spawn(async move {
        let (truncated, reason) = loop {
            match stream.next().await {
                Ok(Some(LogChunk::End { truncated, reason })) => {
                    let _ = sink(LogChunkDto::End { truncated, reason: reason.map(str::to_owned) });
                    break (truncated, if truncated { "kube.stream_limit" } else { "end" });
                }
                Ok(Some(chunk)) => {
                    if !sink(chunk.into()) {
                        break (false, "ui_gone");
                    }
                }
                Ok(None) => {
                    let _ = sink(LogChunkDto::End { truncated: false, reason: None });
                    break (false, "end");
                }
                Err(e) => {
                    let code = kube_error(&e).code;
                    let _ = sink(LogChunkDto::End { truncated: false, reason: Some(code.to_owned()) });
                    break (false, code);
                }
            }
        };
        drop(stream);
        let entry = pump_ctrl.logs().remove(&pump_id);
        if let Some(entry) = entry {
            pump_ctrl.audit(logs_closed(pump_ctrl.connection_id(), &pump_id, entry.target, truncated, reason));
        }
    });
    logs.insert(id.clone(), LogEntry { abort: task.abort_handle(), target });
    drop(logs);
    Ok(StreamOpened { stream_id: id })
}

/// `kube_logs_close({ sessionId, streamId })`: stops the stream (no further chunk).
pub fn close(state: &AppState, session_id: &str, stream_id: &str) -> IpcResult<()> {
    if stream_id.len() > 32 {
        return Err(IpcError::invalid("streamId", "expected log-<number>"));
    }
    let ctrl = cluster_of(state, session_id)?;
    let entry = ctrl.logs().remove(stream_id);
    let entry = entry.ok_or_else(|| IpcError::new("kube.not_found", "log stream not found"))?;
    entry.abort.abort();
    ctrl.audit(logs_closed(ctrl.connection_id(), stream_id, entry.target, false, "user"));
    Ok(())
}

// ------------------------------------------------------------------ Tauri wrappers

/// `kube_logs_open({ sessionId, namespace, pod, container?, follow, tailLines?, sinceSeconds?,
/// timestamps, onChunk })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn kube_logs_open(
    state: State<'_, AppState>,
    session_id: String,
    namespace: String,
    pod: String,
    container: Option<String>,
    follow: Option<bool>,
    tail_lines: Option<u32>,
    since_seconds: Option<u64>,
    timestamps: Option<bool>,
    on_chunk: Channel<LogChunkDto>,
) -> IpcResult<StreamOpened> {
    let sink: ChunkSink = Arc::new(move |c| on_chunk.send(c).is_ok());
    let req = LogsRequest {
        namespace,
        pod,
        container,
        follow: follow.unwrap_or(false),
        tail_lines,
        since_seconds,
        timestamps: timestamps.unwrap_or(false),
    };
    open(&state, &session_id, req, sink).await
}

/// `kube_logs_close({ sessionId, streamId })`.
#[tauri::command]
pub fn kube_logs_close(state: State<'_, AppState>, session_id: String, stream_id: String) -> IpcResult<()> {
    close(&state, &session_id, &stream_id)
}
