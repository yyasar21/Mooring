//! SFTP transfers (ADR-0010 §SFTP): `sftp_download`, `sftp_upload`, `sftp_cancel`.
//!
//! The local side comes from the OS file dialog (`localDir` for a download, `localPath` for
//! an upload). It is confined with `LocalPath`: the base is the directory the dialog returned
//! and the relative part is exactly one file name, so nothing outside that directory is
//! reachable (no `..`, no symlink escape, no ADS / device names). A base inside the app data
//! directory (vault header, audit log, `known_hosts`) is refused, so a compromised `WebView`
//! cannot overwrite or read Mooring's own files through a transfer.
//!
//! Each transfer runs in its own task, streams in 256 KiB blocks (≤ 8 requests in flight,
//! crate-enforced), reports `Progress` after every block and ends with exactly one final
//! `done` / `failed` / `cancelled` event and one `sftp_transfer` audit entry (direction,
//! bytes, outcome; never contents). A cancelled download leaves no partial local file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_proto_ssh::{LocalPath, SftpClient};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::oneshot;

use crate::commands::sftp::{client, sftp_error};
use crate::error::{IpcError, IpcResult};
use crate::sessions::Transfers;
use crate::state::{record_audit, AppState};

/// Most transfers running at once per session.
pub const MAX_TRANSFERS: usize = 8;
/// Longest local path accepted from the dialog, in bytes.
const MAX_LOCAL: usize = 4096;
/// Longest `transferId` accepted.
const MAX_TRANSFER_ID: usize = 64;

/// One progress report. The last one for a transfer has a state other than `running`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// Transfer id.
    pub transfer_id: String,
    /// Bytes moved so far.
    pub bytes_done: u64,
    /// Size when known (server-reported for downloads: a hint only).
    pub bytes_total: Option<u64>,
    /// `running` | `done` | `failed` | `cancelled`.
    pub state: &'static str,
    /// Safe reason for `failed`.
    pub error: Option<String>,
}

/// `{ transferId }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Started {
    /// Id for `sftp_cancel` and the progress events.
    pub transfer_id: String,
}

/// Where progress goes. Returns `false` when the UI side is gone.
pub type ProgressSink = Arc<dyn Fn(Progress) -> bool + Send + Sync>;

fn bad(field: &str, reason: &str) -> IpcError {
    IpcError::invalid(field, reason)
}

/// Validate a directory returned by the OS dialog: absolute, existing, a directory, and not
/// inside the app data directory. Returns it canonicalised. Errors never echo the path.
fn dialog_dir(state: &AppState, field: &str, raw: &Path) -> IpcResult<PathBuf> {
    if raw.as_os_str().is_empty() || raw.as_os_str().len() > MAX_LOCAL {
        return Err(bad(field, "empty or too long"));
    }
    if !raw.is_absolute() {
        return Err(bad(field, "must be an absolute path from the file dialog"));
    }
    let dir = std::fs::canonicalize(raw).map_err(|_| bad(field, "directory not found"))?;
    if !dir.is_dir() {
        return Err(bad(field, "not a directory"));
    }
    if let Ok(data) = std::fs::canonicalize(&state.data_dir) {
        if dir.starts_with(&data) {
            return Err(bad(field, "inside the application data directory"));
        }
    }
    Ok(dir)
}

/// Last segment of a remote path, as a local file name.
fn remote_name(remote: &str) -> IpcResult<&str> {
    let name = remote.trim_end_matches('/').rsplit('/').next().unwrap_or_default();
    if name.is_empty() || name == "." || name == ".." {
        return Err(bad("remote", "names no file"));
    }
    Ok(name)
}

/// `localPath` → (`LocalPath` confined to its parent, file name for the remote side).
fn upload_source(state: &AppState, raw: &str) -> IpcResult<(LocalPath, String)> {
    let path = Path::new(raw);
    let name = path.file_name().ok_or_else(|| bad("localPath", "names no file"))?;
    let name = name.to_str().ok_or_else(|| bad("localPath", "file name is not UTF-8"))?;
    let parent = path.parent().ok_or_else(|| bad("localPath", "names no file"))?;
    let base = dialog_dir(state, "localPath", parent)?;
    let local = LocalPath::new(base, name).map_err(IpcError::from)?;
    local.check_existing_file().map_err(IpcError::from)?;
    Ok((local, name.to_owned()))
}

fn join_remote(dir: &str, name: &str) -> IpcResult<String> {
    if dir.is_empty() {
        return Err(bad("remoteDir", "empty"));
    }
    Ok(if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") })
}

#[derive(Clone, Copy)]
enum Direction {
    Download,
    Upload,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }
}

/// Register the transfer and start its task.
fn start(
    state: &AppState,
    session_id: &str,
    connection: String,
    direction: Direction,
    job: impl FnOnce(SftpClient, Box<dyn FnMut(u64, Option<u64>) + Send>) -> TransferFuture,
    client: SftpClient,
    sink: ProgressSink,
) -> IpcResult<Started> {
    let transfers = transfers_of(state, session_id)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    {
        let mut map = transfers.lock().map_err(|_| IpcError::poisoned())?;
        if map.len() >= MAX_TRANSFERS {
            return Err(IpcError::new("transfer.limit", "too many transfers running"));
        }
        map.insert(transfer_id.clone(), cancel_tx);
    }
    let done = Arc::new(AtomicU64::new(0));
    let progress = {
        let (sink, id, done) = (Arc::clone(&sink), transfer_id.clone(), Arc::clone(&done));
        Box::new(move |bytes: u64, total: Option<u64>| {
            done.store(bytes, Ordering::Relaxed);
            let p = Progress {
                transfer_id: id.clone(),
                bytes_done: bytes,
                bytes_total: total,
                state: "running",
                error: None,
            };
            let _ = sink(p);
        }) as Box<dyn FnMut(u64, Option<u64>) + Send>
    };
    let work = job(client, progress);
    let audit = Arc::clone(&state.audit);
    let id = transfer_id.clone();
    tokio::spawn(async move {
        let outcome = tokio::select! {
            biased;
            _ = cancel_rx => Err(None),
            r = work => r.map_err(|e| Some(sftp_error(e).message)),
        };
        if let Ok(mut map) = transfers.lock() {
            map.remove(&id);
        }
        let (state, bytes, error) = match outcome {
            Ok(n) => ("done", n, None),
            Err(None) => ("cancelled", done.load(Ordering::Relaxed), None),
            Err(Some(reason)) => ("failed", done.load(Ordering::Relaxed), Some(reason)),
        };
        let total = matches!(state, "done").then_some(bytes);
        let p = Progress { transfer_id: id.clone(), bytes_done: bytes, bytes_total: total, state, error };
        let _ = sink(p);
        record_audit(
            &audit,
            AuditEvent::SftpTransfer {
                connection,
                transfer: id,
                direction: direction.as_str().to_owned(),
                bytes,
                outcome: state.to_owned(),
            },
        );
    });
    Ok(Started { transfer_id })
}

type TransferFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, mooring_core::MooringError>> + Send>>;

fn transfers_of(state: &AppState, session_id: &str) -> IpcResult<Transfers> {
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    map.get(session_id)
        .map(|h| Arc::clone(&h.transfers))
        .ok_or_else(|| IpcError::new("session.not_found", "session not found"))
}

/// `sftp_download({ sessionId, remote, localDir })`: `remote` is saved as
/// `localDir/<basename>`, replacing an existing regular file.
pub async fn download(
    state: &AppState,
    session_id: &str,
    remote: &str,
    local_dir: &str,
    sink: ProgressSink,
) -> IpcResult<Started> {
    let base = dialog_dir(state, "localDir", Path::new(local_dir))?;
    let local = LocalPath::new(base, remote_name(remote)?).map_err(IpcError::from)?;
    local.check_new_file().map_err(IpcError::from)?;
    let (client, connection) = client(state, session_id).await?;
    let remote = remote.to_owned();
    let job = move |c: SftpClient, p: Box<dyn FnMut(u64, Option<u64>) + Send>| -> TransferFuture {
        Box::pin(async move { c.download(&remote, &local, p).await })
    };
    start(state, session_id, connection, Direction::Download, job, client, sink)
}

/// `sftp_upload({ sessionId, localPath, remoteDir })`: the file is written to
/// `remoteDir/<file name>`, created or truncated.
pub async fn upload(
    state: &AppState,
    session_id: &str,
    local_path: &str,
    remote_dir: &str,
    sink: ProgressSink,
) -> IpcResult<Started> {
    if local_path.len() > MAX_LOCAL {
        return Err(bad("localPath", "too long"));
    }
    let (local, name) = upload_source(state, local_path)?;
    let remote = join_remote(remote_dir, &name)?;
    let (client, connection) = client(state, session_id).await?;
    let job = move |c: SftpClient, p: Box<dyn FnMut(u64, Option<u64>) + Send>| -> TransferFuture {
        Box::pin(async move { c.upload(&local, &remote, p).await })
    };
    start(state, session_id, connection, Direction::Upload, job, client, sink)
}

/// `sftp_cancel({ sessionId, transferId })`. The transfer reports `cancelled` itself.
pub fn cancel(state: &AppState, session_id: &str, transfer_id: &str) -> IpcResult<()> {
    if transfer_id.is_empty() || transfer_id.len() > MAX_TRANSFER_ID {
        return Err(bad("transferId", "not a transfer id"));
    }
    let transfers = transfers_of(state, session_id)?;
    let tx = transfers.lock().map_err(|_| IpcError::poisoned())?.remove(transfer_id);
    let tx = tx.ok_or_else(|| IpcError::new("transfer.not_found", "transfer not found"))?;
    let _ = tx.send(());
    Ok(())
}

// ------------------------------------------------------------------ Tauri wrappers

fn channel_sink(on_progress: Channel<Progress>) -> ProgressSink {
    Arc::new(move |p| on_progress.send(p).is_ok())
}

/// `sftp_download({ sessionId, remote, localDir, onProgress })`.
#[tauri::command]
pub async fn sftp_download(
    state: State<'_, AppState>,
    session_id: String,
    remote: String,
    local_dir: String,
    on_progress: Channel<Progress>,
) -> IpcResult<Started> {
    download(&state, &session_id, &remote, &local_dir, channel_sink(on_progress)).await
}

/// `sftp_upload({ sessionId, localPath, remoteDir, onProgress })`.
#[tauri::command]
pub async fn sftp_upload(
    state: State<'_, AppState>,
    session_id: String,
    local_path: String,
    remote_dir: String,
    on_progress: Channel<Progress>,
) -> IpcResult<Started> {
    upload(&state, &session_id, &local_path, &remote_dir, channel_sink(on_progress)).await
}

/// `sftp_cancel({ sessionId, transferId })`.
#[tauri::command]
pub fn sftp_cancel(
    state: State<'_, AppState>,
    session_id: String,
    transfer_id: String,
) -> IpcResult<()> {
    cancel(&state, &session_id, &transfer_id)
}

#[cfg(test)]
#[path = "sftp_transfers_tests.rs"]
mod tests;
