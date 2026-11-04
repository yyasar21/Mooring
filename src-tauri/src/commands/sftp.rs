//! SFTP browsing commands (ADR-0010 §SFTP): list / stat / mkdir / rename / remove on the
//! session's SFTP subsystem (opened on first use, closed with the session). Remote paths are
//! checked by the crate (non-empty, ≤ 4096 bytes, no NUL); server error text is never surfaced.
//! Transfers live in `sftp_transfers`.

use mooring_core::MooringError;
use mooring_proto_ssh::{Entry, EntryKind, Listing, SftpClient};
use serde::Serialize;
use tauri::State;

use crate::commands::forward::{control_of, session_error};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// One remote entry on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDto {
    /// File name, no directory part.
    pub name: String,
    /// `file` | `dir` | `symlink` | `other`.
    pub kind: &'static str,
    /// Bytes, when reported.
    pub size: Option<u64>,
    /// Unix seconds, when reported.
    pub mtime: Option<u64>,
    /// Permission bits (`& 0o7777`), when reported.
    pub mode: Option<u32>,
}

impl From<Entry> for EntryDto {
    fn from(e: Entry) -> Self {
        let kind = match e.kind {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
            EntryKind::Symlink => "symlink",
            EntryKind::Other => "other",
        };
        Self { name: e.name, kind, size: e.size, mtime: e.mtime, mode: e.mode }
    }
}

/// `{ entries, truncated }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListingDto {
    /// Entries in server order (no `.` / `..`).
    pub entries: Vec<EntryDto>,
    /// More than 10 000 entries; the rest were dropped.
    pub truncated: bool,
}

impl From<Listing> for ListingDto {
    fn from(l: Listing) -> Self {
        Self { entries: l.entries.into_iter().map(EntryDto::from).collect(), truncated: l.truncated }
    }
}

/// Map crate errors to the SFTP codes. Messages are the crate's fixed, path-free sentences.
pub(crate) fn sftp_error(e: MooringError) -> IpcError {
    match e {
        MooringError::NotFound { .. } => IpcError::new("sftp.not_found", "remote path not found"),
        MooringError::Protocol { protocol: "sftp", reason } if reason == "permission denied" => {
            IpcError::new("sftp.denied", reason)
        }
        MooringError::Protocol { protocol: "sftp", reason } | MooringError::Transport(reason) => {
            IpcError::new("sftp.failed", reason)
        }
        other => session_error(other),
    }
}

/// The session's SFTP client, opening the subsystem on first use.
pub(crate) async fn client(state: &AppState, session_id: &str) -> IpcResult<(SftpClient, String)> {
    let (control, connection) = control_of(state, session_id)?;
    let client = control.sftp().await.map_err(sftp_error)?;
    Ok((client, connection))
}

/// `sftp_list({ sessionId, path })`.
pub async fn list(state: &AppState, session_id: &str, path: &str) -> IpcResult<ListingDto> {
    let (c, _) = client(state, session_id).await?;
    c.list(path).await.map(ListingDto::from).map_err(sftp_error)
}

/// `sftp_stat({ sessionId, path })`.
pub async fn stat(state: &AppState, session_id: &str, path: &str) -> IpcResult<EntryDto> {
    let (c, _) = client(state, session_id).await?;
    c.stat(path).await.map(EntryDto::from).map_err(sftp_error)
}

/// `sftp_mkdir({ sessionId, path })`.
pub async fn mkdir(state: &AppState, session_id: &str, path: &str) -> IpcResult<()> {
    let (c, _) = client(state, session_id).await?;
    c.mkdir(path).await.map_err(sftp_error)
}

/// `sftp_rename({ sessionId, from, to })`.
pub async fn rename(state: &AppState, session_id: &str, from: &str, to: &str) -> IpcResult<()> {
    let (c, _) = client(state, session_id).await?;
    c.rename(from, to).await.map_err(sftp_error)
}

/// `sftp_remove({ sessionId, path })`: a file, symlink or empty directory, never recursive.
pub async fn remove(state: &AppState, session_id: &str, path: &str) -> IpcResult<()> {
    let (c, _) = client(state, session_id).await?;
    c.remove(path).await.map_err(sftp_error)
}

// ------------------------------------------------------------------ Tauri wrappers

/// `sftp_list({ sessionId, path })`.
#[tauri::command]
pub async fn sftp_list(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> IpcResult<ListingDto> {
    list(&state, &session_id, &path).await
}

/// `sftp_stat({ sessionId, path })`.
#[tauri::command]
pub async fn sftp_stat(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> IpcResult<EntryDto> {
    stat(&state, &session_id, &path).await
}

/// `sftp_mkdir({ sessionId, path })`.
#[tauri::command]
pub async fn sftp_mkdir(state: State<'_, AppState>, session_id: String, path: String) -> IpcResult<()> {
    mkdir(&state, &session_id, &path).await
}

/// `sftp_rename({ sessionId, from, to })`.
#[tauri::command]
pub async fn sftp_rename(
    state: State<'_, AppState>,
    session_id: String,
    from: String,
    to: String,
) -> IpcResult<()> {
    rename(&state, &session_id, &from, &to).await
}

/// `sftp_remove({ sessionId, path })`.
#[tauri::command]
pub async fn sftp_remove(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> IpcResult<()> {
    remove(&state, &session_id, &path).await
}

#[cfg(test)]
#[path = "sftp_tests.rs"]
mod tests;
