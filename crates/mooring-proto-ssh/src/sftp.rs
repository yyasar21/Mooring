//! SFTP (ADR-0007 §Channels and flow): one `russh-sftp` session per SSH session, opened on
//! first use and reused, closed with the session.
//!
//! The server is hostile: listings are capped at [`MAX_LIST_ENTRIES`] (with a `truncated`
//! flag), names that could address another path (`/`, NUL, `.`/`..`) are dropped, reply sizes
//! are bounded by the packet cap, and server-supplied error messages are never surfaced.
//! Remote paths are capped at [`MAX_REMOTE_PATH`] bytes. The local side of transfers goes
//! through [`LocalPath`](crate::LocalPath); see `sftp_transfer`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mooring_core::MooringError;
use russh::ChannelMsg;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::{Config, RawSftpSession};
use russh_sftp::extensions;
use russh_sftp::protocol::{FileAttributes, FileType, StatusCode};

use crate::control::SshControl;

/// Longest remote path accepted, in bytes.
pub const MAX_REMOTE_PATH: usize = 4096;
/// Most entries returned by one [`SftpClient::list`].
pub const MAX_LIST_ENTRIES: usize = 10_000;
/// Longest entry name kept in a listing, in bytes.
const MAX_NAME: usize = 1024;
/// Transfers move data in blocks of at most this size (several wire requests in flight).
pub const TRANSFER_BLOCK: usize = 256 * 1024;
/// Most SFTP read or write requests in flight at once. A block is
/// `min(TRANSFER_BLOCK, MAX_IN_FLIGHT * chunk)`, so a server advertising tiny
/// `limits@openssh.com` values cannot make one block fan out into thousands of requests
/// (security review 2, M-3).
pub const MAX_IN_FLIGHT: usize = 8;
/// Largest single SFTP read/write request (OpenSSH-compatible).
pub(crate) const WIRE_CHUNK: u32 = 32 * 1024;
/// Time allowed for the subsystem to start.
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Kind of a remote directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (listings use `lstat` semantics).
    Symlink,
    /// Anything else, or unknown.
    Other,
}

/// One remote file system entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// File name (no directory part).
    pub name: String,
    /// Kind.
    pub kind: EntryKind,
    /// Size in bytes, when the server reports it.
    pub size: Option<u64>,
    /// Modification time (Unix seconds), when reported.
    pub mtime: Option<u64>,
    /// Permission bits (`& 0o7777`), when reported.
    pub mode: Option<u32>,
}

impl Entry {
    fn from_attrs(name: String, attrs: &FileAttributes) -> Self {
        let kind = match attrs.permissions.map(|_| attrs.file_type()) {
            Some(FileType::File) => EntryKind::File,
            Some(FileType::Dir) => EntryKind::Dir,
            Some(FileType::Symlink) => EntryKind::Symlink,
            Some(FileType::Other) | None => EntryKind::Other,
        };
        Self {
            name,
            kind,
            size: attrs.size,
            mtime: attrs.mtime.map(u64::from),
            mode: attrs.permissions.map(|p| p & 0o7777),
        }
    }
}

/// A directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// Entries in server order, without `.` and `..`.
    pub entries: Vec<Entry>,
    /// The directory had more than [`MAX_LIST_ENTRIES`] entries.
    pub truncated: bool,
}

/// Handle to the session's SFTP subsystem. Cheap to clone.
#[derive(Clone)]
pub struct SftpClient {
    pub(crate) raw: Arc<RawSftpSession>,
    /// Bytes per wire read / write request.
    pub(crate) read_chunk: u32,
    pub(crate) write_chunk: u32,
}

impl std::fmt::Debug for SftpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpClient").finish_non_exhaustive()
    }
}

/// The lazily opened client of one session.
#[derive(Default)]
pub(crate) struct SftpSlot {
    client: Mutex<Option<SftpClient>>,
    closed: std::sync::atomic::AtomicBool,
    opening: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for SftpSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpSlot").field("open", &self.get().is_some()).finish_non_exhaustive()
    }
}

impl SftpSlot {
    fn get(&self) -> Option<SftpClient> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Close the SFTP channel; clients obtained earlier fail from now on. Idempotent.
    pub(crate) fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Release);
        let client = self.client.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(client) = client {
            let _ = client.raw.close_session();
        }
    }
}

pub(crate) fn sftp_err(e: &SftpError, path: &str) -> MooringError {
    let protocol =
        |reason: &str| MooringError::Protocol { protocol: "sftp", reason: reason.into() };
    match e {
        SftpError::Status(s) => match s.status_code {
            StatusCode::NoSuchFile => {
                MooringError::NotFound { kind: "remote path", id: path.to_owned() }
            }
            StatusCode::PermissionDenied => protocol("permission denied"),
            StatusCode::OpUnsupported => protocol("operation not supported by the server"),
            _ => protocol("operation failed"),
        },
        SftpError::Timeout => MooringError::Transport("sftp request timed out".into()),
        SftpError::Limited(_) => protocol("server limit exceeded"),
        SftpError::IO(_) | SftpError::UnexpectedPacket | SftpError::UnexpectedBehavior(_) => {
            MooringError::Transport("sftp channel failed".into())
        }
    }
}

pub(crate) fn check_remote(path: &str) -> Result<(), MooringError> {
    let invalid =
        |reason: &str| MooringError::Invalid { field: "remote path", reason: reason.into() };
    if path.is_empty() {
        return Err(invalid("empty"));
    }
    if path.len() > MAX_REMOTE_PATH {
        return Err(invalid("longer than 4096 bytes"));
    }
    if path.contains('\0') {
        return Err(invalid("contains NUL"));
    }
    Ok(())
}

fn acceptable_name(name: &str) -> bool {
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_NAME
        || name.contains('/')
        || name.contains('\0'))
}

fn base_name(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((_, name)) => name.to_owned(),
        None if trimmed.is_empty() => "/".to_owned(),
        None => trimmed.to_owned(),
    }
}

async fn open_client(
    handle: &russh::client::Handle<crate::ClientHandler>,
) -> Result<SftpClient, MooringError> {
    let lost = |_| MooringError::Transport("sftp channel failed".into());
    let mut channel = handle.channel_open_session().await.map_err(lost)?;
    channel.request_subsystem(true, "sftp").await.map_err(lost)?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure | ChannelMsg::Close | ChannelMsg::Eof) | None => {
                return Err(MooringError::Protocol {
                    protocol: "sftp",
                    reason: "sftp subsystem refused".into(),
                });
            }
            Some(_) => {}
        }
    }
    let mut raw = RawSftpSession::new_with_config(channel.into_stream(), Config::default());
    let version = raw.init().await.map_err(|e| sftp_err(&e, ""))?;
    let (mut read_chunk, mut write_chunk) = (WIRE_CHUNK, WIRE_CHUNK);
    if version.extensions.get(extensions::LIMITS).is_some_and(|v| v == "1") {
        if let Ok(limits) = raw.limits().await {
            let clamp = |chunk: u32, limit: u64| {
                if limit == 0 {
                    chunk
                } else {
                    u32::try_from(limit).unwrap_or(u32::MAX).clamp(1, chunk)
                }
            };
            read_chunk = clamp(read_chunk, limits.max_read_len);
            write_chunk = clamp(write_chunk, limits.max_write_len);
            raw.set_limits(limits.into());
        }
    }
    Ok(SftpClient { raw: Arc::new(raw), read_chunk, write_chunk })
}

impl SshControl {
    /// The session's SFTP client, opening the subsystem on first use.
    pub async fn sftp(&self) -> Result<SftpClient, MooringError> {
        let slot = &self.shared.sftp;
        if let Some(client) = slot.get() {
            return Ok(client);
        }
        let _guard = slot.opening.lock().await;
        if let Some(client) = slot.get() {
            return Ok(client);
        }
        let handle = self.live_handle()?;
        let client = tokio::time::timeout(OPEN_TIMEOUT, open_client(&handle))
            .await
            .map_err(|_| MooringError::Transport("sftp start timed out".into()))??;
        let mut stored = slot.client.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_closed() {
            let _ = client.raw.close_session();
            return Err(MooringError::Closed);
        }
        *stored = Some(client.clone());
        Ok(client)
    }
}

impl SftpClient {
    /// List a directory (up to [`MAX_LIST_ENTRIES`] entries).
    pub async fn list(&self, path: &str) -> Result<Listing, MooringError> {
        check_remote(path)?;
        let handle = self.raw.opendir(path).await.map_err(|e| sftp_err(&e, path))?.handle;
        let mut entries = Vec::new();
        let mut truncated = false;
        let mut rounds = 0usize;
        let result = loop {
            rounds += 1;
            if rounds > MAX_LIST_ENTRIES + 1 {
                truncated = true;
                break Ok(());
            }
            match self.raw.readdir(handle.as_str()).await {
                Ok(name) => {
                    for file in name.files {
                        if !acceptable_name(&file.filename) {
                            continue;
                        }
                        if entries.len() == MAX_LIST_ENTRIES {
                            truncated = true;
                            break;
                        }
                        entries.push(Entry::from_attrs(file.filename, &file.attrs));
                    }
                    if truncated {
                        break Ok(());
                    }
                }
                Err(SftpError::Status(s)) if s.status_code == StatusCode::Eof => break Ok(()),
                Err(e) => break Err(sftp_err(&e, path)),
            }
        };
        let _ = self.raw.close(handle).await;
        result.map(|()| Listing { entries, truncated })
    }

    /// Metadata of `path` (follows symlinks).
    pub async fn stat(&self, path: &str) -> Result<Entry, MooringError> {
        check_remote(path)?;
        let attrs = self.raw.stat(path).await.map_err(|e| sftp_err(&e, path))?.attrs;
        Ok(Entry::from_attrs(base_name(path), &attrs))
    }

    /// Create a directory.
    pub async fn mkdir(&self, path: &str) -> Result<(), MooringError> {
        check_remote(path)?;
        self.raw.mkdir(path, FileAttributes::empty()).await.map_err(|e| sftp_err(&e, path))?;
        Ok(())
    }

    /// Rename `from` to `to`.
    pub async fn rename(&self, from: &str, to: &str) -> Result<(), MooringError> {
        check_remote(from)?;
        check_remote(to)?;
        self.raw.rename(from, to).await.map_err(|e| sftp_err(&e, from))?;
        Ok(())
    }

    /// Remove a file, symlink or empty directory (never recursive).
    pub async fn remove(&self, path: &str) -> Result<(), MooringError> {
        check_remote(path)?;
        let attrs = self.raw.lstat(path).await.map_err(|e| sftp_err(&e, path))?.attrs;
        let result = if attrs.permissions.is_some() && attrs.file_type() == FileType::Dir {
            self.raw.rmdir(path).await
        } else {
            self.raw.remove(path).await
        };
        result.map_err(|e| sftp_err(&e, path))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_checks() {
        assert!(check_remote("/tmp/x").is_ok());
        assert!(check_remote("").is_err());
        assert!(check_remote("a\0b").is_err());
        assert!(check_remote(&"a".repeat(MAX_REMOTE_PATH)).is_ok());
        assert!(check_remote(&"a".repeat(MAX_REMOTE_PATH + 1)).is_err());
    }

    #[test]
    fn names_and_basenames() {
        assert!(acceptable_name("file.txt"));
        for bad in ["", ".", "..", "a/b", "a\0", &"x".repeat(MAX_NAME + 1)] {
            assert!(!acceptable_name(bad), "{bad:?}");
        }
        assert_eq!(base_name("/a/b/"), "b");
        assert_eq!(base_name("/"), "/");
        assert_eq!(base_name("rel"), "rel");
    }

    #[test]
    fn entry_kinds_and_mode() {
        let mut attrs = FileAttributes::empty();
        assert_eq!(Entry::from_attrs("x".into(), &attrs).kind, EntryKind::Other);
        attrs.permissions = Some(0o040_755);
        attrs.mtime = Some(7);
        let e = Entry::from_attrs("d".into(), &attrs);
        assert_eq!((e.kind, e.mode, e.mtime), (EntryKind::Dir, Some(0o755), Some(7)));
        attrs.permissions = Some(0o100_644);
        assert_eq!(Entry::from_attrs("f".into(), &attrs).kind, EntryKind::File);
    }

    #[test]
    fn server_messages_are_not_surfaced() {
        let status = russh_sftp::protocol::Status {
            id: 1,
            status_code: StatusCode::Failure,
            error_message: "\x1b[31mevil".into(),
            language_tag: "en".into(),
        };
        let err = sftp_err(&SftpError::Status(status), "/p").to_string();
        assert!(!err.contains("evil"), "{err}");
    }
}
