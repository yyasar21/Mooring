//! Where import bytes come from (ADR-0019 §3): the Rust-side file dialog (`import_pick`,
//! review 4 B-4: no local path crosses IPC), the known locations `~/.ssh/config` and
//! `~/.putty/sessions/`, and the opt-in read of an OpenSSH `IdentityFile`. Every read is
//! capped before the bytes are loaded.

use std::path::{Path, PathBuf};
use std::time::Instant;

use mooring_core::credential::fingerprint::ssh_private_key;
use mooring_import::{ImportFormat, Limits};
use serde::Serialize;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::autolock::AutoLock;
use crate::commands::sftp_pick::LocalPicker;
use crate::commands::sftp_transfers::dialog_dir;
use crate::error::{IpcError, IpcResult};
use crate::picks::PickMode;
use crate::state::AppState;

/// The pick "session" import picks are bound to (no SSH session is involved).
pub const IMPORT_PICK_SESSION: &str = "import";
/// Largest `IdentityFile` read for the key opt-in (ADR-0019 §3).
pub const MAX_KEY_FILE: u64 = 16 * 1024;
/// Most files read from `~/.putty/sessions/`.
pub const MAX_SESSION_FILES: usize = 2000;

/// `{ pickId, fileName, size }` of a picked import file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedFile {
    /// 128-bit hex id, single-use, valid for 10 minutes.
    pub pick_id: String,
    /// File name only (never the path).
    pub file_name: String,
    /// Size in bytes.
    pub size: u64,
}

fn bad(reason: &str) -> IpcError {
    IpcError::invalid("pick", reason)
}

/// A file the user chose: canonical, regular, outside the app data dir, within the input cap.
fn check_file(state: &AppState, raw: &Path, max: usize) -> IpcResult<(PathBuf, String, u64)> {
    let name = raw.file_name().ok_or_else(|| bad("names no file"))?;
    let name = name.to_str().ok_or_else(|| bad("file name is not UTF-8"))?.to_owned();
    let parent = raw.parent().ok_or_else(|| bad("names no file"))?;
    let base = dialog_dir(state, "pick", parent)?;
    let path = base.join(&name);
    let meta = std::fs::metadata(&path).map_err(|_| bad("file not found"))?;
    if !meta.is_file() {
        return Err(bad("not a regular file"));
    }
    if meta.len() > max as u64 {
        return Err(IpcError::new("import.too_large", format!("the file is larger than {max} bytes")));
    }
    Ok((path, name, meta.len()))
}

/// `import_pick`: ask the user for a file, validate it, store the path under a `pickId`.
pub async fn pick(
    state: &AppState,
    picker: &dyn LocalPicker,
    autolock: Option<&AutoLock>,
    format: ImportFormat,
) -> IpcResult<Option<PickedFile>> {
    state.with_ready(|_, _| Ok(()))?;
    let epoch = state.picks.epoch();
    let chosen = {
        let _open = autolock.map(AutoLock::dialog_guard);
        let (tx, rx) = oneshot::channel();
        picker.pick_filtered(PickMode::File, format.label(), format.extensions(), Box::new(move |p| drop(tx.send(p))));
        rx.await.ok().flatten()
    };
    let Some(raw) = chosen else {
        return Ok(None);
    };
    let (path, file_name, size) = check_file(state, &raw, Limits::DEFAULT.max_input)?;
    Ok(state
        .picks
        .insert(epoch, IMPORT_PICK_SESSION, PickMode::File, path, Instant::now())
        .map(|pick_id| PickedFile { pick_id, file_name, size }))
}

/// Read a picked file (cap re-checked on the live metadata).
pub fn read_picked(state: &AppState, pick_id: &str, max: usize) -> IpcResult<(String, Vec<u8>)> {
    let path = state.picks.take(pick_id, IMPORT_PICK_SESSION, PickMode::File, Instant::now())?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    read_capped(&path, max as u64).map(|bytes| (name, bytes))
}

fn read_capped(path: &Path, max: u64) -> IpcResult<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|_| IpcError::new("import.not_found", "file not found"))?;
    if !meta.is_file() {
        return Err(IpcError::new("import.not_found", "not a regular file"));
    }
    if meta.len() > max {
        return Err(IpcError::new("import.too_large", format!("the file is larger than {max} bytes")));
    }
    std::fs::read(path).map_err(|e| {
        tracing::warn!(kind = ?e.kind(), "import source unreadable");
        IpcError::new("import.not_found", "the file could not be read")
    })
}

/// The user's home directory.
pub fn home_dir() -> IpcResult<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).ok_or_else(|| {
        IpcError::new("import.not_found", "no home directory")
    })
}

/// Bytes of a known location: `(format, file name, content)` for OpenSSH, or the session
/// files for `PuTTY`.
#[derive(Debug)]
pub enum Known {
    /// `~/.ssh/config`.
    File(ImportFormat, String, Vec<u8>),
    /// `~/.putty/sessions/*`.
    Dir(ImportFormat, Vec<(String, Vec<u8>)>),
}

/// Read `known` (`"openssh"` | `"putty"`) under `home`.
pub fn read_known(home: &Path, known: &str, limits: &Limits) -> IpcResult<Known> {
    match known {
        "openssh" => {
            let bytes = read_capped(&home.join(".ssh").join("config"), limits.max_input as u64)?;
            Ok(Known::File(ImportFormat::Openssh, "config".into(), bytes))
        }
        "putty" => {
            let dir = home.join(".putty").join("sessions");
            let entries = std::fs::read_dir(&dir)
                .map_err(|_| IpcError::new("import.not_found", "no ~/.putty/sessions directory"))?;
            let mut files = Vec::new();
            let mut total = 0u64;
            for entry in entries.take(MAX_SESSION_FILES) {
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                let Ok(meta) = std::fs::metadata(&path) else { continue };
                if !meta.is_file() || meta.len() > limits.max_input as u64 {
                    continue;
                }
                total = total.saturating_add(meta.len());
                if total > limits.max_input as u64 {
                    return Err(IpcError::new("import.too_large", "the sessions directory is too large"));
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                files.push((name, read_capped(&path, limits.max_input as u64)?));
            }
            files.sort();
            Ok(Known::Dir(ImportFormat::Putty, files))
        }
        _ => Err(IpcError::invalid("known", "expected openssh or putty")),
    }
}

/// Why an `IdentityFile` was not imported (the plan records `key_unreadable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUnreadable;

/// ADR-0019 §3 opt-in: the key named by an OpenSSH `IdentityFile`, only when its canonical
/// path is a regular file under `~/.ssh/`, at most [`MAX_KEY_FILE`] bytes, and parses as an
/// OpenSSH private key (the public half is readable without the passphrase).
pub fn read_identity(home: &Path, key_file: &str) -> Result<Zeroizing<Vec<u8>>, KeyUnreadable> {
    let expanded = match key_file.strip_prefix("~/").or_else(|| key_file.strip_prefix("~\\")) {
        Some(rest) => home.join(rest),
        None if key_file == "~" => home.to_path_buf(),
        None => PathBuf::from(key_file),
    };
    let ssh_dir = std::fs::canonicalize(home.join(".ssh")).map_err(|_| KeyUnreadable)?;
    let path = std::fs::canonicalize(&expanded).map_err(|_| KeyUnreadable)?;
    if !path.starts_with(&ssh_dir) {
        return Err(KeyUnreadable);
    }
    let meta = std::fs::metadata(&path).map_err(|_| KeyUnreadable)?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE {
        return Err(KeyUnreadable);
    }
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(|_| KeyUnreadable)?);
    match ssh_private_key(&bytes) {
        Ok(info) if info.fingerprint.is_some() => Ok(bytes),
        _ => Err(KeyUnreadable),
    }
}
