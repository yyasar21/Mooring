//! `vault_export_pick` / `vault_export_age` (ADR-0023 §2): a passphrase-protected `age`
//! backup of the whole vault (document v2, `mooring_sync::export`).
//!
//! The save dialog opens from Rust (review 4 B-4): the `WebView` gets a `pickId` and the file
//! name, never a path. The export needs the vault unlocked, the **master password** (proved
//! against a scratch copy of the header, so the live vault is untouched) and an export
//! passphrase of at least 12 characters that differs from the master password. The file is
//! written through a `.part` file (mode 0600, fsync) and renamed into place. Audited
//! `vault.exported` with counts only. The shared error mapping of the import side lives here
//! too ([`import_error`]).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use mooring_audit::AuditEvent;
use mooring_sync::export::{self as backup, ExportDocument, ExportError, DOCUMENT_VERSION};
use mooring_vault::{Vault, MIN_EXPORT_PASSPHRASE_CHARS};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::oneshot;

use crate::autolock::AutoLock;
use crate::commands::sftp_pick::{DialogPicker, LocalPicker, Picked};
use crate::commands::sftp_transfers::dialog_dir;
use crate::commands::vault::password_from_ipc;
use crate::error::{IpcError, IpcResult};
use crate::picks::PickMode;
use crate::state::AppState;

/// `Picks` namespace of export targets (never a session id: those are UUIDs).
pub const EXPORT_PICK_SESSION: &str = "vault-export";
/// File extension of a backup.
pub const EXTENSION: &str = "age";
/// Device name written into the snapshot of a backup.
pub const DEVICE_NAME: &str = "backup";

/// `vault_export_age({ pickId, password, exportPassphrase })` input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportInput {
    /// From `vault_export_pick`.
    pub pick_id: String,
    /// Master password (ADR-0006: export requires it).
    pub password: String,
    /// Passphrase of the `age` file.
    pub export_passphrase: String,
}

/// What was written (counts only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSummary {
    /// File size.
    pub bytes: u64,
    /// Credentials in the file.
    pub credentials: u64,
    /// Connections in the file.
    pub connections: u64,
    /// Folders in the file.
    pub folders: u64,
}

fn bad(reason: &str) -> IpcError {
    IpcError::invalid("pick", reason)
}

/// Map a document error of the **import** side to its IPC code (ADR-0023 §2). `foreign`
/// selects the code of a secret that does not open (wrong source password vs. damaged file).
pub fn import_error(e: &ExportError, foreign: bool) -> IpcError {
    match e {
        ExportError::WeakPassphrase { min } => IpcError::new(
            "vault.import_passphrase",
            format!("the backup passphrase has at least {min} characters"),
        ),
        ExportError::Passphrase => {
            IpcError::new("vault.import_passphrase", "wrong passphrase or damaged backup file")
        }
        ExportError::TooLarge => IpcError::new("vault.import_too_large", e.to_string()),
        ExportError::Version(_) => IpcError::new("vault.import_version", e.to_string()),
        ExportError::Sealed if foreign => IpcError::new(
            "vault.import_source_password",
            "the source vault's master password does not open the backup",
        ),
        ExportError::Format(_) | ExportError::Sealed => {
            IpcError::new("vault.import_format", e.to_string())
        }
    }
}

fn export_error(e: &ExportError) -> IpcError {
    match e {
        ExportError::WeakPassphrase { min } => IpcError::new(
            "vault.export_passphrase",
            format!("the export passphrase needs at least {min} characters"),
        ),
        _ => IpcError::new("vault.export", e.to_string()),
    }
}

/// Prove `password` against a scratch copy of the vault header (the live vault and its lock
/// state are untouched; Argon2id runs without the vault mutex held).
pub fn prove_password(state: &AppState, password: &SecretString) -> IpcResult<()> {
    let header = {
        let guard = state.vault()?;
        guard.as_ref().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?.header().clone()
    };
    Vault::from_header(header).unlock(password).map_err(IpcError::from)
}

/// The export passphrase rules (ADR-0023 §2): long enough, never the master password.
pub fn check_export_passphrase(passphrase: &SecretString, master: &SecretString) -> IpcResult<()> {
    let p = passphrase.expose_secret();
    if p.chars().count() < MIN_EXPORT_PASSPHRASE_CHARS {
        return Err(export_error(&ExportError::WeakPassphrase { min: MIN_EXPORT_PASSPHRASE_CHARS }));
    }
    if p == master.expose_secret() {
        return Err(IpcError::new(
            "vault.export_passphrase",
            "the export passphrase must differ from the master password",
        ));
    }
    Ok(())
}

/// Validate a save target from the dialog: an existing directory outside the app data dir, a
/// UTF-8 file name (`.age` appended when missing), not an existing non-file.
fn check_target(state: &AppState, raw: &Path) -> IpcResult<(PathBuf, String)> {
    let name = raw.file_name().ok_or_else(|| bad("names no file"))?;
    let mut name = name.to_str().ok_or_else(|| bad("file name is not UTF-8"))?.to_owned();
    if name.starts_with('.') || name.chars().any(char::is_control) {
        return Err(bad("unsupported file name"));
    }
    if !Path::new(&name).extension().is_some_and(|e| e.eq_ignore_ascii_case(EXTENSION)) {
        name.push_str(".age");
    }
    let parent = raw.parent().ok_or_else(|| bad("names no file"))?;
    let path = dialog_dir(state, "pick", parent)?.join(&name);
    if path.symlink_metadata().is_ok_and(|m| !m.is_file()) {
        return Err(bad("not a regular file"));
    }
    Ok((path, name))
}

fn suggested_name() -> String {
    let date = time::OffsetDateTime::now_utc().date();
    format!("mooring-backup-{date}.{EXTENSION}")
}

/// `vault_export_pick`: the save dialog; `None` when cancelled or locked meanwhile.
pub async fn pick(
    state: &AppState,
    picker: &dyn LocalPicker,
    autolock: Option<&AutoLock>,
) -> IpcResult<Option<Picked>> {
    state.with_ready(|_, _| Ok(()))?;
    let epoch = state.picks.epoch();
    let chosen = {
        let _open = autolock.map(AutoLock::dialog_guard);
        let (tx, rx) = oneshot::channel();
        let reply = Box::new(move |p| drop(tx.send(p)));
        picker.pick_save(&suggested_name(), "Mooring backup", &[EXTENSION], reply);
        rx.await.ok().flatten()
    };
    let Some(raw) = chosen else { return Ok(None) };
    let (path, name) = check_target(state, &raw)?;
    Ok(state
        .picks
        .insert(epoch, EXPORT_PICK_SESSION, PickMode::File, path, Instant::now())
        .map(|pick_id| Picked { pick_id, name }))
}

/// Write `bytes` to `path` through `<path>.part` (0600, fsync, rename).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let result = (|| {
        let mut f = crate::state::create_private(&part)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&part, path)
    })();
    if result.is_err() {
        drop(std::fs::remove_file(&part));
    } else if let Some(dir) = path.parent() {
        crate::state::sync_dir(dir);
    }
    result
}

/// Build the document of the unlocked vault (header without the per-device wrap).
pub fn document(state: &AppState) -> IpcResult<ExportDocument> {
    state.with_ready(|v, s| {
        let snapshot =
            mooring_sync::snapshot::from_store(s, &state.data_dir, v.vault_id(), DEVICE_NAME)
                .map_err(|e| export_error(&e.into()))?;
        Ok(ExportDocument {
            version: DOCUMENT_VERSION,
            header: backup::exportable_header(v),
            snapshot,
            exported_at: crate::dto::ts(time::OffsetDateTime::now_utc()),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
        })
    })
}

/// Encrypt with the production work factor, or the fast one in tests (`Settings`).
pub fn seal_document(
    state: &AppState,
    d: &ExportDocument,
    passphrase: &SecretString,
) -> Result<Vec<u8>, ExportError> {
    if state.settings.fast_exports {
        backup::export_age_fast(d, passphrase)
    } else {
        backup::export_age(d, passphrase)
    }
}

/// `vault_export_age`.
pub fn export(state: &AppState, input: ExportInput) -> IpcResult<ExportSummary> {
    let password = password_from_ipc(input.password)?;
    let passphrase = SecretString::from(input.export_passphrase);
    state.with_ready(|_, _| Ok(()))?;
    check_export_passphrase(&passphrase, &password)?;
    prove_password(state, &password)?;
    let path = state.picks.take(&input.pick_id, EXPORT_PICK_SESSION, PickMode::File, Instant::now())?;
    let d = document(state)?;
    let bytes = seal_document(state, &d, &passphrase).map_err(|e| export_error(&e))?;
    write_atomic(&path, &bytes).map_err(|e| {
        tracing::warn!(kind = ?e.kind(), "backup file not written");
        IpcError::new("vault.export", "the backup file could not be written")
    })?;
    let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let summary = ExportSummary {
        bytes: count(bytes.len()),
        credentials: count(d.snapshot.credentials.len()),
        connections: count(d.snapshot.connections.len()),
        folders: count(d.snapshot.folders.len()),
    };
    state.audit(AuditEvent::VaultExported {
        credentials: summary.credentials,
        connections: summary.connections,
        folders: summary.folders,
    });
    Ok(summary)
}

// ------------------------------------------------------------------ Tauri wrappers

/// `vault_export_pick()` → `{ pickId, name } | null`.
#[tauri::command]
pub async fn vault_export_pick<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
) -> IpcResult<Option<Picked>> {
    let picker = DialogPicker::new(app.clone());
    let autolock = app.try_state::<AutoLock>();
    pick(&state, &picker, autolock.as_deref()).await
}

/// `vault_export_age({ pickId, password, exportPassphrase })`: Argon2id, scrypt and the file
/// write run on the blocking pool.
#[tauri::command(rename_all = "camelCase")]
pub async fn vault_export_age(
    app: AppHandle,
    pick_id: String,
    password: String,
    export_passphrase: String,
) -> IpcResult<ExportSummary> {
    let input = ExportInput { pick_id, password, export_passphrase };
    super::off_thread(app, move |app| export(&app.state::<AppState>(), input)).await
}

#[cfg(test)]
#[path = "vault_export_tests.rs"]
pub(crate) mod tests;
