//! `vault_import_pick` / `vault_import_inspect` / `vault_import_age` (ADR-0023 §2).
//!
//! 1. *pick*: the open dialog from Rust; the path goes to `Picks` under a `pickId`.
//! 2. *inspect*: the file is read in Rust (64 MiB cap), decrypted with the export
//!    passphrase and validated as a whole (`mooring_sync::export`); the parsed document is
//!    held under the same `pickId` ([`super::vault_import_hold`]). A wrong passphrase keeps
//!    the pick for a retry (at most three).
//! 3. *apply*: master password (proved on a scratch header), `mode` `merge` (default) or
//!    `replace` (typed confirmation `REPLACE`). A foreign file needs the **source** master
//!    password: its header unlocks in memory and every secret is re-sealed under our DEK.
//!    `merge` keeps both copies of a record changed on both sides (the imported one renamed
//!    "… (imported <date>)"), never overwrites a secret, unions trust stores, ignores
//!    tombstones; `replace` swaps every folder, connection, credential and trust line for
//!    the file's. Store rows change in one transaction; nothing changes on any refusal.
//!
//! v1 backups (credentials without kind or name) cannot be turned into records and are
//! refused with `vault.import_version`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use mooring_audit::AuditEvent;
use mooring_sync::export::{self as backup, ExportDocument, Imported};
use mooring_sync::merge::{merge, MergeCtx, Reseal, Resolution};
use mooring_sync::snapshot::{self, Snapshot};
use mooring_vault::{Vault, MAX_EXPORT_BYTES};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::oneshot;

use crate::autolock::AutoLock;
use crate::commands::sftp_pick::{DialogPicker, LocalPicker};
use crate::commands::sftp_transfers::dialog_dir;
use crate::commands::vault::password_from_ipc;
use crate::commands::vault_export::{import_error, prove_password, EXTENSION};
use crate::error::{IpcError, IpcResult};
use crate::picks::PickMode;
use crate::state::AppState;

/// `Picks` namespace of backup files to import.
pub const IMPORT_PICK_SESSION: &str = "vault-import";
/// The typed confirmation of `replace`.
pub const REPLACE_CONFIRMATION: &str = "REPLACE";
/// Merge-side device name; conflict copies are renamed from its suffix.
const IMPORT_DEVICE: &str = "import";

/// `{ pickId, name, bytes }` of a chosen backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedBackup {
    /// 128-bit hex id, single-use, valid for 10 minutes.
    pub pick_id: String,
    /// File name only.
    pub name: String,
    /// File size.
    pub bytes: u64,
}

/// Record counts of a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// Folders (the root included).
    pub folders: u64,
    /// Connections.
    pub connections: u64,
    /// Credentials.
    pub credentials: u64,
    /// Trust-store lines.
    pub trust: u64,
}

/// `vault_import_inspect` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportInspect {
    /// Source vault id.
    pub vault_id: String,
    /// The backup is of this vault.
    pub same_vault: bool,
    /// RFC 3339 time of the export.
    pub exported_at: String,
    /// Mooring version that wrote it.
    pub app_version: String,
    /// What the file holds.
    pub counts: Counts,
    /// `vault_import_age` needs `sourcePassword`.
    pub needs_source_password: bool,
}

/// `vault_import_age` input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportInput {
    /// From `vault_import_inspect`.
    pub pick_id: String,
    /// Master password of this vault.
    pub password: String,
    /// The source vault's master password (foreign files only).
    pub source_password: Option<String>,
    /// `merge` | `replace`.
    pub mode: String,
    /// `REPLACE` for `mode: replace`.
    pub confirm: Option<String>,
}

/// One reported conflict (ids and names only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportConflict {
    /// `folder` | `connection` | `credential`.
    pub kind: &'static str,
    /// `kept_both`: id of the imported copy; otherwise the record's id.
    pub id: String,
    /// The (renamed) copy's name, or the kept record's name.
    pub name: String,
    /// `kept_both` (connections, credentials: both copies kept) | `last_writer_wins`
    /// (folders: the newer `updated_at` stays, nothing is duplicated).
    pub resolution: &'static str,
}

/// `vault_import_age` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    /// `merge` | `replace`.
    pub mode: &'static str,
    /// Records added.
    pub added: u64,
    /// Records changed in place (`replace`: always 0, everything is added anew).
    pub updated: u64,
    /// Records changed on both sides: both copies kept.
    pub conflicts: Vec<ImportConflict>,
    /// Records identical on both sides.
    pub skipped: u64,
}

fn n(x: usize) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

fn counts(s: &Snapshot) -> Counts {
    Counts {
        folders: n(s.folders.len()),
        connections: n(s.connections.len()),
        credentials: n(s.credentials.len()),
        trust: n(s.trust.values().map(std::collections::BTreeSet::len).sum()),
    }
}

fn refuse(state: &AppState, e: IpcError) -> IpcError {
    state.audit(AuditEvent::VaultImportRefused { code: e.code.to_string() });
    e
}

/// `vault_import_pick`: the open dialog; `None` when cancelled or locked meanwhile.
pub async fn pick(
    state: &AppState,
    picker: &dyn LocalPicker,
    autolock: Option<&AutoLock>,
) -> IpcResult<Option<PickedBackup>> {
    state.with_ready(|_, _| Ok(()))?;
    let epoch = state.picks.epoch();
    let chosen = {
        let _open = autolock.map(AutoLock::dialog_guard);
        let (tx, rx) = oneshot::channel();
        let reply = Box::new(move |p| drop(tx.send(p)));
        picker.pick_filtered(PickMode::File, "Mooring backup", &[EXTENSION], reply);
        rx.await.ok().flatten()
    };
    let Some(raw) = chosen else { return Ok(None) };
    let bad = |r: &str| IpcError::invalid("pick", r);
    let name = raw.file_name().ok_or_else(|| bad("names no file"))?;
    let name = name.to_str().ok_or_else(|| bad("file name is not UTF-8"))?.to_owned();
    let path = dialog_dir(state, "pick", raw.parent().ok_or_else(|| bad("names no file"))?)?.join(&name);
    let bytes = file_size(&path)?;
    Ok(state
        .picks
        .insert(epoch, IMPORT_PICK_SESSION, PickMode::File, path, Instant::now())
        .map(|pick_id| PickedBackup { pick_id, name, bytes }))
}

fn file_size(path: &Path) -> IpcResult<u64> {
    let meta = std::fs::metadata(path).map_err(|_| IpcError::invalid("pick", "file not found"))?;
    if !meta.is_file() {
        return Err(IpcError::invalid("pick", "not a regular file"));
    }
    if meta.len() > MAX_EXPORT_BYTES as u64 {
        return Err(IpcError::new("vault.import_too_large", "the backup file is larger than 64 MiB"));
    }
    Ok(meta.len())
}

fn read_backup(path: &Path) -> IpcResult<Vec<u8>> {
    file_size(path)?;
    let bytes = std::fs::read(path).map_err(|e| {
        tracing::warn!(kind = ?e.kind(), "backup file unreadable");
        IpcError::invalid("pick", "the file could not be read")
    })?;
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err(IpcError::new("vault.import_too_large", "the backup file is larger than 64 MiB"));
    }
    Ok(bytes)
}

/// `vault_import_inspect({ pickId, exportPassphrase })`.
pub fn inspect(state: &AppState, pick_id: &str, passphrase: &SecretString) -> IpcResult<ImportInspect> {
    let ours = state.with_ready(|v, _| Ok(v.vault_id()))?;
    let parsed = state.picks.take_if(pick_id, IMPORT_PICK_SESSION, PickMode::File, Instant::now(), |path| {
        let (name, bytes) = (path.file_name().map(|n| n.to_string_lossy().into_owned()), read_backup(path)?);
        let d = backup::import_age(&bytes, passphrase).map_err(|e| import_error(&e, false))?;
        Ok((name.unwrap_or_default(), d))
    });
    let (name, d) = parsed.map_err(|e| if e.code == "input.invalid" { e } else { refuse(state, e) })?;
    let d = match d {
        Imported::V2(d) => d,
        Imported::V1 { .. } => {
            return Err(refuse(
                state,
                IpcError::new(
                    "vault.import_version",
                    "this is a v1 backup: its credentials carry no kind or name and cannot be imported",
                ),
            ))
        }
    };
    let foreign = d.snapshot.vault_id != ours;
    let out = ImportInspect {
        vault_id: d.snapshot.vault_id.to_string(),
        same_vault: !foreign,
        exported_at: d.exported_at.clone(),
        app_version: d.app_version.clone(),
        counts: counts(&d.snapshot),
        needs_source_password: foreign,
    };
    state.imports.insert(pick_id, Imported::V2(d), name, foreign, Instant::now());
    Ok(out)
}

/// Re-seal for conflict copies (new record id) under our DEK.
struct OurVault<'a>(&'a Vault);

impl Reseal for OurVault<'_> {
    fn reseal(&self, old: &str, new: &str, secret: &str, sealed: &str) -> mooring_sync::Result<String> {
        mooring_sync::reseal_secret(self.0, old, new, secret, sealed)
    }
}

/// Merge keeps our root folder: the file's root row goes and its children hang under ours
/// (one root per store; a changed root of the same vault must not become a second root).
fn adopt_root(file: &mut Snapshot, local: &Snapshot) {
    let root = |s: &Snapshot| s.folders.values().find(|f| f.parent_id.is_none()).map(|f| f.id.clone());
    let (Some(theirs), Some(ours)) = (root(file), root(local)) else { return };
    file.folders.remove(&theirs);
    if theirs == ours {
        return;
    }
    for f in file.folders.values_mut() {
        if f.parent_id.as_deref() == Some(theirs.as_str()) {
            f.parent_id = Some(ours.clone());
        }
    }
    for c in file.connections.values_mut() {
        if c.folder_id == theirs {
            c.folder_id.clone_from(&ours);
        }
    }
}

/// `" (conflict from import)"` → `" (imported <date>)"` on every kept copy.
fn rename_copies(plan: &mut Snapshot, conflicts: &[mooring_sync::Conflict], date: &str) -> Vec<ImportConflict> {
    let from = format!(" (conflict from {IMPORT_DEVICE})");
    let to = format!(" (imported {date})");
    let fix = |name: &mut String| {
        if let Some(stem) = name.strip_suffix(&from) {
            *name = format!("{stem}{to}");
        }
    };
    let mut out = Vec::new();
    for c in conflicts {
        let Resolution::KeptBoth { copy_id } = &c.resolution else {
            let resolution = match c.resolution {
                Resolution::LastWriterWins => "last_writer_wins",
                _ => "kept_edit",
            };
            out.push(ImportConflict { kind: c.kind.name(), id: c.id.clone(), name: c.name.clone(), resolution });
            continue;
        };
        let name = match c.kind {
            mooring_sync::RecordKind::Folder => plan.folders.get_mut(copy_id).map(|r| &mut r.name),
            mooring_sync::RecordKind::Connection => plan.connections.get_mut(copy_id).map(|r| &mut r.name),
            mooring_sync::RecordKind::Credential => plan.credentials.get_mut(copy_id).map(|r| &mut r.name),
        };
        if let Some(name) = name {
            fix(name);
            out.push(ImportConflict {
                kind: c.kind.name(),
                id: copy_id.clone(),
                name: name.clone(),
                resolution: "kept_both",
            });
        }
    }
    out
}

/// Sealing is randomised: a credential whose secrets open to the same plaintext as ours
/// takes our sealed strings, so merge sees it as unchanged instead of keeping two copies.
fn align_secrets(file: &mut Snapshot, local: &Snapshot, v: &Vault) {
    let open = |id: &str, name: &str, sealed: &str| {
        serde_json::from_str::<mooring_vault::Sealed>(sealed).ok().and_then(|s| v.open(id, name, &s).ok())
    };
    for (id, theirs) in &mut file.credentials {
        let Some(ours) = local.credentials.get(id) else { continue };
        if theirs.secrets.len() != ours.secrets.len() {
            continue;
        }
        let same = theirs.secrets.iter().all(|(name, sealed)| {
            ours.secrets.get(name).is_some_and(|mine| match (open(id, name, sealed), open(id, name, mine)) {
                (Some(a), Some(b)) => *a == *b,
                _ => false,
            })
        });
        if same {
            theirs.secrets.clone_from(&ours.secrets);
        }
    }
}

fn tally<V: PartialEq>(local: &BTreeMap<String, V>, file: &BTreeMap<String, V>) -> (u64, u64) {
    let added = file.keys().filter(|k| !local.contains_key(*k)).count();
    let same = file.iter().filter(|(k, v)| local.get(*k) == Some(v)).count();
    (n(added), n(same))
}

/// `vault_import_age`.
pub fn apply(state: &AppState, input: ImportInput) -> IpcResult<ImportReport> {
    let password = password_from_ipc(input.password)?;
    let replace = match input.mode.as_str() {
        "merge" => false,
        "replace" => true,
        _ => return Err(IpcError::invalid("mode", "expected merge or replace")),
    };
    if replace && input.confirm.as_deref() != Some(REPLACE_CONFIRMATION) {
        return Err(IpcError::invalid("confirm", "type REPLACE to replace the vault contents"));
    }
    state.with_ready(|_, _| Ok(()))?;
    prove_password(state, &password)?;
    let held = state.imports.take(&input.pick_id, Instant::now())?;
    let Imported::V2(d) = held.doc else {
        return Err(IpcError::new("vault.import_version", "unsupported backup version"));
    };
    let source = if held.foreign {
        let raw = input.source_password.filter(|p| !p.is_empty()).ok_or_else(|| {
            IpcError::new("vault.import_source_password", "the source vault's master password is required")
        })?;
        let mut from = Vault::from_header(d.header.clone());
        from.unlock(&password_from_ipc(raw)?).map_err(|_| {
            refuse(state, IpcError::new("vault.import_source_password", "wrong master password of the source vault"))
        })?;
        Some(from)
    } else {
        None
    };
    let report = apply_document(state, d, source.as_ref(), replace).map_err(|e| refuse(state, e))?;
    drop(source);
    if replace && held.foreign {
        super::vault_biometric::on_vault_rotated(state);
    }
    state.audit(AuditEvent::VaultImported {
        mode: report.mode.to_owned(),
        foreign: held.foreign,
        added: report.added,
        updated: report.updated,
        conflicts: n(report.conflicts.len()),
        skipped: report.skipped,
    });
    Ok(report)
}

fn apply_document(
    state: &AppState,
    d: ExportDocument,
    source: Option<&Vault>,
    replace: bool,
) -> IpcResult<ImportReport> {
    let foreign = source.is_some();
    state.with_ready(|v, s| {
        let mut file = d.snapshot;
        // Every secret must open (ours, or the source's) and is sealed under our DEK; a file
        // with one bad secret is refused as a whole.
        backup::reseal_snapshot(&mut file, source.unwrap_or(v), v).map_err(|e| import_error(&e, foreign))?;
        file.vault_id = v.vault_id();
        file.tombstones.clear();
        let local = snapshot::from_store(s, &state.data_dir, v.vault_id(), IMPORT_DEVICE)
            .map_err(|e| import_error(&e.into(), foreign))?;
        let now = crate::dto::ts(time::OffsetDateTime::now_utc());
        let (target, report) = if replace {
            let c = counts(&file);
            let added = c.folders + c.connections + c.credentials;
            let report = ImportReport { mode: "replace", added, updated: 0, conflicts: vec![], skipped: 0 };
            (file, report)
        } else {
            adopt_root(&mut file, &local);
            align_secrets(&mut file, &local, v);
            let (fa, fs) = tally(&local.folders, &file.folders);
            let (ca, cs) = tally(&local.connections, &file.connections);
            let (ka, ks) = tally(&local.credentials, &file.credentials);
            let ctx = MergeCtx { remote_device: IMPORT_DEVICE, now: &now };
            let mut plan = merge(None, &local, &file, ctx, &OurVault(v)).map_err(|e| import_error(&e.into(), foreign))?;
            let date = now.get(..10).unwrap_or(&now).to_owned();
            let conflicts = rename_copies(&mut plan.snapshot, &plan.conflicts, &date);
            let report = ImportReport {
                mode: "merge",
                added: fa + ca + ka,
                updated: 0,
                conflicts,
                skipped: fs + cs + ks,
            };
            (plan.snapshot, report)
        };
        snapshot::apply(s, &state.data_dir, &target).map_err(|e| {
            tracing::warn!(error = %e, "backup import not applied");
            match e {
                mooring_sync::SyncError::Store(se) => IpcError::from(se),
                other => import_error(&other.into(), foreign),
            }
        })?;
        Ok(report)
    })
}

// ------------------------------------------------------------------ Tauri wrappers

/// `vault_import_pick()` → `{ pickId, name, bytes } | null`.
#[tauri::command]
pub async fn vault_import_pick<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
) -> IpcResult<Option<PickedBackup>> {
    let picker = DialogPicker::new(app.clone());
    let autolock = app.try_state::<AutoLock>();
    pick(&state, &picker, autolock.as_deref()).await
}

/// `vault_import_inspect({ pickId, exportPassphrase })`: read + scrypt off the IPC thread.
#[tauri::command(rename_all = "camelCase")]
pub async fn vault_import_inspect(
    app: AppHandle,
    pick_id: String,
    export_passphrase: String,
) -> IpcResult<ImportInspect> {
    let passphrase = SecretString::from(export_passphrase);
    super::off_thread(app, move |app| inspect(&app.state::<AppState>(), &pick_id, &passphrase)).await
}

/// `vault_import_age({ pickId, password, sourcePassword, mode, confirm })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn vault_import_age(
    app: AppHandle,
    pick_id: String,
    password: String,
    source_password: Option<String>,
    mode: String,
    confirm: Option<String>,
) -> IpcResult<ImportReport> {
    let input = ImportInput { pick_id, password, source_password, mode, confirm };
    super::off_thread(app, move |app| apply(&app.state::<AppState>(), input)).await
}

#[cfg(test)]
#[path = "vault_import_tests.rs"]
mod tests;
