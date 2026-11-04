//! `vault_join` (ADR-0017 §5, A3 S2): a fresh device adopts a synced vault.
//!
//! The device first creates a throw-away *bootstrap* vault and stores the `s3_access_key`
//! credential in it (the UI handles credential ids only; no secret crosses IPC outward). The
//! bootstrap store must be empty apart from that credential (`sync.store_not_empty`: the
//! root folder, no other folder, connection or credential, never synced). Then:
//!
//! 1. the remote vault header is fetched (certificate prompt through the Gate), parsed and
//!    unlocked with the vault's master password (`vault.unlock` on a wrong one);
//! 2. the current blob is verified against that header and applied with no merge
//!    ([`mooring_sync::SyncEngine::join`]); the store is rebound to the joined vault inside the
//!    apply and bound back if it fails;
//! 3. the joined header replaces the bootstrap header on disk and in memory, the access key is
//!    re-created under the joined vault (or the synced copy with the same key id is reused),
//!    and the sync settings are stored. Audited `sync.pulled` + `sync.joined`.
//!
//! Review 6 L-37 — the header write cannot strand the device: the joined header is **staged**
//! to [`JOIN_TMP`] (0600, fsync) before the apply and renamed over the bootstrap header right
//! after it. A staging failure stops the join before any row changes; an apply failure binds
//! the store back and discards the staged file; a rename failure keeps the staged file and the
//! joined binding, and [`recover_staged_header`] completes the rename at the next start when
//! the store is bound to the staged header's vault (otherwise the leftover is removed).

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_core::credential::{CredentialFields, CredentialKind, SecretName};
use mooring_core::CredentialId;
use mooring_store::Store;
use mooring_sync::{Outcome, SyncEngine};
use mooring_vault::{Header, Uuid, Vault};
use tauri::{AppHandle, Manager, Runtime, State};
use zeroize::Zeroizing;

use super::sync_config::{self as config, BackendInput, SyncConfig};
use super::sync_gate::{self as gate, DialogPrompter, SyncPrompter};
use super::sync_local::{AppAudit, JoinLocal};
use super::vault::{password_from_ipc, VaultStatus};
use crate::autolock::AutoLock;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;
use crate::sync_runner::{emit_status, SyncHub};

/// The staged joined header, next to `vault.header.json` (L-37).
pub const JOIN_TMP: &str = "vault.header.json.join-tmp";

/// Writes the joined header in two steps (tests inject failures).
pub trait HeaderWriter: Send + Sync {
    /// Write `header` to [`JOIN_TMP`] (0600, fsync).
    fn stage(&self, state: &AppState, header: &Header) -> IpcResult<()>;
    /// Rename the staged file over the vault header (durable).
    fn commit(&self, state: &AppState) -> IpcResult<()>;
}

fn io(what: &'static str) -> IpcError {
    IpcError::new("state.io", what)
}

/// The production writer.
#[derive(Debug, Default)]
pub struct FsHeaderWriter;

impl HeaderWriter for FsHeaderWriter {
    fn stage(&self, state: &AppState, header: &Header) -> IpcResult<()> {
        use std::io::Write;
        let bytes = header.to_bytes().map_err(|_| io("the joined header could not be encoded"))?;
        let path = state.data_dir.join(JOIN_TMP);
        let written = crate::state::create_private(&path).and_then(|mut f| {
            f.write_all(&bytes)?;
            f.sync_all()
        });
        if let Err(e) = written {
            tracing::warn!(kind = ?e.kind(), "join: the joined header could not be staged");
            discard_staged(state);
            return Err(io("the joined vault header could not be written"));
        }
        Ok(())
    }

    fn commit(&self, state: &AppState) -> IpcResult<()> {
        let header = state.data_dir.join(AppState::HEADER_FILE);
        if header.exists() {
            if let Err(e) = std::fs::copy(&header, state.data_dir.join(AppState::HEADER_BACKUP)) {
                tracing::debug!(kind = ?e.kind(), "join: header backup skipped");
            }
        }
        std::fs::rename(state.data_dir.join(JOIN_TMP), &header)
            .map_err(|_| io("the joined vault header could not be installed"))?;
        crate::state::sync_dir(&state.data_dir);
        Ok(())
    }
}

/// Remove a staged header (a join that failed before the rename).
pub fn discard_staged(state: &AppState) {
    if let Err(e) = std::fs::remove_file(state.data_dir.join(JOIN_TMP)) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(kind = ?e.kind(), "join: staged header not removed");
        }
    }
}

/// Start-up (L-37): complete the rename of a staged joined header when `store` is already
/// bound to its vault (the apply succeeded, the rename did not) **and** the header on disk is
/// still the bootstrap one. Returns the vault to start with.
///
/// Review 6b: (a) when the rename fails again the staged file is kept (it is the only copy of
/// the joined header) and the staged vault is returned, so the device binds to the vault its
/// store belongs to; (b) when the current header already carries the joined vault's id, it is
/// newer than the staged copy (a password change or KDF upgrade rewrote it after the failed
/// commit), so the staged file is removed instead of being installed over it.
pub fn recover_staged_header(data_dir: &std::path::Path, store: &Store, current: Option<Vault>) -> Option<Vault> {
    let tmp = data_dir.join(JOIN_TMP);
    let Ok(bytes) = std::fs::read(&tmp) else { return current };
    let staged = Vault::from_header_bytes(&bytes).ok();
    let staged_id = staged.as_ref().map(|v| v.vault_id().to_string());
    let bound = store.vault_id().ok().flatten();
    let completes = staged_id.is_some() && staged_id == bound;
    let current_is_joined = current.as_ref().map(|v| v.vault_id().to_string()) == staged_id;
    if completes && !current_is_joined {
        match std::fs::rename(&tmp, data_dir.join(AppState::HEADER_FILE)) {
            Ok(()) => {
                crate::state::sync_dir(data_dir);
                tracing::warn!("join: staged vault header installed at start");
            }
            Err(e) => {
                tracing::error!(kind = ?e.kind(), "join: staged vault header kept; it could not be installed");
            }
        }
        return staged;
    }
    if let Err(e) = std::fs::remove_file(&tmp) {
        tracing::warn!(kind = ?e.kind(), "join: stale staged header not removed");
    }
    current
}

/// The vault id a staged header (if any) carries.
pub fn staged_vault_id(data_dir: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(data_dir.join(JOIN_TMP)).ok()?;
    Some(Vault::from_header_bytes(&bytes).ok()?.vault_id().to_string())
}

/// `vault_join` input (no `Debug`: it carries the master password).
pub struct JoinInput {
    /// Where the vault is synced.
    pub backend: BackendInput,
    /// The `s3_access_key` credential stored in the bootstrap vault.
    pub credential_id: String,
    /// Id of the synced vault (shown in `sync_status.vaultId` on a synced device).
    pub vault_id: String,
    /// Master password of the synced vault.
    pub password: String,
    /// Background interval after the join, `null` = manual only.
    pub interval_minutes: Option<u32>,
}

impl std::fmt::Debug for JoinInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinInput").field("vault_id", &self.vault_id).finish_non_exhaustive()
    }
}

fn not_empty() -> IpcError {
    IpcError::new("sync.store_not_empty", "joining needs a fresh vault that holds only the access key")
}

/// The bootstrap store holds the root folder and `cred` only, and never synced.
fn check_empty(store: &Store, cred: CredentialId) -> IpcResult<()> {
    let rows = store.export_sync_rows()?;
    let only_root = rows.folders.len() <= 1 && rows.folders.values().all(|f| f.parent_id.is_none());
    let only_cred = rows.credentials.keys().all(|id| *id == cred.to_string());
    let synced = mooring_sync::load_state(store).ok().flatten().is_some()
        || store.sync_setting(config::CONFIG_KEY)?.is_some();
    if only_root && only_cred && rows.connections.is_empty() && !synced {
        Ok(())
    } else {
        Err(not_empty())
    }
}

type Material = (String, serde_json::Value, Vec<(SecretName, Zeroizing<Vec<u8>>)>);

/// Name, fields and secrets of the bootstrap credential (secrets zeroized on drop).
fn material(vault: &Vault, store: &Store, id: CredentialId) -> IpcResult<Material> {
    let meta = store.get_credential(id)?;
    let secrets = meta
        .secret_names
        .iter()
        .map(|n| Ok((*n, store.open_secret(vault, id, *n)?)))
        .collect::<IpcResult<Vec<_>>>()?;
    Ok((meta.name, meta.fields.to_value(), secrets))
}

/// The access key in the joined store: the synced copy with the same key id, or a new one.
fn install_credential(vault: &Vault, store: &Store, m: &Material) -> IpcResult<CredentialId> {
    let key_id = m.1.get("access_key_id").and_then(|v| v.as_str()).unwrap_or_default();
    for c in store.list_credentials()? {
        if let CredentialFields::S3AccessKey(f) = &c.fields {
            if f.access_key_id == key_id {
                return Ok(c.id);
            }
        }
    }
    let secrets: mooring_store::Secrets<'_> = m.2.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    Ok(store.create_credential(vault, &m.0, CredentialKind::S3AccessKey, &m.1, &secrets)?.id)
}

/// `vault_join` with the production header writer.
pub async fn join(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    input: JoinInput,
) -> IpcResult<VaultStatus> {
    join_with(state, hub, prompter, autolock, input, &FsHeaderWriter).await
}

/// `vault_join` over `writer` (tests inject a failing one).
pub async fn join_with(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    input: JoinInput,
    writer: &dyn HeaderWriter,
) -> IpcResult<VaultStatus> {
    let backend = config::check_backend(&input.backend)?;
    let interval_minutes = config::check_interval(input.interval_minutes)?;
    let target = Uuid::parse_str(input.vault_id.trim())
        .ok()
        .filter(|u| !u.is_nil())
        .ok_or_else(|| IpcError::invalid("vaultId", "not a vault id"))?;
    let password = password_from_ipc(input.password)?;
    let ready = state.ready();
    let cred = config::check_credential(&ready, &input.credential_id)?;
    let (bootstrap, boot) = state.with_ready(|v, s| {
        check_empty(s, cred)?;
        Ok((v.vault_id(), material(v, s, cred)?))
    })?;
    if bootstrap == target {
        return Err(not_empty());
    }
    let flight = hub.try_begin()?;
    let mut cfg = SyncConfig { backend, credential_id: cred.to_string(), interval_minutes };
    let header = gate::with_trust(state, prompter, autolock, |once| {
        let remote = config::remote(state, &ready, &cfg, target, once);
        async move { Ok(remote?.get_header().await?) }
    })
    .await?
    .ok_or_else(|| IpcError::new("sync.invalid", "the storage holds no vault with this id"))?;
    let mut joined = Vault::from_header_bytes(&header)?;
    if joined.vault_id() != target || joined.header().needs_upgrade() {
        return Err(IpcError::new("sync.wrong_vault", "the stored header belongs to another vault"));
    }
    joined.unlock(&password)?;
    // L-37: the joined header is on disk (staged) before any row changes.
    writer.stage(state, joined.header())?;
    let local = JoinLocal {
        vault: joined,
        store: Arc::clone(&state.store),
        previous_vault: bootstrap.to_string(),
        trust_dir: state.data_dir.clone(),
        device_name: hub.device_name().to_owned(),
    };
    let audit = AppAudit::of(state);
    let outcome = gate::with_trust(state, prompter, autolock, |once| {
        let remote = config::remote(state, &ready, &cfg, target, once);
        let (local, audit) = (&local, &audit);
        async move { Ok(SyncEngine::default().join(local, &remote?, audit).await?) }
    })
    .await
    .map_err(IpcError::from);
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            // The store is bound back to the bootstrap vault (`JoinLocal::apply`).
            discard_staged(state);
            hub.finish(&Err(e.clone()));
            return Err(e);
        }
    };
    let JoinLocal { vault: joined, .. } = local;
    // The rows are in and the store is bound to the joined vault: install the header. A
    // failed rename leaves the staged file for `recover_staged_header` at the next start;
    // this process goes on with the joined vault in memory.
    if let Err(e) = writer.commit(state) {
        tracing::error!(code = e.code, "join: the joined header stays staged until the next start");
    }
    *state.vault()? = Some(joined);
    state.drop_header_backup();
    let id = state.with_ready(|v, s| install_credential(v, s, &boot))?;
    drop(boot);
    cfg.credential_id = id.to_string();
    config::save(&ready, Some(&cfg))?;
    let counter = match outcome {
        Outcome::Pulled { counter } => counter,
        _ => 0,
    };
    state.audit(AuditEvent::SyncJoined { vault: target.to_string(), counter });
    hub.finish(&Ok(outcome));
    hub.reschedule();
    drop(flight);
    emit_status(state, hub);
    Ok(VaultStatus::Unlocked)
}

/// `vault_join({ backend, credentialId, vaultId, password, intervalMinutes? })` →
/// `"unlocked"`.
#[tauri::command(rename_all = "camelCase")]
#[allow(clippy::too_many_arguments)]
pub async fn vault_join<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    backend: BackendInput,
    credential_id: String,
    vault_id: String,
    password: String,
    interval_minutes: Option<u32>,
) -> IpcResult<VaultStatus> {
    let hub = app
        .try_state::<SyncHub>()
        .ok_or_else(|| IpcError::new("sync.not_configured", "sync is not available"))?;
    let prompter = DialogPrompter { app: app.clone() };
    let input = JoinInput { backend, credential_id, vault_id, password, interval_minutes };
    join(&state, &hub, Some(&prompter), app.try_state::<AutoLock>().as_deref(), input).await
}
