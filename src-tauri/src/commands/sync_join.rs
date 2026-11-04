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

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_core::credential::{CredentialFields, CredentialKind, SecretName};
use mooring_core::CredentialId;
use mooring_store::Store;
use mooring_sync::{Outcome, SyncEngine};
use mooring_vault::{Uuid, Vault};
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

/// `vault_join`.
pub async fn join(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    input: JoinInput,
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
            hub.finish(&Err(e.clone()));
            return Err(e);
        }
    };
    let JoinLocal { vault: joined, .. } = local;
    state.save_header(&joined)?;
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
