//! Vault sync commands (ADR-0017 §5, A3 S2). Exact IPC JSON: `docs/handoff/a3-rust-core-s2.md`.
//!
//! `sync_configure`, `sync_status` (passive), `sync_now`, `sync_resolve_fork`,
//! `sync_disable`; `vault_join` is in [`super::sync_join`]. Every command is refused while the
//! vault is locked (`vault.locked`). The `s3_access_key` credential is opened from the vault
//! for each run and dropped after it; no secret crosses IPC, and the endpoint certificate and
//! the fork resolution are answered in native dialogs ([`super::sync_gate`]).

use std::time::{Duration, Instant};

use mooring_audit::AuditEvent;
use mooring_sync::{Alarm, Conflict, Keep, Outcome, SyncEngine, SyncError};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime, State};

use super::sync_config::{self as config, BackendInput, SyncConfig};
use super::sync_gate::{self as gate, DialogPrompter, SyncPrompter};
use super::sync_local::{AppAudit, AppLocal};
use crate::autolock::AutoLock;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;
use crate::sync_runner::{emit_status, SyncHub};

/// Every code a sync command can return besides the shared ones (`vault.locked`,
/// `input.invalid`, `credential.*`, `store.*`): the engine's (S1) and this layer's.
pub const SYNC_CODES: &[&str] = &[
    "sync.format",
    "sync.too_large",
    "sync.tampered",
    "sync.wrong_vault",
    "sync.header_mismatch",
    "sync.rollback",
    "sync.fork",
    "sync.conflict",
    "sync.unsupported_backend",
    "sync.backend",
    "sync.keyring_header",
    "sync.invalid",
    "sync.store",
    "sync.vault",
    "sync.io",
    "sync.store_not_empty",
    "sync.backend_unsupported",
    "sync.in_progress",
    "sync.not_configured",
    "sync.cancelled",
    "http.invalid",
    "http.plaintext_refused",
    "http.trust_store",
    "http.trust_prompt",
    "http.trust_mismatch",
    "http.trust_rejected",
    "http.tls",
    "http.connect",
    "http.timeout",
    "http.protocol",
    "http.status",
    "http.redirect",
    "http.body_too_large",
    "http.decode",
    "http.websocket",
];

/// `IpcError` of an engine error: its stable code and a fixed, secret-free message.
pub fn sync_error(e: &SyncError) -> IpcError {
    let code = SYNC_CODES.iter().copied().find(|c| *c == e.code()).unwrap_or(match e.code() {
        "vault.locked" => "vault.locked",
        _ => "sync.invalid",
    });
    let message = match e {
        SyncError::Http(h) => match h {
            mooring_http::HttpError::TrustPrompt(_) => "the sync storage certificate is not trusted".to_owned(),
            mooring_http::HttpError::TrustMismatch(_) => "the sync storage certificate changed".to_owned(),
            mooring_http::HttpError::Connect(_) | mooring_http::HttpError::Timeout => {
                "the sync storage could not be reached".to_owned()
            }
            _ => "the sync storage request failed".to_owned(),
        },
        SyncError::Store(_) | SyncError::Io(_) => {
            tracing::warn!(error = %e, "sync local error");
            "the local data could not be read or written".to_owned()
        }
        other => other.to_string(),
    };
    IpcError::new(code, message)
}

fn not_configured() -> IpcError {
    IpcError::new("sync.not_configured", "sync is not set up on this device")
}

/// Refuse while locked (and before a vault exists).
fn require_unlocked(state: &AppState) -> IpcResult<()> {
    state.with_ready(|_, _| Ok(()))
}

/// `sync_status()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// `disabled` | `idle` | `running` | `error` | `fork` | `rollback`.
    pub state: &'static str,
    /// The stored settings, `null` when sync is off.
    pub config: Option<SyncConfig>,
    /// Vault id (what a joining device needs).
    pub vault_id: String,
    /// This device's sync id, once it has synced.
    pub device_id: Option<String>,
    /// Last generation this device saw or wrote (0 = never).
    pub counter: u64,
    /// Remote generation last seen (the alarm's when one is pending).
    pub remote_counter: Option<u64>,
    /// Writer of the remote blob last seen ("last pushed by …", R-SYNC-FREEZE).
    pub remote_device: Option<String>,
    /// Its creation time (unix seconds).
    pub remote_created_unix: Option<u64>,
    /// Last pull / push (unix seconds).
    pub last_pull_unix: Option<u64>,
    /// Last push.
    pub last_push_unix: Option<u64>,
    /// Last finished run (this process).
    pub last_run_unix: Option<u64>,
    /// Its outcome.
    pub last_outcome: Option<Outcome>,
    /// Its error.
    pub last_error: Option<IpcError>,
    /// Pending hard stop.
    pub alarm: Option<Alarm>,
    /// Conflicts of the last merge.
    pub conflicts: Vec<Conflict>,
    /// Next background run (unix seconds), `null` when none is scheduled.
    pub next_run_unix: Option<u64>,
}

/// Current status (passive).
pub fn status(state: &AppState, hub: &SyncHub) -> IpcResult<SyncStatus> {
    let ready = state.ready();
    let cfg = config::load(&ready)?;
    let (vault_id, local) = state.with_ready(|v, s| {
        let local = mooring_sync::load_state(s).map_err(|e| sync_error(&e))?;
        Ok((v.vault_id().to_string(), local))
    })?;
    let view = hub.view(Instant::now());
    let alarm = local.as_ref().and_then(|l| l.alarm);
    let state_name = match (&cfg, alarm) {
        (None, _) => "disabled",
        (_, Some(Alarm::Fork { .. })) => "fork",
        (_, Some(Alarm::Rollback { .. })) => "rollback",
        _ if view.running => "running",
        _ if view.last_error.is_some() => "error",
        _ => "idle",
    };
    let counter = local.as_ref().map_or(0, |l| l.last_counter);
    let remote_counter = match alarm {
        Some(Alarm::Fork { remote } | Alarm::Rollback { remote, .. }) => Some(remote),
        None => local.as_ref().filter(|l| l.last_counter > 0).map(|l| l.last_counter),
    };
    Ok(SyncStatus {
        state: state_name,
        next_run_unix: if cfg.as_ref().is_some_and(|c| c.interval_minutes.is_some()) { view.next_run_unix } else { None },
        config: cfg,
        vault_id,
        device_id: local.as_ref().map(|l| l.device_id.to_string()),
        counter,
        remote_counter,
        remote_device: local.as_ref().and_then(|l| l.remote_device.clone()),
        remote_created_unix: local.as_ref().and_then(|l| l.remote_created_unix),
        last_pull_unix: local.as_ref().and_then(|l| l.last_pull_unix),
        last_push_unix: local.as_ref().and_then(|l| l.last_push_unix),
        last_run_unix: view.last_run_unix,
        last_outcome: view.last_outcome,
        last_error: view.last_error,
        alarm,
        conflicts: view.conflicts,
    })
}

/// `(interval, blocked)` for the runner: no config or manual-only → no interval; a pending
/// alarm blocks.
pub fn schedule_inputs(state: &AppState) -> IpcResult<(Option<Duration>, bool)> {
    let Some(cfg) = config::load(&state.ready())? else { return Ok((None, false)) };
    let alarm = state.with_ready(|_, s| Ok(mooring_sync::load_state(s).ok().flatten().and_then(|l| l.alarm)))?;
    let interval = cfg.interval_minutes.map(|m| Duration::from_secs(u64::from(m) * 60));
    Ok((interval, alarm.is_some()))
}

/// `sync_configure` input.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigureInput {
    /// Where to sync.
    pub backend: BackendInput,
    /// `s3_access_key` credential id.
    pub credential_id: String,
    /// Background interval, `null` = manual only.
    pub interval_minutes: Option<u32>,
}

fn vault_id(state: &AppState) -> IpcResult<mooring_vault::Uuid> {
    state.with_ready(|v, _| {
        mooring_sync::header_object(v).map_err(|e| sync_error(&e))?;
        Ok(v.vault_id())
    })
}

/// Validate, probe the backend for conditional writes (certificate prompt through the
/// Gate), store, audit `sync.configured`. A new endpoint, bucket or prefix forgets the
/// device's sync state (it described another remote).
pub async fn configure(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    input: ConfigureInput,
) -> IpcResult<SyncConfig> {
    require_unlocked(state)?;
    let ready = state.ready();
    let cfg = SyncConfig {
        backend: config::check_backend(&input.backend)?,
        credential_id: config::check_credential(&ready, &input.credential_id)?.to_string(),
        interval_minutes: config::check_interval(input.interval_minutes)?,
    };
    let vault = vault_id(state)?;
    let flight = hub.try_begin()?;
    gate::with_trust(state, prompter, autolock, |once| {
        let remote = config::remote(state, &ready, &cfg, vault, once);
        async move { Ok(remote?.require_conditional_writes().await?) }
    })
    .await?;
    let previous = config::load(&ready)?;
    if previous.as_ref().is_some_and(|p| p.backend != cfg.backend) {
        state.with_ready(|_, s| mooring_sync::clear_state(s).map_err(|e| sync_error(&e)))?;
    }
    config::save(&ready, Some(&cfg))?;
    state.audit(AuditEvent::SyncConfigured {
        endpoint: cfg.backend.endpoint.clone(),
        bucket: cfg.backend.bucket.clone(),
        prefix: cfg.backend.prefix.clone(),
        credential: cfg.credential_id.clone(),
        interval_minutes: cfg.interval_minutes,
    });
    hub.reschedule();
    drop(flight);
    emit_status(state, hub);
    Ok(cfg)
}

/// One engine run (`sync_now` and the runner): single-flight, outcome recorded and emitted.
pub async fn run_once(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
) -> IpcResult<Outcome> {
    require_unlocked(state)?;
    let flight = hub.try_begin()?;
    emit_status(state, hub);
    let result = async {
        let ready = state.ready();
        let cfg = config::load(&ready)?.ok_or_else(not_configured)?;
        let vault = vault_id(state)?;
        let local = AppLocal::new(state, hub.device_name());
        let audit = AppAudit::of(state);
        let out = gate::with_trust(state, prompter, autolock, |once| {
            let remote = config::remote(state, &ready, &cfg, vault, once);
            let (local, audit) = (&local, &audit);
            async move { Ok(SyncEngine::default().run(local, &remote?, audit).await?) }
        })
        .await?;
        Ok::<_, IpcError>(out)
    }
    .await;
    hub.finish(&result);
    drop(flight);
    emit_status(state, hub);
    result
}

/// `sync_resolve_fork({ keep })`: after a native confirmation (the other side is discarded),
/// keep this device's data or the remote's. Audited `sync.fork_resolved`.
pub async fn resolve_fork(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    keep: &str,
) -> IpcResult<Outcome> {
    let (keep, target) = match keep {
        "local" => (Keep::Local, "local"),
        "remote" => (Keep::Remote, "remote"),
        _ => return Err(IpcError::invalid("keep", "must be \"local\" or \"remote\"")),
    };
    require_unlocked(state)?;
    let ready = state.ready();
    let cfg = config::load(&ready)?.ok_or_else(not_configured)?;
    let pending = state.with_ready(|_, s| Ok(mooring_sync::load_state(s).ok().flatten().and_then(|l| l.alarm)))?;
    if pending.is_none() {
        return Err(IpcError::new("sync.invalid", "there is no fork or rollback to resolve"));
    }
    let message = match keep {
        Keep::Local => "Publish this device's data as the synced vault? Every change other devices synced after the fork is discarded.",
        Keep::Remote => "Replace this device's data with the synced vault? Every local change since the last sync is discarded.",
    };
    let confirmed = match prompter {
        Some(p) => {
            let scope = gate::Scope { kind: "sync_fork", target, destructive: true };
            gate::confirm(&state.confirm, scope, p, autolock, "Resolve sync fork", message, "Discard and resolve").await?
        }
        None => false,
    };
    if !confirmed {
        return Err(IpcError::new("sync.cancelled", "the fork was not resolved"));
    }
    let flight = hub.try_begin()?;
    let vault = vault_id(state)?;
    let local = AppLocal::new(state, hub.device_name());
    let audit = AppAudit::of(state);
    let result = gate::with_trust(state, prompter, autolock, |once| {
        let remote = config::remote(state, &ready, &cfg, vault, once);
        let (local, audit) = (&local, &audit);
        async move { Ok(SyncEngine::default().resolve_fork(local, &remote?, keep, audit).await?) }
    })
    .await
    .map_err(IpcError::from);
    hub.finish(&result);
    hub.reschedule();
    drop(flight);
    emit_status(state, hub);
    result
}

/// `sync_disable({ deleteRemote })`: forget the settings and this device's sync state;
/// optionally delete the vault's objects in the bucket first.
pub async fn disable(
    state: &AppState,
    hub: &SyncHub,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    delete_remote: bool,
) -> IpcResult<()> {
    require_unlocked(state)?;
    let ready = state.ready();
    let cfg = config::load(&ready)?.ok_or_else(not_configured)?;
    let flight = hub.try_begin()?;
    if delete_remote {
        let vault = vault_id(state)?;
        let last = state.with_ready(|_, s| Ok(mooring_sync::load_state(s).ok().flatten().map_or(0, |l| l.last_counter)))?;
        gate::with_trust(state, prompter, autolock, |once| {
            let remote = config::remote(state, &ready, &cfg, vault, once);
            async move { Ok(remote?.delete_all(last).await?) }
        })
        .await?;
    }
    state.with_ready(|_, s| mooring_sync::clear_state(s).map_err(|e| sync_error(&e)))?;
    config::save(&ready, None)?;
    state.audit(AuditEvent::SyncDisabled { delete_remote });
    hub.reset();
    drop(flight);
    emit_status(state, hub);
    Ok(())
}

// ------------------------------------------------------------------ Tauri wrappers

fn hub<R: Runtime>(app: &AppHandle<R>) -> IpcResult<State<'_, SyncHub>> {
    app.try_state::<SyncHub>().ok_or_else(|| IpcError::new("sync.not_configured", "sync is not available"))
}

/// `sync_configure({ backend, credentialId, intervalMinutes })` → `SyncConfig`.
#[tauri::command(rename_all = "camelCase")]
pub async fn sync_configure<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    backend: BackendInput,
    credential_id: String,
    interval_minutes: Option<u32>,
) -> IpcResult<SyncConfig> {
    let prompter = DialogPrompter { app: app.clone() };
    let input = ConfigureInput { backend, credential_id, interval_minutes };
    configure(&state, &*hub(&app)?, Some(&prompter), app.try_state::<AutoLock>().as_deref(), input).await
}

/// `sync_status()` → `SyncStatus` (passive).
#[tauri::command]
pub fn sync_status<R: Runtime>(app: AppHandle<R>, state: State<'_, AppState>) -> IpcResult<SyncStatus> {
    status(&state, &*hub(&app)?)
}

/// `sync_now()` → `Outcome`.
#[tauri::command]
pub async fn sync_now<R: Runtime>(app: AppHandle<R>, state: State<'_, AppState>) -> IpcResult<Outcome> {
    let prompter = DialogPrompter { app: app.clone() };
    run_once(&state, &*hub(&app)?, Some(&prompter), app.try_state::<AutoLock>().as_deref()).await
}

/// `sync_resolve_fork({ keep: "local" | "remote" })` → `Outcome`.
#[tauri::command(rename_all = "camelCase")]
pub async fn sync_resolve_fork<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    keep: String,
) -> IpcResult<Outcome> {
    let prompter = DialogPrompter { app: app.clone() };
    resolve_fork(&state, &*hub(&app)?, Some(&prompter), app.try_state::<AutoLock>().as_deref(), &keep).await
}

/// `sync_disable({ deleteRemote? })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn sync_disable<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    delete_remote: Option<bool>,
) -> IpcResult<()> {
    let prompter = DialogPrompter { app: app.clone() };
    let al = app.try_state::<AutoLock>();
    disable(&state, &*hub(&app)?, Some(&prompter), al.as_deref(), delete_remote.unwrap_or(false)).await
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
