//! Vault commands: status, create, unlock, lock, change password, plus `app_info`.

use mooring_audit::AuditEvent;
use mooring_vault::{LockReason, Vault, VaultState};
use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Longest password accepted over IPC (bytes); the vault enforces the minimum.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Static facts about the running build.
#[derive(Debug, Serialize)]
pub struct AppInfo {
    name: &'static str,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    debug: bool,
}

/// Round-trip smoke test used by the UI on startup.
#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        name: "Mooring",
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        debug: cfg!(debug_assertions),
    }
}

/// What the UI needs to decide between onboarding, unlock screen and main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    /// No vault yet: show onboarding.
    Missing,
    /// Header present, DEK not in memory.
    Locked,
    /// Ready.
    Unlocked,
}

/// Wrap a password from IPC, refusing absurd sizes before any key derivation.
pub fn password_from_ipc(password: String) -> IpcResult<SecretString> {
    let password = SecretString::from(password);
    if secrecy::ExposeSecret::expose_secret(&password).len() > MAX_PASSWORD_BYTES {
        return Err(IpcError::new("vault.password_too_long", "password longer than 1024 bytes"));
    }
    Ok(password)
}

/// Current vault status.
pub fn status(state: &AppState) -> IpcResult<VaultStatus> {
    let guard = state.vault()?;
    Ok(match guard.as_ref().map(Vault::state) {
        None => VaultStatus::Missing,
        Some(VaultState::Locked) => VaultStatus::Locked,
        Some(VaultState::Unlocked) => VaultStatus::Unlocked,
    })
}

/// Create a new vault. Refused when one already exists.
pub fn create(state: &AppState, password: SecretString) -> IpcResult<VaultStatus> {
    let mut guard = state.vault()?;
    if guard.is_some() {
        return Err(IpcError::new("vault.exists", "a vault already exists"));
    }
    let vault = Vault::create(&password, state.settings.kdf.params())?;
    state.save_header(&vault)?;
    *guard = Some(vault);
    drop(guard);
    state.audit(AuditEvent::VaultCreated);
    Ok(VaultStatus::Unlocked)
}

/// Unlock with the master password. A v1 header is upgraded and persisted; if that write fails
/// the vault is locked again (review L1). The store is bound to the vault id on first use.
pub fn unlock(state: &AppState, password: SecretString) -> IpcResult<VaultStatus> {
    let mut guard = state.vault()?;
    let vault = guard.as_mut().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
    vault.unlock_persisting(&password, |header| {
        state.save_header_bytes(header).map_err(IpcError::from)
    })?;
    drop(guard);
    // The current header has just proven it unlocks: the backup is no longer needed (L2).
    state.drop_header_backup();
    // Bind the store now (A1-QA-2: only after unlock, when a v1 header has its real id) so a
    // different vault's database is reported here. On failure the vault is locked again.
    if let Err(e) = state.with_ready(|_, _| Ok(())) {
        if let Some(v) = state.vault()?.as_mut() {
            v.lock();
        }
        return Err(e);
    }
    state.audit(AuditEvent::VaultUnlocked);
    Ok(VaultStatus::Unlocked)
}

/// Wipe the key from memory. Open sessions survive (ADR-0006).
pub fn lock(state: &AppState, reason: Option<&str>) -> IpcResult<VaultStatus> {
    // Unknown or missing reasons from the WebView are recorded as a user lock.
    let reason = reason.and_then(LockReason::parse).unwrap_or(LockReason::User);
    let mut guard = state.vault()?;
    let Some(v) = guard.as_mut() else {
        return Ok(VaultStatus::Missing);
    };
    let reason = v.lock_with_reason(reason);
    drop(guard);
    state.audit(AuditEvent::VaultLocked { reason: reason.as_str().to_owned() });
    Ok(VaultStatus::Locked)
}

/// Change the master password: re-wrap under a freshly calibrated KDF, persist durably, drop
/// the old-password backup. `change_password` clears any keyring wrap (review ruling c);
/// keyring commands are not wired in A1, so there is no keyring item to delete yet.
pub fn change_password(
    state: &AppState,
    current: SecretString,
    next: SecretString,
) -> IpcResult<VaultStatus> {
    let params = state.settings.kdf.params();
    let mut guard = state.vault()?;
    let vault = guard.as_mut().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
    let was = vault.state();
    let before = vault.header().clone();
    if let Err(e) = vault.change_password(&current, &next, params) {
        if was == VaultState::Locked {
            vault.lock();
        }
        return Err(e.into());
    }
    if let Err(e) = state.save_header(vault) {
        // Keep memory and disk in agreement: go back to the persisted header, locked.
        *vault = Vault::from_header(before);
        return Err(e.into());
    }
    drop(guard);
    state.drop_header_backup();
    state.audit(AuditEvent::PasswordChanged);
    Ok(VaultStatus::Unlocked)
}

// ------------------------------------------------------------------ Tauri wrappers

/// `vault_status()`.
#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> IpcResult<VaultStatus> {
    status(&state)
}

/// `vault_create({ password })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn vault_create(state: State<'_, AppState>, password: String) -> IpcResult<VaultStatus> {
    let password = password_from_ipc(password)?;
    create(&state, password)
}

/// `vault_unlock({ password })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn vault_unlock(state: State<'_, AppState>, password: String) -> IpcResult<VaultStatus> {
    let password = password_from_ipc(password)?;
    unlock(&state, password)
}

/// `vault_lock({ reason })`.
#[tauri::command(rename_all = "camelCase")]
pub fn vault_lock(state: State<'_, AppState>, reason: Option<String>) -> IpcResult<VaultStatus> {
    if reason.as_ref().is_some_and(|r| r.len() > 32) {
        return Err(IpcError::invalid("reason", "too long"));
    }
    lock(&state, reason.as_deref())
}

/// `vault_change_password({ current, next })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn vault_change_password(
    state: State<'_, AppState>,
    current: String,
    next: String,
) -> IpcResult<VaultStatus> {
    let current = password_from_ipc(current)?;
    let next = password_from_ipc(next)?;
    change_password(&state, current, next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    #[test]
    fn lifecycle_and_audit() {
        let f = empty();
        assert_eq!(status(&f.state).expect("s"), VaultStatus::Missing);
        assert_eq!(lock(&f.state, None).expect("no vault"), VaultStatus::Missing);
        assert_eq!(create(&f.state, pw("short")).expect_err("weak").code, "vault.weak_password");
        create(&f.state, pw(MASTER)).expect("create");
        assert_eq!(create(&f.state, pw(MASTER)).expect_err("dup").code, "vault.exists");
        assert_eq!(lock(&f.state, Some("idle")).expect("lock"), VaultStatus::Locked);
        assert_eq!(unlock(&f.state, pw("wrong password!!")).expect_err("x").code, "vault.unlock");
        assert_eq!(status(&f.state).expect("s"), VaultStatus::Locked);
        assert_eq!(unlock(&f.state, pw(MASTER)).expect("unlock"), VaultStatus::Unlocked);
        assert_eq!(audit_events(&f.state), ["vault_created", "vault_locked", "vault_unlocked"]);
    }

    #[test]
    fn oversized_password_is_refused_before_kdf() {
        let e = password_from_ipc("x".repeat(MAX_PASSWORD_BYTES + 1)).expect_err("long");
        assert_eq!(e.code, "vault.password_too_long");
        assert!(password_from_ipc("x".repeat(MAX_PASSWORD_BYTES)).is_ok());
    }

    #[test]
    fn state_reloads_locked_from_disk() {
        let f = unlocked();
        let again = AppState::new(f.dir.path().to_path_buf(), settings(f.clipboard.clone()))
            .expect("reload");
        assert_eq!(status(&again).expect("s"), VaultStatus::Locked);
        // The previous instance still holds the store; the reload opens a second connection.
        assert_eq!(unlock(&again, pw(MASTER)).expect("unlock"), VaultStatus::Unlocked);
    }

    #[test]
    fn change_password_persists_and_drops_backup() {
        let f = unlocked();
        let next = "another test-only pw";
        assert_eq!(
            change_password(&f.state, pw("wrong password!!"), pw(next)).expect_err("cur").code,
            "vault.unlock"
        );
        assert_eq!(
            change_password(&f.state, pw(MASTER), pw("short")).expect_err("weak").code,
            "vault.weak_password"
        );
        change_password(&f.state, pw(MASTER), pw(next)).expect("change");
        assert!(!f.dir.path().join(AppState::HEADER_BACKUP).exists(), "old-password header gone");
        lock(&f.state, None).expect("lock");
        assert_eq!(unlock(&f.state, pw(MASTER)).expect_err("old").code, "vault.unlock");
        unlock(&f.state, pw(next)).expect("new password unlocks");
        // A fresh process reads the new header from disk.
        let again = AppState::new(f.dir.path().to_path_buf(), settings(f.clipboard.clone()))
            .expect("reload");
        unlock(&again, pw(next)).expect("persisted");
        assert!(audit_events(&f.state).contains(&"password_changed".to_owned()));
    }

    #[test]
    fn change_password_on_locked_vault_stays_locked_on_error() {
        let f = unlocked();
        lock(&f.state, None).expect("lock");
        let e = change_password(&f.state, pw(MASTER), pw("short")).expect_err("weak");
        assert_eq!(e.code, "vault.weak_password");
        assert_eq!(status(&f.state).expect("s"), VaultStatus::Locked);
    }

    #[test]
    fn unlock_reports_a_foreign_store() {
        let f = unlocked();
        // Bind the store, then swap in a different vault header.
        f.state.with_ready(|_, _| Ok(())).expect("bind");
        let other = Vault::create(&pw(MASTER), mooring_vault::KdfParams::TEST).expect("other");
        f.state.save_header(&other).expect("save");
        let again = AppState::new(f.dir.path().to_path_buf(), settings(f.clipboard.clone()))
            .expect("reload");
        let e = unlock(&again, pw(MASTER)).expect_err("mismatch");
        assert_eq!(e.code, "store.vault_mismatch");
        assert_eq!(status(&again).expect("s"), VaultStatus::Locked, "re-locked on bind failure");
    }

    #[test]
    fn store_is_not_bound_before_unlock() {
        // A1-QA-2: a v1 header reports a nil id until its first password unlock, so nothing may
        // bind the store while the vault is locked.
        let f = empty();
        create(&f.state, pw(MASTER)).expect("create");
        lock(&f.state, None).expect("lock");
        assert_eq!(crate::commands::tree::list(&f.state).expect_err("locked").code, "vault.locked");
        let bound = f.state.store.lock().expect("lock").store.as_ref().expect("s").vault_id();
        assert_eq!(bound.expect("q"), None, "locked commands never bind");
        unlock(&f.state, pw(MASTER)).expect("unlock");
        let id = f.state.vault().expect("v").as_ref().expect("v").vault_id().to_string();
        let bound = f.state.store.lock().expect("lock").store.as_ref().expect("s").vault_id();
        assert_eq!(bound.expect("q"), Some(id), "bound at unlock");
    }
}
