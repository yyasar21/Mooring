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
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub debug: bool,
    /// ADR-0021: the `Mooring Data` folder in portable mode, else `null` (About and
    /// Settings → Updates show "Portable build — data in <path>").
    pub portable_data_dir: Option<String>,
}

/// The facts for `state` (pure).
pub fn info(state: &AppState) -> AppInfo {
    AppInfo {
        name: "Mooring",
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        debug: cfg!(debug_assertions),
        portable_data_dir: state.portable_root.as_ref().map(|p| p.display().to_string()),
    }
}

/// Round-trip smoke test used by the UI on startup.
#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    info(&state)
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
    after_unlock(state)?;
    state.audit(AuditEvent::VaultUnlocked);
    // ADR-0022: a stale (suspended) or legacy keyring wrap goes now that the KEK is known.
    super::vault_biometric::on_password_unlock(state, &password);
    Ok(VaultStatus::Unlocked)
}

/// What every successful unlock does after the DEK is in memory (password or biometric,
/// ADR-0022): drop the header backup, bind the store, re-seal legacy secrets, sweep web
/// stores, show the hidden windows, start the vCenter schedulers. On a bind failure the
/// vault is locked again and the error returned.
pub fn after_unlock(state: &AppState) -> IpcResult<()> {
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
    reseal_legacy(state);
    // Review 5 L-30: persistent web stores without a persistent web connection go.
    crate::web::sweep::orphan_stores(state);
    // ADR-0013: web and detached windows come back.
    state.lock_observer.notify(false);
    // ADR-0015: scheduled vCenter refreshes run only while unlocked.
    crate::scheduler::start_all(&crate::vsphere_sync::VsCtx::of(state));
    Ok(())
}

/// Re-seal secrets migrated from schema v2 under their ADR-0009 names (ADR-0009 §4). Runs on
/// every unlock and is a no-op once done. A failure never fails or re-locks the unlock: it is
/// logged, the store is unchanged (one transaction), and the alias table keeps the legacy
/// secrets usable until a later unlock succeeds.
fn reseal_legacy(state: &AppState) {
    // StoreError's Display names the failing layer (SQLite, vault tag, corrupt row), never a
    // secret value.
    match state.with_ready(|vault, store| Ok(store.reseal_legacy(vault))) {
        Ok(Ok(0)) => {}
        Ok(Ok(count)) => {
            tracing::info!(count, "legacy credentials resealed");
            state.audit(AuditEvent::CredentialResealed { count: count as u64 });
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "legacy credential reseal failed; legacy reads stay available");
        }
        Err(e) => tracing::warn!(code = e.code, "legacy credential reseal skipped"),
    }
}

/// Wipe the key from memory and clear a copied password still on the clipboard (review 2,
/// M-1). Open sessions and loopback forwards survive (ADR-0006); `external` forwards are
/// closed (review 4 M-10).
pub fn lock(state: &AppState, reason: Option<&str>) -> IpcResult<VaultStatus> {
    state.clear_pending_clipboard();
    // Review 4 B-4: local paths picked before the lock cannot be used after it.
    state.picks.clear();
    // ADR-0019 §3: a previewed import plan (possibly holding plaintext secrets) does not
    // outlive the lock.
    state.import_plans.clear();
    // Review 7 L-43: a confirmed directory sign-in does not outlive the unlocked session.
    state.ldap_binds.clear();
    // ADR-0023 §2: a decrypted import document does not outlive the lock.
    state.imports.clear();
    // Review 4 M-10: no LAN-exposed listener keeps running behind a locked UI.
    crate::commands::forward::close_external(state);
    // ADR-0014 K4: Kubernetes tokens live in memory only; every cluster, exec shell, log
    // stream and pod forward ends with the lock.
    crate::kube_sessions::close_all(&state.sessions);
    // Unknown or missing reasons from the WebView are recorded as a user lock.
    let reason = reason.and_then(LockReason::parse).unwrap_or(LockReason::User);
    let mut guard = state.vault()?;
    let Some(v) = guard.as_mut() else {
        return Ok(VaultStatus::Missing);
    };
    let reason = v.lock_with_reason(reason);
    drop(guard);
    // ADR-0016 E2: OIDC windows close; Vault tokens are revoked (ours) or forgotten. Review 6b
    // L-34 (a): only **after** the key wipe, so a login that reads the bumped epoch can no
    // longer open its material from the vault (`on_lock` needs nothing from the vault).
    state.secrets.on_lock();
    state.audit(AuditEvent::VaultLocked { reason: reason.as_str().to_owned() });
    // ADR-0015: stop the vCenter schedulers and log their sessions out.
    state.vsphere.on_lock();
    // ADR-0013: no web or detached window stays visible outside the lock screen.
    state.lock_observer.notify(true);
    Ok(VaultStatus::Locked)
}

/// Change the master password: re-wrap under a freshly calibrated KDF, persist durably, drop
/// the old-password backup. `change_password` clears any keyring wrap (review ruling c); the
/// OS biometric item follows with reason `password_changed` (ADR-0022 §2).
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
    let had_wrap = before.keyring_enabled();
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
    super::vault_biometric::on_password_changed(state, had_wrap);
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

    /// ADR-0021: `portableDataDir` is the `Mooring Data` path in portable mode, else null.
    #[test]
    fn app_info_reports_the_portable_data_dir() {
        let f = empty();
        let v = serde_json::to_value(super::info(&f.state)).expect("json");
        assert_eq!(v["portableDataDir"], serde_json::Value::Null);
        assert_eq!(v["name"], "Mooring");
        let p = empty_portable();
        let root = p.dir.path().join("Mooring Data");
        let v = serde_json::to_value(super::info(&p.state)).expect("json");
        assert_eq!(v["portableDataDir"], root.display().to_string());
        assert_eq!(p.state.data_dir, root.join("data"));
        assert_eq!(p.state.cache_dir, root.join("cache"));
    }

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
        let again = AppState::new(dirs(f.dir.path()), settings(f.clipboard.clone()))
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
        let again = AppState::new(dirs(f.dir.path()), settings(f.clipboard.clone()))
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
        let again = AppState::new(dirs(f.dir.path()), settings(f.clipboard.clone()))
            .expect("reload");
        let e = unlock(&again, pw(MASTER)).expect_err("mismatch");
        assert_eq!(e.code, "store.vault_mismatch");
        assert_eq!(status(&again).expect("s"), VaultStatus::Locked, "re-locked on bind failure");
    }

    /// A data dir holding a vault header and a schema-v2 database whose secrets were sealed by
    /// `sealer` (the vault itself, or another one to make the reseal fail).
    fn v2_state(sealer: Option<&Vault>) -> (Fixture, mooring_store::testing::V2Credentials) {
        let dir = tempfile::tempdir().expect("tempdir");
        let v = Vault::create(&pw(MASTER), mooring_vault::KdfParams::TEST).expect("vault");
        std::fs::write(
            dir.path().join(AppState::HEADER_FILE),
            v.header().to_bytes().expect("header"),
        )
        .expect("write header");
        let db = dir.path().join(AppState::DB_FILE);
        let ids = mooring_store::testing::write_v2_database(&db, sealer.unwrap_or(&v))
            .expect("v2 database");
        let clipboard = std::sync::Arc::new(crate::clipboard::MemoryClipboard::default());
        let state = AppState::new(dirs(dir.path()), settings(clipboard.clone()))
            .expect("state migrates v2");
        (Fixture { dir, state, clipboard }, ids)
    }

    #[test]
    fn unlock_reseals_legacy_credentials_once() {
        use mooring_core::credential::testdata::CERT_PEM;
        use mooring_core::CredentialFields;
        use mooring_store::testing::{legacy_secret_rows, LEGACY_PASSPHRASE, LEGACY_PW};
        use mooring_store::SecretName;

        let (f, ids) = v2_state(None);
        let db = f.dir.path().join(AppState::DB_FILE);
        assert_eq!(legacy_secret_rows(&db).expect("rows"), 5, "pw 1 + key 2 + cert 2");
        assert_eq!(unlock(&f.state, pw(MASTER)).expect("unlock"), VaultStatus::Unlocked);
        assert_eq!(legacy_secret_rows(&db).expect("rows"), 0, "legacy names gone");
        f.state
            .with_ready(|v, s| {
                assert!(!s.reseal_pending()?);
                assert_eq!(s.open_secret(v, ids.pw, SecretName::Password)?.as_slice(), LEGACY_PW);
                assert_eq!(
                    s.open_secret(v, ids.key, SecretName::Passphrase)?.as_slice(),
                    LEGACY_PASSPHRASE
                );
                let cert = s.get_credential(ids.cert)?;
                let CredentialFields::X509(x) = &cert.fields else { panic!("kind") };
                assert_eq!(x.cert_pem, CERT_PEM, "placeholder replaced by the real PEM");
                assert_eq!(cert.secret_names, [SecretName::KeyPem]);
                Ok(())
            })
            .expect("read back");
        let resealed = |s: &AppState| {
            let text = std::fs::read_to_string(s.data_dir.join(AppState::AUDIT_FILE)).expect("a");
            text.lines().filter(|l| l.contains(r#""event":"credential_resealed""#)).count()
        };
        assert_eq!(resealed(&f.state), 1);
        let audit = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("a");
        assert!(audit.contains(r#""count":3"#), "count recorded");
        // second unlock reseals nothing and writes no second entry
        lock(&f.state, None).expect("lock");
        unlock(&f.state, pw(MASTER)).expect("again");
        assert_eq!(resealed(&f.state), 1, "no entry for a reseal of 0");
        assert_eq!(f.state.with_ready(|v, s| Ok(s.reseal_legacy(v)?)).expect("noop"), 0);
    }

    #[test]
    fn reseal_failure_does_not_fail_unlock() {
        use mooring_store::testing::legacy_secret_rows;
        // Secrets sealed by a different vault: the reseal cannot open them.
        let other = Vault::create(&pw(MASTER), mooring_vault::KdfParams::TEST).expect("other");
        let (f, _) = v2_state(Some(&other));
        assert_eq!(unlock(&f.state, pw(MASTER)).expect("unlock"), VaultStatus::Unlocked);
        assert_eq!(status(&f.state).expect("s"), VaultStatus::Unlocked, "not re-locked");
        let db = f.dir.path().join(AppState::DB_FILE);
        assert_eq!(legacy_secret_rows(&db).expect("rows"), 5, "transaction rolled back");
        assert!(f.state.with_ready(|_, s| Ok(s.reseal_pending()?)).expect("flag"));
        assert!(!audit_events(&f.state).contains(&"credential_resealed".to_owned()));
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
