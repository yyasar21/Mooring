//! Biometric unlock commands (ADR-0022 §2): `biometric_status`, `biometric_enroll`,
//! `biometric_unlock`, `biometric_disable`.
//!
//! The wrap of the DEK lives in the header (`keyring_wrap`, ADR-0006); the wrap key lives
//! behind the OS gesture ([`crate::biometric`]). Two `app.*` settings complete the picture:
//! `app.biometric` (the enrolment marker: a header wrap without it is a legacy ADR-0006
//! keyring wrap and is dropped with `keyring.removed`) and `app.biometric_suspended` (the
//! auto-disable reason, shown by the UI until the next enrolment or disable). No secret
//! crosses IPC: the master password comes in for enrol / disable, nothing comes out.

use std::time::Instant;

use mooring_audit::AuditEvent;
use mooring_vault::{Vault, VaultError, VaultState};
use secrecy::SecretString;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::biometric::{Adapter, BioError, Prefetched, Unavailable};
use crate::commands::vault::{password_from_ipc, VaultStatus};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Enrolment marker (`{ "platform": "macos" }`).
pub const KEY_ENROLLED: &str = "app.biometric";
/// Auto-disable reason (`failed_attempts` | `password_changed` | `biometry_changed` |
/// `vault_rotated`).
pub const KEY_SUSPENDED: &str = "app.biometric_suspended";

/// `biometric_status()` (passive; works while locked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatus {
    /// The store can be used on this machine and build.
    pub available: bool,
    /// Enrolled, not suspended, usable for `biometric_unlock`.
    pub enabled: bool,
    /// `macos` | `windows` | `linux`.
    pub platform: &'static str,
    /// `Touch ID` | `Windows Hello` | `null`.
    pub label: Option<&'static str>,
    /// `ok` | `no_acl` | `unsigned_build` | `keychain_unavailable` | `not_enrolled` |
    /// `suspended`.
    pub reason: &'static str,
    /// The auto-disable reason while `reason == "suspended"` (ADR-0022 §2).
    pub suspended_reason: Option<String>,
}

fn unavailable(u: Unavailable) -> IpcError {
    let text = match u {
        Unavailable::NoAcl => "biometric unlock is not offered on this operating system",
        Unavailable::UnsignedBuild => "Touch ID needs a signed build",
        Unavailable::KeychainUnavail => "the OS biometric store is not available",
    };
    IpcError::new("biometric.unavailable", format!("{text} ({})", u.reason()))
}

/// The error of a failed prompt (`biometric.cancelled` / `biometric.failed` / unavailable).
fn prompt_error(e: Option<BioError>) -> IpcError {
    match e {
        Some(BioError::Cancelled) => {
            IpcError::new("biometric.cancelled", "the biometric prompt was cancelled")
        }
        Some(BioError::Unavailable(u)) => unavailable(u),
        _ => IpcError::new("biometric.failed", "the biometric check failed"),
    }
}

/// Read an `app.*` setting through the store slot (no vault binding: works while locked).
fn setting(state: &AppState, key: &str) -> Option<String> {
    let slot = state.store.lock().ok()?;
    slot.store.as_ref()?.app_setting(key).ok().flatten()
}

fn write_setting(state: &AppState, key: &str, value: Option<&str>) {
    let Ok(slot) = state.store.lock() else { return };
    let Some(store) = slot.store.as_ref() else { return };
    let r = match value {
        Some(v) => store.set_app_setting(key, v),
        None => store.set_app_setting(key, ""),
    };
    if let Err(e) = r {
        tracing::warn!(key, error = %e, "biometric setting not written");
    }
}

fn enrolled_marker(state: &AppState) -> bool {
    setting(state, KEY_ENROLLED).is_some_and(|v| !v.is_empty())
}

/// The auto-disable reason on record, if any.
pub fn suspended_reason(state: &AppState) -> Option<String> {
    setting(state, KEY_SUSPENDED).filter(|v| !v.is_empty())
}

fn header_has_wrap(state: &AppState) -> IpcResult<bool> {
    Ok(state.vault()?.as_ref().is_some_and(|v| v.header().keyring_enabled()))
}

/// `biometric_status`.
pub fn status(state: &AppState) -> IpcResult<BiometricStatus> {
    let store = state.biometric.store();
    let availability = store.available();
    let wrap = header_has_wrap(state)?;
    let suspended = suspended_reason(state);
    let enrolled = wrap && enrolled_marker(state);
    let (reason, enabled) = match (&availability, &suspended, enrolled) {
        (Err(u), _, _) => (u.reason(), false),
        (Ok(()), Some(_), _) => ("suspended", false),
        (Ok(()), None, true) => ("ok", true),
        (Ok(()), None, false) => ("not_enrolled", false),
    };
    Ok(BiometricStatus {
        available: availability.is_ok(),
        enabled,
        platform: store.platform(),
        label: store.label(),
        reason,
        suspended_reason: suspended,
    })
}

fn require_available(state: &AppState) -> IpcResult<()> {
    state.biometric.store().available().map_err(unavailable)
}

/// `biometric_enroll({ password })`: unlocked vault + master password; replaces any earlier
/// enrolment (the re-enrol flow after a suspension). Refused while sync is configured
/// (ADR-0017 §2: the header object must not carry a wrap).
pub fn enroll(state: &AppState, password: SecretString) -> IpcResult<BiometricStatus> {
    state.with_ready(|_, _| Ok(()))?;
    require_available(state)?;
    if super::sync_config::load(&state.ready())?.is_some() {
        return Err(IpcError::new(
            "biometric.sync_enabled",
            "disable vault sync before enabling biometric unlock",
        ));
    }
    let store = state.biometric.store();
    let adapter = Adapter::new(store);
    let mut guard = state.vault()?;
    let vault = guard.as_mut().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
    let before = vault.header().clone();
    if let Err(e) = vault.enable_keyring_unlock(&adapter, &password) {
        return Err(match e {
            VaultError::Keyring(_) | VaultError::KeyringUnavailable => {
                prompt_error(adapter.last_error())
            }
            other => other.into(),
        });
    }
    if let Err(e) = state.save_header(vault) {
        // Memory and disk stay in agreement: the item goes, the old header comes back.
        if let Err(d) = store.delete(vault.vault_id()) {
            tracing::warn!(?d, "biometric item not removed after a failed header write");
        }
        *vault = Vault::from_header(before);
        return Err(e.into());
    }
    drop(guard);
    state.drop_header_backup();
    write_setting(state, KEY_ENROLLED, Some(&format!(r#"{{"platform":"{}"}}"#, store.platform())));
    write_setting(state, KEY_SUSPENDED, None);
    state.biometric.reset_failures();
    state.audit(AuditEvent::BiometricEnabled { platform: store.platform().to_owned() });
    status(state)
}

/// Auto-disable without the password (ADR-0022 §2): the OS item or key is deleted at once,
/// the reason is recorded, the stale header wrap is cleared on the next password unlock.
pub fn suspend(state: &AppState, reason: &str) {
    let id = state.vault().ok().and_then(|g| g.as_ref().map(Vault::vault_id));
    if let Some(id) = id {
        if let Err(e) = state.biometric.store().delete(id) {
            tracing::warn!(?e, reason, "biometric item not removed on suspend");
        }
    }
    write_setting(state, KEY_SUSPENDED, Some(reason));
    state.biometric.reset_failures();
    tracing::warn!(reason, "biometric unlock suspended");
    state.audit(AuditEvent::BiometricSuspended { reason: reason.to_owned() });
}

/// `biometric_unlock()` at `now` (the clock of the failure window). The OS prompt runs
/// without the vault mutex held ([`Prefetched`]).
pub fn unlock_at(state: &AppState, now: Instant) -> IpcResult<VaultStatus> {
    require_available(state)?;
    if let Some(reason) = suspended_reason(state) {
        return Err(IpcError::new(
            "biometric.suspended",
            format!("biometric unlock was switched off ({reason}); unlock with the password"),
        ));
    }
    if !header_has_wrap(state)? || !enrolled_marker(state) {
        return Err(IpcError::new("biometric.not_enrolled", "biometric unlock is not enrolled"));
    }
    let id = {
        let guard = state.vault()?;
        let vault = guard.as_ref().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
        if vault.state() == VaultState::Unlocked {
            return Ok(VaultStatus::Unlocked);
        }
        vault.vault_id()
    };
    let store = state.biometric.store();
    let platform = store.platform().to_owned();
    let outcome = match store.get(id) {
        Ok(key) => {
            let mut guard = state.vault()?;
            let vault =
                guard.as_mut().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
            if vault.vault_id() != id {
                return Err(IpcError::new("biometric.not_enrolled", "the vault changed; try again"));
            }
            if vault.state() == VaultState::Unlocked {
                return Ok(VaultStatus::Unlocked);
            }
            // A key that does not open the wrap (another enrolment, a KSP whose signature is
            // not deterministic) counts as a failed attempt.
            vault.unlock_with_keyring(&Prefetched(key)).map_err(|_| BioError::Failed)
        }
        Err(e) => Err(e),
    };
    match outcome {
        Ok(()) => {
            super::vault::after_unlock(state)?;
            state.biometric.reset_failures();
            state.audit(AuditEvent::BiometricUnlocked { platform });
            Ok(VaultStatus::Unlocked)
        }
        Err(e) => {
            state.audit(AuditEvent::BiometricFailed { platform, reason: e.reason().to_owned() });
            match e {
                BioError::NotFound => {
                    suspend(state, "biometry_changed");
                    Err(IpcError::new(
                        "biometric.suspended",
                        "the biometric enrolment changed; unlock with the password and enrol again",
                    ))
                }
                BioError::Unavailable(u) => Err(unavailable(u)),
                BioError::Cancelled | BioError::Failed => {
                    if state.biometric.record_failure(now) {
                        suspend(state, "failed_attempts");
                        return Err(IpcError::new(
                            "biometric.suspended",
                            "too many failed attempts; unlock with the password",
                        ));
                    }
                    Err(prompt_error(Some(e)))
                }
            }
        }
    }
}

/// `biometric_disable({ password })`: deletes the OS item and clears the wrap.
pub fn disable(state: &AppState, password: SecretString) -> IpcResult<BiometricStatus> {
    let adapter = Adapter::new(state.biometric.store());
    let mut guard = state.vault()?;
    let vault = guard.as_mut().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
    let was = vault.state();
    if vault.header().keyring_enabled() {
        if let Err(e) = vault.disable_keyring_unlock(&adapter, &password) {
            if was == VaultState::Locked {
                vault.lock();
            }
            return Err(match e {
                VaultError::Keyring(_) => prompt_error(adapter.last_error()),
                other => other.into(),
            });
        }
        state.save_header(vault)?;
    } else {
        // Nothing to clear in the header; still prove the password (ADR-0006).
        let before = vault.state();
        vault.unlock(&password)?;
        if before == VaultState::Locked {
            vault.lock();
        }
        if let Err(e) = state.biometric.store().delete(vault.vault_id()) {
            tracing::warn!(?e, "biometric item not removed on disable");
        }
    }
    drop(guard);
    state.drop_header_backup();
    write_setting(state, KEY_ENROLLED, None);
    write_setting(state, KEY_SUSPENDED, None);
    state.biometric.reset_failures();
    state.audit(AuditEvent::BiometricDisabled);
    status(state)
}

/// After a successful **password** unlock (ADR-0022 §2): a stale wrap left by a suspension is
/// cleared; a wrap without the enrolment marker is a legacy ADR-0006 keyring wrap and goes
/// with `keyring.removed` (owner decision 25). The OS item delete is idempotent.
pub fn on_password_unlock(state: &AppState, password: &SecretString) {
    let Ok(wrap) = header_has_wrap(state) else { return };
    if !wrap {
        return;
    }
    let legacy = !enrolled_marker(state);
    let suspended = suspended_reason(state).is_some();
    if !legacy && !suspended {
        return;
    }
    let adapter = Adapter::new(state.biometric.store());
    let Ok(mut guard) = state.vault() else { return };
    let Some(vault) = guard.as_mut() else { return };
    if let Err(e) = vault.disable_keyring_unlock(&adapter, password) {
        tracing::warn!(error = %e, "stale biometric wrap not cleared");
        return;
    }
    if let Err(e) = state.save_header(vault) {
        tracing::warn!(error = %e, "header without the stale wrap not persisted");
        return;
    }
    drop(guard);
    if legacy {
        write_setting(state, KEY_ENROLLED, None);
        state.audit(AuditEvent::KeyringRemoved);
        tracing::info!("legacy keyring wrap removed");
    } else {
        tracing::info!("stale biometric wrap cleared after a suspension");
    }
}

/// After a password change (ADR-0022 §2 `password_changed`): the wrap is gone from the
/// header already; the OS item follows and the reason is recorded.
pub fn on_password_changed(state: &AppState, had_wrap: bool) {
    if had_wrap {
        suspend(state, "password_changed");
    }
}

/// The vault id is about to change (sync join, foreign `replace` import; ADR-0022 §2
/// `vault_rotated`): an enrolment bound to the current id is suspended and its OS item goes.
pub fn on_vault_rotated(state: &AppState) {
    if enrolled_marker(state) && suspended_reason(state).is_none() {
        suspend(state, "vault_rotated");
    }
}

// ------------------------------------------------------------------ Tauri wrappers

/// `biometric_status()`.
#[tauri::command]
pub fn biometric_status(state: State<'_, AppState>) -> IpcResult<BiometricStatus> {
    status(&state)
}

/// `biometric_enroll({ password })`: the OS prompt runs on the blocking pool.
#[tauri::command(rename_all = "camelCase")]
pub async fn biometric_enroll(app: AppHandle, password: String) -> IpcResult<BiometricStatus> {
    let password = password_from_ipc(password)?;
    super::off_thread(app, move |app| enroll(&app.state::<AppState>(), password)).await
}

/// `biometric_unlock()`: the OS prompt runs on the blocking pool.
#[tauri::command]
pub async fn biometric_unlock(app: AppHandle) -> IpcResult<VaultStatus> {
    super::off_thread(app, move |app| unlock_at(&app.state::<AppState>(), Instant::now())).await
}

/// `biometric_disable({ password })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn biometric_disable(app: AppHandle, password: String) -> IpcResult<BiometricStatus> {
    let password = password_from_ipc(password)?;
    super::off_thread(app, move |app| disable(&app.state::<AppState>(), password)).await
}

#[cfg(test)]
#[path = "vault_biometric_tests.rs"]
mod tests;
