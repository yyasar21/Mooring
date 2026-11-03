//! IPC commands. Every function here is an attack surface: validate, never leak.

use mooring_audit::AuditEvent;
use mooring_vault::{KdfParams, LockReason, Vault, VaultState};
use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use crate::state::AppState;

/// Error shape sent to the WebView. `code` is stable for the UI; `message` is user-facing and
/// never contains secret material (vault errors are built that way by construction).
#[derive(Debug, Serialize)]
pub struct IpcError {
    code: &'static str,
    message: String,
}

impl IpcError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl From<mooring_vault::VaultError> for IpcError {
    fn from(e: mooring_vault::VaultError) -> Self {
        use mooring_vault::VaultError as V;
        let code = match e {
            V::Unlock => "vault.unlock",
            V::Tampered => "vault.tampered",
            V::Locked => "vault.locked",
            V::Format(_) => "vault.format",
            V::KdfParams(_) => "vault.kdf",
            V::WeakPassword { .. } => "vault.weak_password",
            V::KeyringUnavailable => "vault.keyring_unavailable",
            V::Keyring(_) => "vault.keyring",
            V::Export(_) => "vault.export",
            V::Seal => "vault.seal",
        };
        Self::new(code, e.to_string())
    }
}

impl From<crate::state::StateError> for IpcError {
    fn from(e: crate::state::StateError) -> Self {
        tracing::error!(error = %e, "state error");
        Self::new("state.io", "could not persist application state")
    }
}

type IpcResult<T> = Result<T, IpcError>;

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
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    /// No vault yet: show onboarding.
    Missing,
    /// Header present, DEK not in memory.
    Locked,
    /// Ready.
    Unlocked,
}

/// Current vault status.
#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> IpcResult<VaultStatus> {
    let guard =
        state.vault.lock().map_err(|_| IpcError::new("state.poisoned", "internal error"))?;
    Ok(match guard.as_ref().map(Vault::state) {
        None => VaultStatus::Missing,
        Some(VaultState::Locked) => VaultStatus::Locked,
        Some(VaultState::Unlocked) => VaultStatus::Unlocked,
    })
}

fn password_from_ipc(password: String) -> IpcResult<SecretString> {
    // Length is checked by the vault; here we only refuse absurd input before deriving a key.
    if password.len() > 1024 {
        return Err(IpcError::new("vault.password_too_long", "password longer than 1024 bytes"));
    }
    Ok(SecretString::from(password))
}

/// Create a new vault. Refused when one already exists.
#[tauri::command]
pub fn vault_create(state: State<'_, AppState>, password: String) -> IpcResult<VaultStatus> {
    let password = password_from_ipc(password)?;
    let mut guard =
        state.vault.lock().map_err(|_| IpcError::new("state.poisoned", "internal error"))?;
    if guard.is_some() {
        return Err(IpcError::new("vault.exists", "a vault already exists"));
    }
    let vault = Vault::create(&password, KdfParams::DEFAULT)?;
    state.save_header(&vault)?;
    *guard = Some(vault);
    audit(&state, AuditEvent::VaultCreated);
    Ok(VaultStatus::Unlocked)
}

/// Unlock with the master password.
#[tauri::command]
pub fn vault_unlock(state: State<'_, AppState>, password: String) -> IpcResult<VaultStatus> {
    let password = password_from_ipc(password)?;
    let mut guard =
        state.vault.lock().map_err(|_| IpcError::new("state.poisoned", "internal error"))?;
    let vault = guard.as_mut().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
    // A v1 -> v2 upgrade happens in memory during unlock (ADR-0006) and is persisted here. If
    // that write fails the vault is locked again with its v1 header (review L1).
    vault.unlock_persisting(&password, |header| {
        state.save_header_bytes(header).map_err(IpcError::from)
    })?;
    audit(&state, AuditEvent::VaultUnlocked);
    Ok(VaultStatus::Unlocked)
}

/// Wipe the key from memory.
#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>, reason: Option<String>) -> IpcResult<VaultStatus> {
    // Unknown or missing reasons from the WebView are recorded as a user lock.
    let reason = reason.as_deref().and_then(LockReason::parse).unwrap_or(LockReason::User);
    let mut guard =
        state.vault.lock().map_err(|_| IpcError::new("state.poisoned", "internal error"))?;
    if let Some(v) = guard.as_mut() {
        let reason = v.lock_with_reason(reason);
        audit(&state, AuditEvent::VaultLocked { reason: reason.as_str().to_owned() });
        Ok(VaultStatus::Locked)
    } else {
        Ok(VaultStatus::Missing)
    }
}

fn audit(state: &AppState, event: AuditEvent) {
    match state.audit.lock() {
        Ok(mut log) => {
            if let Err(e) = log.record(event) {
                tracing::error!(error = %e, "audit write failed");
            }
        }
        Err(_) => tracing::error!("audit log mutex poisoned"),
    }
}
