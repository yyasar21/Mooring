//! `credential_copy_secret` and `credential_copy_otp` (ADR-0009 §6): Rust opens the secret,
//! writes the clipboard, schedules a clear that only fires while the clipboard still holds
//! that value, and audits `credential_copied {credential, name}` (`name: "otp"` for codes).
//! Nothing secret is returned; the clear task holds a SHA-256 digest, not the value.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mooring_audit::AuditEvent;
use mooring_core::credential::{otp, CredentialError};
use mooring_core::SecretName;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::clipboard::{self, Clipboard};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// `{ clearsInMs }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyResult {
    /// When the clipboard will be cleared.
    pub clears_in_ms: u64,
}

/// `{ clearsInMs, validForMs }`: the code itself never comes back over IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpCopyResult {
    /// When the clipboard will be cleared (never later than `validForMs`).
    pub clears_in_ms: u64,
    /// How long the copied code stays valid.
    pub valid_for_ms: u64,
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn text(bytes: &[u8]) -> IpcResult<Zeroizing<String>> {
    std::str::from_utf8(bytes)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|_| IpcError::invalid("name", "secret is not text"))
}

/// Put `value` on the clipboard and schedule the clear after `delay`. Must run inside a Tokio
/// runtime.
fn place(state: &AppState, value: &str, delay: Duration) -> IpcResult<()> {
    let clipboard = Arc::clone(&state.settings.clipboard);
    clipboard
        .set(value)
        .map_err(|_| IpcError::new("clipboard.unavailable", "the clipboard is not available"))?;
    let expected = clipboard::digest(value);
    if let Ok(mut pending) = state.pending_clipboard.lock() {
        *pending = Some(expected);
    }
    tokio::spawn(clear_later(clipboard, Arc::clone(&state.pending_clipboard), expected, delay));
    Ok(())
}

/// `credential_copy_secret({ id, name })`: only names the kind schema flags `copyable`.
pub fn copy_secret(state: &AppState, id: &str, name: &str) -> IpcResult<CopyResult> {
    let cred = dto::credential_id("id", id)?;
    let name = SecretName::parse(name).ok_or_else(|| IpcError::invalid("name", "unknown secret name"))?;
    let secret = state.with_ready(|vault, store| {
        let meta = store.get_credential(cred)?;
        let copyable = meta.kind.schema().secret(name).is_some_and(|s| s.copyable);
        if !copyable {
            return Err(IpcError::invalid("name", "this secret cannot be copied"));
        }
        if !meta.secret_names.contains(&name) {
            return Err(CredentialError::SecretMissing(name).into());
        }
        Ok(store.open_secret(vault, cred, name)?)
    })?;
    let value = text(&secret)?;
    drop(secret);
    let delay = state.settings.clipboard_clear_after;
    place(state, &value, delay)?;
    drop(value);
    state.audit(AuditEvent::CredentialCopied { credential: cred.to_string(), name: name.as_str().to_owned() });
    Ok(CopyResult { clears_in_ms: ms(delay) })
}

/// `credential_copy_otp({ id })`: compute the current TOTP code in Rust and copy it. The clear
/// fires at the latest when the code expires.
pub fn copy_otp(state: &AppState, id: &str) -> IpcResult<OtpCopyResult> {
    copy_otp_at(state, id, SystemTime::now())
}

/// [`copy_otp`] at a given time (tests).
pub fn copy_otp_at(state: &AppState, id: &str, now: SystemTime) -> IpcResult<OtpCopyResult> {
    let cred = dto::credential_id("id", id)?;
    let unix_ms = now.duration_since(UNIX_EPOCH).map_or(0, ms);
    let (code, valid_for) = state.with_ready(|vault, store| {
        let meta = store.get_credential(cred)?;
        if !meta.kind.supports_otp() {
            return Err(IpcError::invalid("id", "this kind has no second factor"));
        }
        if !meta.secret_names.contains(&SecretName::OtpSeed) {
            return Err(CredentialError::SecretMissing(SecretName::OtpSeed).into());
        }
        let params = meta.fields.otp().unwrap_or_default();
        let seed_text = store.open_secret(vault, cred, SecretName::OtpSeed)?;
        let seed = otp::decode_seed(&seed_text)?;
        Ok(otp::totp_now(&seed, params, unix_ms))
    })?;
    let delay = state.settings.clipboard_clear_after.min(Duration::from_millis(valid_for));
    place(state, &code, delay)?;
    drop(code);
    state.audit(AuditEvent::CredentialCopied { credential: cred.to_string(), name: "otp".to_owned() });
    Ok(OtpCopyResult { clears_in_ms: ms(delay), valid_for_ms: valid_for })
}

async fn clear_later(
    clipboard: Arc<dyn Clipboard>,
    pending: Arc<Mutex<Option<clipboard::ValueDigest>>>,
    expected: clipboard::ValueDigest,
    delay: Duration,
) {
    tokio::time::sleep(delay).await;
    // Forget the pending digest unless a newer copy replaced it; shutdown/lock may have
    // already taken it, in which case the clear below finds a different value or nothing.
    if let Ok(mut p) = pending.lock() {
        if p.as_ref() == Some(&expected) {
            *p = None;
        }
    }
    let result =
        tokio::task::spawn_blocking(move || clipboard::clear_if_unchanged(&*clipboard, &expected)).await;
    match result {
        Ok(Ok(true)) => tracing::info!("copied secret cleared from the clipboard"),
        Ok(Ok(false)) => tracing::debug!("clipboard changed since copy; left alone"),
        Ok(Err(_)) | Err(_) => tracing::warn!("could not clear the clipboard"),
    }
}

// ------------------------------------------------------------------ Tauri wrappers

/// `credential_copy_secret({ id, name })`.
#[tauri::command]
pub async fn credential_copy_secret(state: State<'_, AppState>, id: String, name: String) -> IpcResult<CopyResult> {
    copy_secret(&state, &id, &name)
}

/// `credential_copy_otp({ id })`.
#[tauri::command]
pub async fn credential_copy_otp(state: State<'_, AppState>, id: String) -> IpcResult<OtpCopyResult> {
    copy_otp(&state, &id)
}

#[cfg(test)]
#[path = "credential_copy_tests.rs"]
mod tests;
