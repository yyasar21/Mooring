//! Credential commands (ADR-0008 §Credentials). Metadata goes out; secrets only come in and are
//! sealed straight into the store. `credential_copy_password` writes the clipboard from Rust.

use std::sync::Arc;
use std::time::Duration;

use mooring_audit::AuditEvent;
use mooring_store::{CredentialKind, CredentialMeta, SecretField, MAX_NAME};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::clipboard::{self, Clipboard};
use crate::dto::{self, CredentialDto};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Largest secret accepted over IPC (bytes): the store's sealed-column cap.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// Longest user name (characters, store rule).
pub const MAX_USERNAME_CHARS: usize = 256;

/// `credential_create` input. `secret`/`secret2` are wrapped at the IPC edge.
#[derive(Debug)]
pub struct NewCredential {
    /// Display name.
    pub name: String,
    /// Kind name.
    pub kind: String,
    /// User name (`""` = none).
    pub username: String,
    /// Primary secret.
    pub secret: SecretString,
    /// Secondary secret.
    pub secret2: Option<SecretString>,
}

impl NewCredential {
    /// A password credential with a synthetic secret (tests only).
    #[cfg(test)]
    pub fn password_for_tests(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            kind: "password".to_owned(),
            username: "ops".to_owned(),
            secret: SecretString::from("test-only secret"),
            secret2: None,
        }
    }
}

fn check_secret(field: &str, s: &SecretString, required: bool) -> IpcResult<()> {
    let len = s.expose_secret().len();
    if len > MAX_SECRET_BYTES {
        return Err(IpcError::invalid(field, "larger than 64 KiB"));
    }
    if required && len == 0 {
        return Err(IpcError::invalid(field, "is required"));
    }
    Ok(())
}

fn check_meta(name: &str, username: &str) -> IpcResult<()> {
    // Cheap size bounds before the store's full validation (which never echoes the value).
    if name.len() > MAX_NAME * 4 {
        return Err(IpcError::invalid("name", "must be 1..=120 characters"));
    }
    if username.chars().count() > MAX_USERNAME_CHARS {
        return Err(IpcError::invalid("username", "at most 256 characters"));
    }
    Ok(())
}

fn opt_username(username: &str) -> Option<&str> {
    Some(username.trim()).filter(|u| !u.is_empty())
}

/// `credential_list()`.
pub fn list(state: &AppState) -> IpcResult<Vec<CredentialDto>> {
    state.with_ready(|_, store| Ok(store.list_credentials()?.iter().map(Into::into).collect()))
}

/// `credential_create(...)`.
pub fn create(state: &AppState, c: NewCredential) -> IpcResult<CredentialDto> {
    check_meta(&c.name, &c.username)?;
    let kind = dto::credential_kind(&c.kind)?;
    check_secret("secret", &c.secret, true)?;
    if let Some(s2) = &c.secret2 {
        check_secret("secret2", s2, false)?;
    }
    let meta = CredentialMeta::new(&c.name, kind, opt_username(&c.username))?;
    state.with_ready(|vault, store| {
        let secret2 = c.secret2.as_ref().map(|s| s.expose_secret().as_bytes());
        let stored = store.create_credential(
            vault,
            &meta,
            c.secret.expose_secret().as_bytes(),
            secret2.filter(|s| !s.is_empty()),
        )?;
        Ok(CredentialDto::from(&stored))
    })
}

/// `credential_update_meta({ id, name, username })`.
pub fn update_meta(
    state: &AppState,
    id: &str,
    name: &str,
    username: &str,
) -> IpcResult<CredentialDto> {
    let id = dto::credential_id("id", id)?;
    check_meta(name, username)?;
    state.with_ready(|_, store| {
        Ok(CredentialDto::from(&store.update_credential_meta(id, name, opt_username(username))?))
    })
}

/// `credential_replace_secret({ id, secret, secret2 })`: `secret2 = null` clears it.
pub fn replace_secret(
    state: &AppState,
    id: &str,
    secret: &SecretString,
    secret2: Option<&SecretString>,
) -> IpcResult<()> {
    let id = dto::credential_id("id", id)?;
    check_secret("secret", secret, true)?;
    if let Some(s2) = secret2 {
        check_secret("secret2", s2, false)?;
    }
    state.with_ready(|vault, store| {
        store.get_credential(id)?;
        store.replace_credential_secret(
            vault,
            id,
            SecretField::Secret,
            Some(secret.expose_secret().as_bytes()),
        )?;
        let s2 = secret2.map(|s| s.expose_secret().as_bytes()).filter(|s| !s.is_empty());
        store.replace_credential_secret(vault, id, SecretField::Secret2, s2)?;
        Ok(())
    })
}

/// `credential_delete({ id })`.
pub fn delete(state: &AppState, id: &str) -> IpcResult<()> {
    let id = dto::credential_id("id", id)?;
    state.with_ready(|_, store| Ok(store.delete_credential(id)?))
}

/// `{ clearsInMs }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyResult {
    /// When the clipboard will be cleared.
    pub clears_in_ms: u64,
}

/// `credential_copy_password({ id })`: put a password credential's secret on the clipboard,
/// audit `credential_used { purpose: copy }`, and schedule a clear that only fires while the
/// clipboard still holds that value. The clear task holds a SHA-256 digest, not the secret.
/// Must run inside a Tokio runtime (the clear task is spawned on it).
pub fn copy_password(state: &AppState, id: &str) -> IpcResult<CopyResult> {
    let cred = dto::credential_id("id", id)?;
    let secret = state.with_ready(|vault, store| {
        let meta = store.get_credential(cred)?;
        if meta.kind != CredentialKind::Password {
            return Err(IpcError::invalid("id", "only password credentials can be copied"));
        }
        Ok(store.open_credential_secret(vault, cred, SecretField::Secret)?)
    })?;
    let text = Zeroizing::new(
        String::from_utf8(secret.to_vec())
            .map_err(|_| IpcError::invalid("id", "password is not text"))?,
    );
    drop(secret);
    let clipboard = Arc::clone(&state.settings.clipboard);
    clipboard
        .set(&text)
        .map_err(|_| IpcError::new("clipboard.unavailable", "the clipboard is not available"))?;
    let expected = clipboard::digest(&text);
    drop(text);
    let delay = state.settings.clipboard_clear_after;
    tokio::spawn(clear_later(clipboard, expected, delay));
    state.audit(AuditEvent::CredentialUsed {
        credential: cred.to_string(),
        purpose: "copy".to_owned(),
        connection: None,
    });
    Ok(CopyResult { clears_in_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX) })
}

async fn clear_later(
    clipboard: Arc<dyn Clipboard>,
    expected: clipboard::ValueDigest,
    delay: Duration,
) {
    tokio::time::sleep(delay).await;
    let result =
        tokio::task::spawn_blocking(move || clipboard::clear_if_unchanged(&*clipboard, &expected))
            .await;
    match result {
        Ok(Ok(true)) => tracing::info!("copied password cleared from the clipboard"),
        Ok(Ok(false)) => tracing::debug!("clipboard changed since copy; left alone"),
        Ok(Err(_)) | Err(_) => tracing::warn!("could not clear the clipboard"),
    }
}

// ------------------------------------------------------------------ Tauri wrappers

/// `credential_list()`.
#[tauri::command]
pub fn credential_list(state: State<'_, AppState>) -> IpcResult<Vec<CredentialDto>> {
    list(&state)
}

/// `credential_create({ name, kind, username, secret, secret2 })`.
#[tauri::command]
pub fn credential_create(
    state: State<'_, AppState>,
    name: String,
    kind: String,
    username: Option<String>,
    secret: String,
    secret2: Option<String>,
) -> IpcResult<CredentialDto> {
    let c = NewCredential {
        name,
        kind,
        username: username.unwrap_or_default(),
        secret: SecretString::from(secret),
        secret2: secret2.map(SecretString::from),
    };
    create(&state, c)
}

/// `credential_update_meta({ id, name, username })`.
#[tauri::command]
pub fn credential_update_meta(
    state: State<'_, AppState>,
    id: String,
    name: String,
    username: Option<String>,
) -> IpcResult<CredentialDto> {
    update_meta(&state, &id, &name, username.as_deref().unwrap_or_default())
}

/// `credential_replace_secret({ id, secret, secret2 })`.
#[tauri::command]
pub fn credential_replace_secret(
    state: State<'_, AppState>,
    id: String,
    secret: String,
    secret2: Option<String>,
) -> IpcResult<()> {
    let secret = SecretString::from(secret);
    let secret2 = secret2.map(SecretString::from);
    replace_secret(&state, &id, &secret, secret2.as_ref())
}

/// `credential_delete({ id })`.
#[tauri::command]
pub fn credential_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    delete(&state, &id)
}

/// `credential_copy_password({ id })`.
#[tauri::command]
pub async fn credential_copy_password(
    state: State<'_, AppState>,
    id: String,
) -> IpcResult<CopyResult> {
    copy_password(&state, &id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::*;

    fn new(kind: &str, secret: &str) -> NewCredential {
        NewCredential {
            name: "ops".into(),
            kind: kind.into(),
            username: " admin ".into(),
            secret: SecretString::from(secret.to_owned()),
            secret2: None,
        }
    }

    #[test]
    fn round_trip_metadata_only() {
        let f = unlocked();
        let c = create(&f.state, new("password", "test-only pw 1")).expect("create");
        assert_eq!((c.kind, c.username.as_str()), ("password", "admin"));
        let json = serde_json::to_string(&list(&f.state).expect("list")).expect("json");
        assert!(!json.contains("test-only pw 1"), "no secret outward: {json}");
        let u = update_meta(&f.state, &c.id, "ops2", "").expect("update");
        assert_eq!((u.name.as_str(), u.username.as_str()), ("ops2", ""));
        replace_secret(&f.state, &c.id, &SecretString::from("test-only pw 2"), None).expect("re");
        f.state
            .with_ready(|v, s| {
                let id = c.id.parse().expect("id");
                let got = s.open_credential_secret(v, id, SecretField::Secret)?;
                assert_eq!(got.as_slice(), b"test-only pw 2");
                Ok(())
            })
            .expect("open");
        delete(&f.state, &c.id).expect("delete");
        assert_eq!(delete(&f.state, &c.id).expect_err("gone").code, "credential.not_found");
    }

    #[test]
    fn validation() {
        let f = unlocked();
        let big = "x".repeat(MAX_SECRET_BYTES + 1);
        assert_eq!(create(&f.state, new("token", "s")).expect_err("kind").code, "input.invalid");
        assert_eq!(create(&f.state, new("password", "")).expect_err("empty").code, "input.invalid");
        assert_eq!(create(&f.state, new("password", &big)).expect_err("big").code, "input.invalid");
        let mut long_user = new("password", "s");
        long_user.username = "u".repeat(257);
        assert_eq!(create(&f.state, long_user).expect_err("user").code, "input.invalid");
        let mut bad_name = new("password", "s");
        bad_name.name = String::new();
        assert_eq!(create(&f.state, bad_name).expect_err("name").code, "input.invalid");
        let missing = mooring_core::CredentialId::new().to_string();
        let e = replace_secret(&f.state, &missing, &SecretString::from("s"), None).expect_err("nf");
        assert_eq!(e.code, "credential.not_found");
        assert_eq!(update_meta(&f.state, "nope", "n", "").expect_err("id").code, "input.invalid");
        crate::commands::vault::lock(&f.state, None).expect("lock");
        assert_eq!(create(&f.state, new("password", "s")).expect_err("lock").code, "vault.locked");
    }

    #[tokio::test]
    async fn copy_password_sets_clears_and_audits() {
        let f = unlocked();
        let c = create(&f.state, new("password", "test-only clip")).expect("create");
        let r = copy_password(&f.state, &c.id).expect("copy");
        assert_eq!(r.clears_in_ms, 200);
        assert_eq!(f.clipboard.peek().as_deref(), Some("test-only clip"));
        let events = audit_events(&f.state);
        assert_eq!(events.last().map(String::as_str), Some("credential_used"));
        let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
        assert!(log.contains("\"purpose\":\"copy\"") && !log.contains("test-only clip"));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(f.clipboard.peek(), None, "cleared after the delay");
    }

    #[tokio::test]
    async fn copy_leaves_a_newer_clipboard_value_alone() {
        let f = unlocked();
        let c = create(&f.state, new("password", "test-only clip")).expect("create");
        copy_password(&f.state, &c.id).expect("copy");
        f.clipboard.set("user copied this").expect("set");
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(f.clipboard.peek().as_deref(), Some("user copied this"));
    }

    #[tokio::test]
    async fn copy_refuses_non_passwords_and_locked_vault() {
        let f = unlocked();
        let key = create(&f.state, new("ssh_key", "test-only pem")).expect("create");
        assert_eq!(copy_password(&f.state, &key.id).expect_err("kind").code, "input.invalid");
        assert_eq!(f.clipboard.peek(), None);
        crate::commands::vault::lock(&f.state, None).expect("lock");
        assert_eq!(copy_password(&f.state, &key.id).expect_err("lock").code, "vault.locked");
    }
}
