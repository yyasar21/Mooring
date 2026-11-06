//! Credential commands (ADR-0009 §6, replacing the ADR-0008 block). Metadata goes out; secrets
//! only come in, are size-checked here, validated per kind in `mooring-core` and sealed one by
//! one into the store. Clipboard commands live in [`super::credential_copy`].

use std::collections::BTreeMap;

use mooring_audit::AuditEvent;
use mooring_core::credential::{self as cred, parse_account, Account, KindSchema};
use mooring_core::SecretName;
use mooring_store::{Secrets, MAX_NAME};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tauri::{AppHandle, Manager, State};

use crate::dto::{self, CredentialDto};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Largest single secret accepted over IPC (bytes): the kubeconfig cap. Per-secret caps are
/// enforced by `mooring-core` afterwards.
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
/// Most secrets in one call.
pub const MAX_SECRETS: usize = 8;
/// Largest `fields` object accepted (bytes of JSON).
pub const MAX_FIELDS_BYTES: usize = mooring_core::credential::MAX_FIELDS_JSON;
/// Longest account input for `credential_parse_account` (bytes).
pub const MAX_ACCOUNT_INPUT: usize = 512;
/// Inputs at least this large are parsed off the IPC thread (review 3, L-10).
pub const OFFLOAD_BYTES: usize = 64 * 1024;

/// Secrets as they cross IPC: `{ [name]: string }`, wrapped at once.
#[derive(Default, Deserialize)]
#[serde(transparent)]
pub struct WireSecrets(pub BTreeMap<String, SecretString>);

impl std::fmt::Debug for WireSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl WireSecrets {
    /// Total bytes of all values (no secret is exposed beyond its length).
    fn byte_len(&self) -> usize {
        self.0.values().map(|v| v.expose_secret().len()).sum()
    }

    /// Synthetic secrets for tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn of(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|(k, v)| ((*k).to_owned(), SecretString::from((*v).to_owned()))).collect())
    }

    /// Parse names and bound sizes. Blank values are dropped (the UI leaves untouched inputs
    /// empty); every name must be a known secret name (the kind check comes later).
    fn parse(&self) -> IpcResult<BTreeMap<SecretName, &SecretString>> {
        if self.0.len() > MAX_SECRETS {
            return Err(IpcError::invalid("secrets", "too many entries"));
        }
        let mut out = BTreeMap::new();
        for (k, v) in &self.0 {
            let name = SecretName::parse(k).ok_or_else(|| IpcError::invalid("secrets", "unknown secret name"))?;
            if v.expose_secret().len() > MAX_SECRET_BYTES {
                return Err(IpcError::invalid(name.as_str(), "larger than 1 MiB"));
            }
            if !v.expose_secret().is_empty() {
                out.insert(name, v);
            }
        }
        Ok(out)
    }
}

fn as_bytes<'a>(m: &BTreeMap<SecretName, &'a SecretString>) -> Secrets<'a> {
    m.iter().map(|(k, v)| (*k, v.expose_secret().as_bytes())).collect()
}

fn check_name(name: &str) -> IpcResult<()> {
    if name.len() > MAX_NAME * 4 {
        return Err(IpcError::invalid("name", "must be 1..=120 characters"));
    }
    Ok(())
}

fn check_fields(fields: &serde_json::Value) -> IpcResult<()> {
    if !fields.is_object() {
        return Err(IpcError::invalid("fields", "must be an object"));
    }
    if fields.to_string().len() > MAX_FIELDS_BYTES {
        return Err(IpcError::invalid("fields", "larger than 128 KiB"));
    }
    Ok(())
}

/// `credential_create` input.
#[derive(Debug)]
pub struct NewCredential {
    /// Display name.
    pub name: String,
    /// Kind wire name.
    pub kind: String,
    /// Plain fields.
    pub fields: serde_json::Value,
    /// Secrets by name.
    pub secrets: WireSecrets,
}

impl NewCredential {
    /// A `user_password` credential (`ops`) with a synthetic password (tests only).
    #[cfg(any(test, feature = "test-util"))]
    pub fn password_for_tests(name: &str) -> Self {
        Self::user_password(name, "ops", "test-only secret")
    }

    /// A `user_password` credential (tests only).
    #[cfg(any(test, feature = "test-util"))]
    pub fn user_password(name: &str, username: &str, password: &str) -> Self {
        Self {
            name: name.to_owned(),
            kind: "user_password".to_owned(),
            fields: serde_json::json!({ "username": username }),
            secrets: WireSecrets::of(&[("password", password)]),
        }
    }
}

/// `credential_kinds()`: the ADR-0009 table, also the protocol matrix.
pub fn kinds() -> &'static [KindSchema] {
    cred::credential_kinds()
}

/// `credential_list()`.
pub fn list(state: &AppState) -> IpcResult<Vec<CredentialDto>> {
    state.with_ready(|_, store| Ok(store.list_credentials()?.iter().map(Into::into).collect()))
}

/// `credential_create({ name, kind, fields, secrets })`.
pub fn create(state: &AppState, c: NewCredential) -> IpcResult<CredentialDto> {
    check_name(&c.name)?;
    let kind = dto::credential_kind(&c.kind)?;
    check_fields(&c.fields)?;
    let parsed = c.secrets.parse()?;
    let stored = state.with_ready(|vault, store| {
        Ok(store.create_credential(vault, &c.name, kind, &c.fields, &as_bytes(&parsed))?)
    })?;
    if stored.secret_names.contains(&SecretName::OtpSeed) {
        state.audit(AuditEvent::CredentialOtpAttached { credential: stored.id.to_string() });
    }
    Ok(CredentialDto::from(&stored))
}

/// `credential_update_fields({ id, name, fields })`: kind is immutable.
pub fn update_fields(state: &AppState, id: &str, name: &str, fields: &serde_json::Value) -> IpcResult<CredentialDto> {
    let id = dto::credential_id("id", id)?;
    check_name(name)?;
    check_fields(fields)?;
    state.with_ready(|_, store| Ok(CredentialDto::from(&store.update_credential_fields(id, name, fields)?)))
}

/// `credential_replace_secrets({ id, set, clear })`.
pub fn replace_secrets(state: &AppState, id: &str, set: &WireSecrets, clear: &[String]) -> IpcResult<()> {
    let id = dto::credential_id("id", id)?;
    let parsed = set.parse()?;
    if clear.len() > MAX_SECRETS {
        return Err(IpcError::invalid("clear", "too many entries"));
    }
    let clear = clear
        .iter()
        .map(|n| SecretName::parse(n).ok_or_else(|| IpcError::invalid("clear", "unknown secret name")))
        .collect::<IpcResult<Vec<_>>>()?;
    let attached = parsed.contains_key(&SecretName::OtpSeed);
    state.with_ready(|vault, store| {
        store.replace_secrets(vault, id, &as_bytes(&parsed), &clear)?;
        Ok(())
    })?;
    if attached {
        state.audit(AuditEvent::CredentialOtpAttached { credential: id.to_string() });
    }
    Ok(())
}

/// `credential_delete({ id })`.
pub fn delete(state: &AppState, id: &str) -> IpcResult<()> {
    let id = dto::credential_id("id", id)?;
    state.with_ready(|_, store| Ok(store.delete_credential(id)?))
}

/// `credential_parse_account({ input })` → `{ form, user, domain }`. Pure; no vault needed.
pub fn parse_account_input(input: &str) -> IpcResult<Account> {
    if input.len() > MAX_ACCOUNT_INPUT {
        return Err(IpcError::invalid("input", "too long"));
    }
    Ok(parse_account(input)?)
}

/// Run `f` on Tokio's blocking pool when the input is at least [`OFFLOAD_BYTES`]: parsing a large
/// kubeconfig or PEM and sealing it must not block the thread that serves IPC. Small inputs run
/// inline. A panic in `f` becomes an `internal` [`IpcError`] without detail.
pub async fn offload<H, T, F>(handle: H, input_bytes: usize, f: F) -> IpcResult<T>
where
    H: Send + 'static,
    T: Send + 'static,
    F: FnOnce(H) -> IpcResult<T> + Send + 'static,
{
    if input_bytes < OFFLOAD_BYTES {
        return f(handle);
    }
    super::off_thread(handle, f).await
}

// ------------------------------------------------------------------ Tauri wrappers

/// `credential_kinds()`.
#[tauri::command]
pub fn credential_kinds() -> &'static [KindSchema] {
    kinds()
}

/// `credential_list()`.
#[tauri::command]
pub fn credential_list(state: State<'_, AppState>) -> IpcResult<Vec<CredentialDto>> {
    list(&state)
}

/// `credential_create({ name, kind, fields, secrets })`.
#[tauri::command]
pub async fn credential_create(
    app: AppHandle,
    name: String,
    kind: String,
    fields: Option<serde_json::Value>,
    secrets: Option<WireSecrets>,
) -> IpcResult<CredentialDto> {
    let fields = fields.unwrap_or_else(|| serde_json::json!({}));
    let secrets = secrets.unwrap_or_default();
    let bytes = secrets.byte_len() + fields.to_string().len();
    offload(app, bytes, move |app| create(&app.state::<AppState>(), NewCredential { name, kind, fields, secrets }))
        .await
}

/// `credential_update_fields({ id, name, fields })`.
#[tauri::command]
pub async fn credential_update_fields(
    app: AppHandle,
    id: String,
    name: String,
    fields: serde_json::Value,
) -> IpcResult<CredentialDto> {
    let bytes = fields.to_string().len();
    offload(app, bytes, move |app| update_fields(&app.state::<AppState>(), &id, &name, &fields)).await
}

/// `credential_replace_secrets({ id, set, clear })`.
#[tauri::command]
pub async fn credential_replace_secrets(
    app: AppHandle,
    id: String,
    set: Option<WireSecrets>,
    clear: Option<Vec<String>>,
) -> IpcResult<()> {
    let set = set.unwrap_or_default();
    let bytes = set.byte_len();
    offload(app, bytes, move |app| replace_secrets(&app.state::<AppState>(), &id, &set, &clear.unwrap_or_default()))
        .await
}

/// `credential_delete({ id })`.
#[tauri::command]
pub fn credential_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    delete(&state, &id)
}

/// `credential_parse_account({ input })`.
#[tauri::command]
pub fn credential_parse_account(input: String) -> IpcResult<Account> {
    parse_account_input(&input)
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
