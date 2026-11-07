//! ADR-0016 §7 (E2): secret source commands. Sources hold no secret (the login lives in an
//! ordinary `api_token` / `vault_approle` credential), and nothing returned here carries a
//! token or a secret value: tests report counts, TTLs and **names** only.
//!
//! ```text
//! secret_source_list()                         -> SecretSource[]
//! secret_source_get({ id })                    -> SecretSource
//! secret_source_create({ kind?, name, address, namespace?, authMethod, authMount?,
//!                        credentialId?, oidcRole?, options? }) -> SecretSource
//!   # kind: vault (default) | onepassword | bitwarden (ADR-0026); options.bwsPath (bitwarden)
//! secret_source_update({ id, ...same })        -> SecretSource     # forgets the cached token
//! secret_source_delete({ id })                 -> null             # source.in_use while referenced
//! secret_source_test({ id })                   -> SourceTest
//! secret_source_revoke({ id })                 -> null             # revoke (ours) + forget
//! credential_external_test({ credentialId })   -> RefTest
//! ```
//! The OIDC commands are in [`super::secret_sources_oidc`].

use mooring_audit::AuditEvent;
use mooring_core::credential::CredentialFields;
use mooring_core::secret_source::{SecretSource, SecretSourceInput};
use mooring_core::SecretSourceId;
use serde::Serialize;
use tauri::State;

use crate::commands::connect_plan::source_error;
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::secrets_runtime::login_provider;
use crate::state::AppState;

/// Largest create / update payload (bytes of JSON); `caPem` alone may be 64 KiB.
pub const MAX_INPUT_BYTES: usize = 96 * 1024;

/// `options` of a source on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceOptionsDto {
    /// Extra PEM roots (certificates only).
    pub ca_pem: Option<String>,
    /// `http://` to loopback allowed.
    pub allow_http: bool,
    /// Extra OIDC window origins.
    pub allowed_origins: Vec<String>,
    /// Bitwarden: the chosen fixed `bws` location (`null` = the first that exists).
    pub bws_path: Option<String>,
}

/// One source on the wire (no secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretSourceDto {
    /// Id.
    pub id: String,
    /// Name.
    pub name: String,
    /// `vault` | `onepassword` | `bitwarden`.
    pub kind: &'static str,
    /// `https://host[:port][/prefix]`.
    pub address: String,
    /// `X-Vault-Namespace`.
    pub namespace: Option<String>,
    /// `token` | `approle` | `oidc`.
    pub auth_method: &'static str,
    /// Auth mount.
    pub auth_mount: String,
    /// Login credential (token / approle).
    pub credential_id: Option<String>,
    /// OIDC role.
    pub oidc_role: Option<String>,
    /// Options.
    pub options: SourceOptionsDto,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub updated_at: String,
}

impl From<&SecretSource> for SecretSourceDto {
    fn from(s: &SecretSource) -> Self {
        let oidc_role = match &s.auth {
            mooring_core::secret_source::SecretSourceAuth::Oidc { role, .. } => Some(role.clone()),
            _ => None,
        };
        Self {
            id: s.id.to_string(),
            name: s.name.clone(),
            kind: s.kind.name(),
            address: s.address.clone(),
            namespace: s.namespace.clone(),
            auth_method: s.auth.method().name(),
            auth_mount: s.auth.mount().to_owned(),
            credential_id: s.auth.credential_id().map(|c| c.to_string()),
            oidc_role,
            options: SourceOptionsDto {
                ca_pem: s.options.ca_pem.clone(),
                allow_http: s.options.allow_http,
                allowed_origins: s.options.allowed_origins.clone(),
                bws_path: s.options.bws_path.clone(),
            },
            created_at: dto::ts(s.created_at),
            updated_at: dto::ts(s.updated_at),
        }
    }
}

/// `secret_source_test` result: never the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceTestDto {
    /// Login + `lookup-self` succeeded.
    pub ok: bool,
    /// `token` | `approle` | `oidc`.
    pub method: &'static str,
    /// Cached lifetime.
    pub ttl_seconds: Option<u64>,
    /// Renewable.
    pub renewable: bool,
    /// Number of policies of the token.
    pub policies_count: usize,
    /// Error code when `ok` is false (`credential.external_*`).
    pub error: Option<&'static str>,
    /// `credential.external_unavailable` category when `ok` is false.
    pub category: Option<&'static str>,
}

/// `credential_external_test` result: KV key **names** only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefTestDto {
    /// The reference resolves and fits the target kind.
    pub ok: bool,
    /// KV version read.
    pub version: Option<u64>,
    /// Names of the target kind present in KV.
    pub present: Vec<String>,
    /// Required names missing.
    pub missing: Vec<String>,
    /// KV keys the target kind does not use (refused at connect).
    pub extra: Vec<String>,
    /// Error code when the read failed.
    pub error: Option<&'static str>,
    /// Category of `credential.external_unavailable`.
    pub category: Option<&'static str>,
}

/// Parse a source id from IPC.
pub fn source_id(raw: &str) -> IpcResult<SecretSourceId> {
    if raw.len() > 64 {
        return Err(IpcError::invalid("id", "not a UUID"));
    }
    raw.trim().parse().map_err(|_| IpcError::invalid("id", "not a UUID"))
}

fn parse_input(input: &serde_json::Value) -> IpcResult<SecretSourceInput> {
    if !input.is_object() || input.to_string().len() > MAX_INPUT_BYTES {
        return Err(IpcError::invalid("source", "must be an object of at most 96 KiB"));
    }
    // serde messages name the field, never the value of a string.
    serde_json::from_value(input.clone()).map_err(|e| {
        const FIELDS: [&str; 13] = ["kind", "name", "address", "namespace", "authMethod", "authMount",
            "credentialId", "oidcRole", "options", "caPem", "allowHttp", "allowedOrigins", "bwsPath"];
        let text = e.to_string();
        let field = text.split('`').find(|t| FIELDS.contains(t)).unwrap_or("source");
        IpcError::invalid(field, "missing or malformed")
    })
}

/// The stored source `id`.
pub fn load(state: &AppState, id: SecretSourceId) -> IpcResult<SecretSource> {
    state.with_ready(|_, store| store.get_secret_source(id).map_err(source_error))
}

fn trust_warning(changed: &[&str]) -> bool {
    changed.iter().any(|c| matches!(*c, "caPem" | "allowHttp" | "bwsPath"))
}

/// The `secret_source_changed` row of `s` after `changed` (review 6 N-42): the names
/// actually set or changed, the fingerprints of a new `caPem`, and `warning` when trust
/// widened (`caPem`, `allowHttp`, or an `allowedOrigins` entry added, `added_origin`).
fn changed_event(s: &SecretSource, changed: Vec<&str>, added_origin: bool) -> AuditEvent {
    let ca_pem = if changed.contains(&"caPem") {
        s.options.ca_pem.as_deref().map(crate::commands::conn_options::ca_fingerprints).unwrap_or_default()
    } else {
        Vec::new()
    };
    AuditEvent::SecretSourceChanged {
        source: s.id.to_string(),
        warning: trust_warning(&changed) || added_origin,
        changed: changed.into_iter().map(str::to_owned).collect(),
        ca_pem,
    }
}

/// `secret_source_list()`.
pub fn list(state: &AppState) -> IpcResult<Vec<SecretSourceDto>> {
    state.with_ready(|_, store| Ok(store.list_secret_sources()?.iter().map(SecretSourceDto::from).collect()))
}

/// `secret_source_get({ id })`.
pub fn get(state: &AppState, id: &str) -> IpcResult<SecretSourceDto> {
    Ok(SecretSourceDto::from(&load(state, source_id(id)?)?))
}

/// `secret_source_create({ ... })`.
pub fn create(state: &AppState, input: &serde_json::Value) -> IpcResult<SecretSourceDto> {
    let input = parse_input(input)?;
    let s = state.with_ready(|_, store| Ok(store.create_secret_source(&input)?))?;
    let mut changed = vec!["created"];
    if s.options.ca_pem.is_some() {
        changed.push("caPem");
    }
    if s.options.allow_http {
        changed.push("allowHttp");
    }
    if s.options.bws_path.is_some() {
        changed.push("bwsPath");
    }
    let origins = !s.options.allowed_origins.is_empty();
    if origins {
        changed.push("allowedOrigins");
    }
    state.audit(changed_event(&s, changed, origins));
    Ok(SecretSourceDto::from(&s))
}

/// `secret_source_update({ id, ... })`: the cached token is forgotten (address, trust or
/// login may have changed).
pub async fn update(state: &AppState, id: &str, input: &serde_json::Value) -> IpcResult<SecretSourceDto> {
    let raw = input;
    let id = source_id(id)?;
    let mut input = parse_input(input)?;
    let kind_given = raw.get("kind").is_some();
    let (before, s, changed) = state.with_ready(|_, store| {
        let stored = store.get_secret_source(id).map_err(source_error)?;
        if !kind_given {
            input.kind = stored.kind; // an A3 payload without `kind` keeps the stored one
        }
        let before = stored.options.allowed_origins;
        let (s, changed) = store.update_secret_source(id, &input).map_err(source_error)?;
        Ok((before, s, changed))
    })?;
    state.secrets.engine().logout(id).await;
    let added_origin = s.options.allowed_origins.iter().any(|o| !before.contains(o));
    state.audit(changed_event(&s, changed, added_origin));
    Ok(SecretSourceDto::from(&s))
}

/// `secret_source_delete({ id })`: refused (`source.in_use`) while an `external_ref` names it.
pub async fn delete(state: &AppState, id: &str) -> IpcResult<()> {
    let id = source_id(id)?;
    if let Err(e) = state.with_ready(|_, store| store.delete_secret_source(id).map_err(source_error)) {
        state.secrets.refused(Some(id.to_string()), "delete", e.code);
        return Err(e);
    }
    state.secrets.engine().logout(id).await;
    state.audit(AuditEvent::SecretSourceChanged {
        source: id.to_string(),
        changed: vec!["deleted".to_owned()],
        ca_pem: Vec::new(),
        warning: false,
    });
    Ok(())
}

/// `secret_source_test({ id })`: a fresh login (OIDC: the signed-in token) + `lookup-self`.
pub async fn test(state: &AppState, id: &str) -> IpcResult<SourceTestDto> {
    let source = load(state, source_id(id)?)?;
    let provider = login_provider(state.ready());
    let method = source.auth.method().name();
    Ok(match state.secrets.engine().test_source(&source, &provider).await {
        Ok(t) => SourceTestDto {
            ok: true,
            method,
            ttl_seconds: t.ttl_seconds,
            renewable: t.renewable,
            policies_count: t.policies_count,
            error: None,
            category: None,
        },
        Err(e) => SourceTestDto {
            ok: false,
            method,
            ttl_seconds: None,
            renewable: false,
            policies_count: 0,
            error: Some(e.code()),
            category: Some(e.category().as_str()),
        },
    })
}

/// `secret_source_revoke({ id })`: revoke the cached token when Mooring minted it (`AppRole`,
/// OIDC) and forget it either way. Needs no unlocked vault (it only drops material).
pub async fn revoke(state: &AppState, id: &str) -> IpcResult<()> {
    state.secrets.engine().logout(source_id(id)?).await;
    Ok(())
}

/// `credential_external_test({ credentialId })`: read the reference, report names only.
pub async fn external_test(state: &AppState, credential_id: &str) -> IpcResult<RefTestDto> {
    let cid = dto::credential_id("credentialId", credential_id)?;
    let (fields, source) = state.with_ready(|_, store| {
        let meta = store.get_credential(cid)?;
        let CredentialFields::ExternalRef(f) = &meta.fields else {
            return Err(IpcError::invalid("credentialId", "not an external_ref credential"));
        };
        let source = store
            .source_of(&meta.fields)
            .map_err(source_error)?
            .ok_or_else(|| IpcError::new("source.not_found", "the reference names no secret source"))?;
        Ok((f.clone(), source))
    })?;
    let provider = login_provider(state.ready());
    Ok(match state.secrets.engine().test_ref(&source, &fields, &provider).await {
        Ok(t) => RefTestDto {
            ok: t.missing.is_empty() && t.extra.is_empty(),
            version: Some(t.version),
            present: t.present,
            missing: t.missing,
            extra: t.extra,
            error: None,
            category: None,
        },
        Err(e) => RefTestDto {
            ok: false,
            version: None,
            present: Vec::new(),
            missing: Vec::new(),
            extra: Vec::new(),
            error: Some(e.code()),
            category: Some(e.category().as_str()),
        },
    })
}

// --- Tauri wrappers --------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // the flat ADR-0016 §7 argument list
fn input_json(
    kind: Option<String>,
    name: String,
    address: String,
    namespace: Option<String>,
    auth_method: String,
    auth_mount: Option<String>,
    credential_id: Option<String>,
    oidc_role: Option<String>,
    options: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "name": name, "address": address, "namespace": namespace, "authMethod": auth_method,
        "authMount": auth_mount, "credentialId": credential_id, "oidcRole": oidc_role,
        "options": options.unwrap_or_else(|| serde_json::json!({})),
    });
    if let Some(k) = kind {
        v["kind"] = serde_json::Value::String(k);
    }
    v
}

/// `secret_source_list()`.
#[tauri::command]
pub fn secret_source_list(state: State<'_, AppState>) -> IpcResult<Vec<SecretSourceDto>> {
    list(&state)
}

/// `secret_source_get({ id })`.
#[tauri::command]
pub fn secret_source_get(state: State<'_, AppState>, id: String) -> IpcResult<SecretSourceDto> {
    get(&state, &id)
}

/// `secret_source_create({ name, address, namespace, authMethod, authMount, credentialId,
/// oidcRole, options })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one argument per ADR-0016 §7 field
pub fn secret_source_create(
    state: State<'_, AppState>,
    kind: Option<String>,
    name: String,
    address: String,
    namespace: Option<String>,
    auth_method: String,
    auth_mount: Option<String>,
    credential_id: Option<String>,
    oidc_role: Option<String>,
    options: Option<serde_json::Value>,
) -> IpcResult<SecretSourceDto> {
    let input = input_json(kind, name, address, namespace, auth_method, auth_mount, credential_id, oidc_role, options);
    create(&state, &input)
}

/// `secret_source_update({ id, ...create })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one argument per ADR-0016 §7 field
pub async fn secret_source_update(
    state: State<'_, AppState>,
    id: String,
    kind: Option<String>,
    name: String,
    address: String,
    namespace: Option<String>,
    auth_method: String,
    auth_mount: Option<String>,
    credential_id: Option<String>,
    oidc_role: Option<String>,
    options: Option<serde_json::Value>,
) -> IpcResult<SecretSourceDto> {
    let input = input_json(kind, name, address, namespace, auth_method, auth_mount, credential_id, oidc_role, options);
    update(&state, &id, &input).await
}

/// `secret_source_delete({ id })`.
#[tauri::command]
pub async fn secret_source_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    delete(&state, &id).await
}

/// `secret_source_test({ id })`.
#[tauri::command]
pub async fn secret_source_test(state: State<'_, AppState>, id: String) -> IpcResult<SourceTestDto> {
    test(&state, &id).await
}

/// `secret_source_revoke({ id })`.
#[tauri::command]
pub async fn secret_source_revoke(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    revoke(&state, &id).await
}

/// `credential_external_test({ credentialId })`.
#[tauri::command]
pub async fn credential_external_test(
    state: State<'_, AppState>,
    credential_id: String,
) -> IpcResult<RefTestDto> {
    external_test(&state, &credential_id).await
}

#[cfg(test)]
#[path = "secret_sources_tests.rs"]
mod tests;
