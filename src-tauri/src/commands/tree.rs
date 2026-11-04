//! Connection tree commands (ADR-0008 §Tree). Every command needs an unlocked vault: the tree
//! is vault-derived state in the UI (lock wipes it), and it keeps the store bound to its vault.

use mooring_core::{validate_name, Connection, ConnectionId, Role};
use mooring_store::MAX_SEARCH_LIMIT;
use serde::Deserialize;
use tauri::State;

use crate::dto::{self, ConnectionDto, FolderDto, HitDto, TreeDto};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Longest search query accepted over IPC (bytes); the store truncates further.
pub const MAX_QUERY_BYTES: usize = 1024;

/// Fields shared by `connection_create` and `connection_update`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionFields {
    /// Folder.
    pub folder_id: String,
    /// Display name.
    pub name: String,
    /// Protocol name.
    pub protocol: String,
    /// Host.
    pub host: String,
    /// Port, `null` = default.
    pub port: Option<u32>,
    /// Own credential.
    pub credential_id: Option<String>,
    /// Username override (ADR-0009 §3).
    #[serde(default)]
    pub username_override: Option<String>,
    /// Domain override.
    #[serde(default)]
    pub domain_override: Option<String>,
    /// RD Gateway credential.
    #[serde(default)]
    pub gateway_credential_id: Option<String>,
    /// Become credential.
    #[serde(default)]
    pub become_credential_id: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl ConnectionFields {
    /// Plain fields with no credential links (tests and helpers).
    pub fn basic(folder_id: &str, name: &str, protocol: &str, host: &str) -> Self {
        Self {
            folder_id: folder_id.to_owned(),
            name: name.to_owned(),
            protocol: protocol.to_owned(),
            host: host.to_owned(),
            port: None,
            credential_id: None,
            username_override: None,
            domain_override: None,
            gateway_credential_id: None,
            become_credential_id: None,
            tags: Vec::new(),
        }
    }
}

impl ConnectionFields {
    /// Validate into a domain `Connection` (store re-validates names, hosts and tags).
    fn into_connection(self, id: Option<ConnectionId>) -> IpcResult<Connection> {
        if self.tags.len() > mooring_core::MAX_TAGS {
            return Err(IpcError::invalid("tags", "at most 50 tags"));
        }
        let folder = dto::folder_id("folderId", &self.folder_id)?;
        let protocol = dto::protocol(&self.protocol)?;
        let mut c = Connection::new(folder, self.name, protocol, self.host)?;
        if let Some(id) = id {
            c.id = id;
        }
        c.port = dto::port(self.port)?;
        c.credential = dto::opt_credential_id("credentialId", self.credential_id.as_deref())?;
        c.gateway_credential =
            dto::opt_credential_id("gatewayCredentialId", self.gateway_credential_id.as_deref())?;
        c.become_credential =
            dto::opt_credential_id("becomeCredentialId", self.become_credential_id.as_deref())?;
        for (field, v) in [("usernameOverride", &self.username_override), ("domainOverride", &self.domain_override)] {
            if v.as_ref().is_some_and(|v| v.len() > 1024) {
                return Err(IpcError::invalid(field, "too long"));
            }
        }
        c.username_override = self.username_override;
        c.domain_override = self.domain_override;
        c.tags = self.tags;
        Ok(c)
    }
}

/// `tree_list()`.
pub fn list(state: &AppState) -> IpcResult<TreeDto> {
    state.with_ready(|_, store| {
        let folders = dto::folders(store)?;
        let mut connections = Vec::new();
        for f in store.list_folders()? {
            for c in store.list_connections(f.id)? {
                connections.push(dto::connection(store, &c)?);
            }
        }
        Ok(TreeDto { folders, connections })
    })
}

/// `folder_create({ parentId, name })`. Only sub-folders: the root exists from first start.
pub fn create_folder(state: &AppState, parent_id: &str, name: &str) -> IpcResult<FolderDto> {
    let parent = dto::folder_id("parentId", parent_id)?;
    let name = validate_name(name)?;
    state.with_ready(|_, store| {
        let f = store.create_folder(Some(parent), &name)?;
        dto::folder(store, f.id)
    })
}

/// `folder_rename({ id, name })`.
pub fn rename_folder(state: &AppState, id: &str, name: &str) -> IpcResult<FolderDto> {
    let id = dto::folder_id("id", id)?;
    let name = validate_name(name)?;
    state.with_ready(|_, store| {
        store.rename_folder(id, &name)?;
        dto::folder(store, id)
    })
}

/// `folder_move({ id, parentId })`.
pub fn move_folder(state: &AppState, id: &str, parent_id: &str) -> IpcResult<FolderDto> {
    let id = dto::folder_id("id", id)?;
    let parent = dto::folder_id("parentId", parent_id)?;
    state.with_ready(|_, store| {
        // The store reports moving the root as a cycle (every folder descends from it);
        // the UI expects the clearer `tree.root`.
        if store.get_folder(id)?.parent.is_none() {
            return Err(IpcError::new("tree.root", "the root folder cannot be moved"));
        }
        store.move_folder(id, parent)?;
        dto::folder(store, id)
    })
}

/// `folder_set_default_credential({ id, credentialId })`.
pub fn set_default_credential(
    state: &AppState,
    id: &str,
    credential_id: Option<&str>,
) -> IpcResult<FolderDto> {
    let id = dto::folder_id("id", id)?;
    let cred = dto::opt_credential_id("credentialId", credential_id)?;
    state.with_ready(|_, store| {
        store.set_folder_default_credential(id, cred)?;
        dto::folder(store, id)
    })
}

/// `folder_delete({ id })`: cascades; the root is refused with `tree.root`.
pub fn delete_folder(state: &AppState, id: &str) -> IpcResult<()> {
    let id = dto::folder_id("id", id)?;
    state.with_ready(|_, store| Ok(store.delete_folder(id)?))
}

/// `connection_create(fields)`.
pub fn create_connection(state: &AppState, fields: ConnectionFields) -> IpcResult<ConnectionDto> {
    let c = fields.into_connection(None)?;
    state.with_ready(|_, store| {
        let stored = store.create_connection(&c)?;
        // ADR-0014 K4: a Kubernetes credential must fit the connection's options.
        if let Err(e) = crate::commands::kube::save_check(store, stored.id) {
            store.delete_connection(stored.id)?;
            return Err(e);
        }
        dto::connection(store, &stored)
    })
}

/// `connection_update({ id, ...fields })`.
pub fn update_connection(
    state: &AppState,
    id: &str,
    fields: ConnectionFields,
) -> IpcResult<ConnectionDto> {
    let id = dto::connection_id("id", id)?;
    let mut c = fields.into_connection(Some(id))?;
    state.with_ready(|_, store| {
        let before = store.get_connection(id)?;
        c.created_at = before.created_at;
        let stored = store.update_connection(&c)?;
        // ADR-0014 K4: a Kubernetes credential must fit the connection's options.
        if let Err(e) = crate::commands::kube::save_check(store, id) {
            store.update_connection(&before)?;
            return Err(e);
        }
        dto::connection(store, &stored)
    })
}

/// `connection_move({ id, folderId })`.
pub fn move_connection(state: &AppState, id: &str, folder_id: &str) -> IpcResult<ConnectionDto> {
    let id = dto::connection_id("id", id)?;
    let folder = dto::folder_id("folderId", folder_id)?;
    state.with_ready(|_, store| {
        let mut c = store.get_connection(id)?;
        c.folder = folder;
        let stored = store.update_connection(&c)?;
        dto::connection(store, &stored)
    })
}

/// `connection_delete({ id })`.
pub fn delete_connection(state: &AppState, id: &str) -> IpcResult<()> {
    let id = dto::connection_id("id", id)?;
    state.with_ready(|_, store| Ok(store.delete_connection(id)?))?;
    // ADR-0013: a persistent web store does not outlive its connection.
    if let Err(e) = crate::web::remove_store_dir(state, &id.to_string()) {
        tracing::warn!(code = e.code, "web store of a deleted connection kept");
    }
    Ok(())
}

/// `connection_set_role_credential({ id, role, credentialId })`: `role` is `gateway` or
/// `become`; an incompatible credential fails with `credential.incompatible`.
pub fn set_role_credential(
    state: &AppState,
    id: &str,
    role: &str,
    credential_id: Option<&str>,
) -> IpcResult<ConnectionDto> {
    let id = dto::connection_id("id", id)?;
    let role = Role::parse(role)
        .filter(|r| *r != Role::Primary)
        .ok_or_else(|| IpcError::invalid("role", "must be gateway or become"))?;
    let cred = dto::opt_credential_id("credentialId", credential_id)?;
    state.with_ready(|_, store| {
        let c = store.set_connection_role_credential(id, role, cred)?;
        dto::connection(store, &c)
    })
}

/// `connection_search({ query, limit })`: limit clamped to `1..=200`.
pub fn search(state: &AppState, query: &str, limit: u32) -> IpcResult<Vec<HitDto>> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(IpcError::invalid("query", "longer than 1024 bytes"));
    }
    let limit = usize::try_from(limit).unwrap_or(MAX_SEARCH_LIMIT).clamp(1, MAX_SEARCH_LIMIT);
    state.with_ready(|_, store| Ok(store.search(query, limit)?.iter().map(HitDto::from).collect()))
}

/// Root folder id (tests and first-start helpers).
#[cfg(any(test, feature = "test-util"))]
pub fn root_id(store: &mooring_store::Store) -> mooring_core::FolderId {
    store.root_folder().expect("query").expect("root").id
}

// ------------------------------------------------------------------ Tauri wrappers

/// `tree_list()`.
#[tauri::command]
pub fn tree_list(state: State<'_, AppState>) -> IpcResult<TreeDto> {
    list(&state)
}

/// `folder_create({ parentId, name })`.
#[tauri::command]
pub fn folder_create(
    state: State<'_, AppState>,
    parent_id: String,
    name: String,
) -> IpcResult<FolderDto> {
    create_folder(&state, &parent_id, &name)
}

/// `folder_rename({ id, name })`.
#[tauri::command]
pub fn folder_rename(state: State<'_, AppState>, id: String, name: String) -> IpcResult<FolderDto> {
    rename_folder(&state, &id, &name)
}

/// `folder_move({ id, parentId })`.
#[tauri::command]
pub fn folder_move(
    state: State<'_, AppState>,
    id: String,
    parent_id: String,
) -> IpcResult<FolderDto> {
    move_folder(&state, &id, &parent_id)
}

/// `folder_set_default_credential({ id, credentialId })`.
#[tauri::command]
pub fn folder_set_default_credential(
    state: State<'_, AppState>,
    id: String,
    credential_id: Option<String>,
) -> IpcResult<FolderDto> {
    set_default_credential(&state, &id, credential_id.as_deref())
}

/// `folder_delete({ id })`.
#[tauri::command]
pub fn folder_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    delete_folder(&state, &id)
}

/// `connection_create({ folderId, name, protocol, host, port, credentialId, usernameOverride,
/// domainOverride, gatewayCredentialId, becomeCredentialId, tags })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one argument per ADR-0008/0009 field
pub fn connection_create(
    state: State<'_, AppState>,
    folder_id: String,
    name: String,
    protocol: String,
    host: String,
    port: Option<u32>,
    credential_id: Option<String>,
    username_override: Option<String>,
    domain_override: Option<String>,
    gateway_credential_id: Option<String>,
    become_credential_id: Option<String>,
    tags: Option<Vec<String>>,
) -> IpcResult<ConnectionDto> {
    let fields = ConnectionFields {
        folder_id,
        name,
        protocol,
        host,
        port,
        credential_id,
        username_override,
        domain_override,
        gateway_credential_id,
        become_credential_id,
        tags: tags.unwrap_or_default(),
    };
    create_connection(&state, fields)
}

/// `connection_update({ id, ...connection_create fields })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one argument per ADR-0008/0009 field
pub fn connection_update(
    state: State<'_, AppState>,
    id: String,
    folder_id: String,
    name: String,
    protocol: String,
    host: String,
    port: Option<u32>,
    credential_id: Option<String>,
    username_override: Option<String>,
    domain_override: Option<String>,
    gateway_credential_id: Option<String>,
    become_credential_id: Option<String>,
    tags: Option<Vec<String>>,
) -> IpcResult<ConnectionDto> {
    let fields = ConnectionFields {
        folder_id,
        name,
        protocol,
        host,
        port,
        credential_id,
        username_override,
        domain_override,
        gateway_credential_id,
        become_credential_id,
        tags: tags.unwrap_or_default(),
    };
    update_connection(&state, &id, fields)
}

/// `connection_set_role_credential({ id, role, credentialId })`.
#[tauri::command]
pub fn connection_set_role_credential(
    state: State<'_, AppState>,
    id: String,
    role: String,
    credential_id: Option<String>,
) -> IpcResult<ConnectionDto> {
    set_role_credential(&state, &id, &role, credential_id.as_deref())
}

/// `connection_move({ id, folderId })`.
#[tauri::command]
pub fn connection_move(
    state: State<'_, AppState>,
    id: String,
    folder_id: String,
) -> IpcResult<ConnectionDto> {
    move_connection(&state, &id, &folder_id)
}

/// `connection_delete({ id })`: also closes the connection's web window (ADR-0013).
#[tauri::command]
pub fn connection_delete<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    id: String,
) -> IpcResult<()> {
    delete_connection(&state, &id)?;
    crate::commands::web::close_for_deleted(&app, &state, &id);
    Ok(())
}

/// `connection_search({ query, limit })`.
#[tauri::command]
pub fn connection_search(
    state: State<'_, AppState>,
    query: String,
    limit: u32,
) -> IpcResult<Vec<HitDto>> {
    search(&state, &query, limit)
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
