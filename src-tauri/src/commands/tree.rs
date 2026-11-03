//! Connection tree commands (ADR-0008 §Tree). Every command needs an unlocked vault: the tree
//! is vault-derived state in the UI (lock wipes it), and it keeps the store bound to its vault.

use mooring_core::{validate_name, Connection, ConnectionId};
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
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
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
        c.created_at = store.get_connection(id)?.created_at;
        let stored = store.update_connection(&c)?;
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
    state.with_ready(|_, store| Ok(store.delete_connection(id)?))
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
#[cfg(test)]
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

/// `connection_create({ folderId, name, protocol, host, port, credentialId, tags })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one argument per ADR-0008 field
pub fn connection_create(
    state: State<'_, AppState>,
    folder_id: String,
    name: String,
    protocol: String,
    host: String,
    port: Option<u32>,
    credential_id: Option<String>,
    tags: Option<Vec<String>>,
) -> IpcResult<ConnectionDto> {
    let tags = tags.unwrap_or_default();
    let fields = ConnectionFields { folder_id, name, protocol, host, port, credential_id, tags };
    create_connection(&state, fields)
}

/// `connection_update({ id, folderId, name, protocol, host, port, credentialId, tags })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one argument per ADR-0008 field
pub fn connection_update(
    state: State<'_, AppState>,
    id: String,
    folder_id: String,
    name: String,
    protocol: String,
    host: String,
    port: Option<u32>,
    credential_id: Option<String>,
    tags: Option<Vec<String>>,
) -> IpcResult<ConnectionDto> {
    let tags = tags.unwrap_or_default();
    let fields = ConnectionFields { folder_id, name, protocol, host, port, credential_id, tags };
    update_connection(&state, &id, fields)
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

/// `connection_delete({ id })`.
#[tauri::command]
pub fn connection_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    delete_connection(&state, &id)
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
mod tests {
    use super::*;
    use crate::state::testing::*;

    fn root(state: &AppState) -> String {
        state.with_ready(|_, s| Ok(root_id(s).to_string())).expect("root")
    }

    fn fields(folder: &str, name: &str, host: &str) -> ConnectionFields {
        ConnectionFields {
            folder_id: folder.to_owned(),
            name: name.to_owned(),
            protocol: "ssh".to_owned(),
            host: host.to_owned(),
            port: None,
            credential_id: None,
            tags: vec!["lab".to_owned()],
        }
    }

    #[test]
    fn locked_vault_refuses_tree_access() {
        let f = unlocked();
        let root = root(&f.state);
        crate::commands::vault::lock(&f.state, None).expect("lock");
        assert_eq!(list(&f.state).expect_err("locked").code, "vault.locked");
        assert_eq!(create_folder(&f.state, &root, "x").expect_err("locked").code, "vault.locked");
        let e = search(&f.state, "x", 10).expect_err("locked");
        assert_eq!(e.code, "vault.locked");
    }

    #[test]
    fn folder_round_trip_and_tree_errors() {
        let f = unlocked();
        let root = root(&f.state);
        let a = create_folder(&f.state, &root, "  Servers ").expect("a");
        assert_eq!(a.name, "Servers");
        assert_eq!(a.parent_id.as_deref(), Some(root.as_str()));
        let b = create_folder(&f.state, &a.id, "okd").expect("b");
        assert_eq!(rename_folder(&f.state, &b.id, "OKD").expect("rename").name, "OKD");
        assert_eq!(move_folder(&f.state, &a.id, &b.id).expect_err("cycle").code, "tree.cycle");
        assert_eq!(move_folder(&f.state, &root, &a.id).expect_err("root").code, "tree.root");
        assert_eq!(delete_folder(&f.state, &root).expect_err("root").code, "tree.root");
        let missing = mooring_core::FolderId::new().to_string();
        assert_eq!(rename_folder(&f.state, &missing, "x").expect_err("nf").code, "tree.not_found");
        let moved = move_folder(&f.state, &b.id, &root).expect("move");
        assert_eq!(moved.parent_id.as_deref(), Some(root.as_str()));
        delete_folder(&f.state, &a.id).expect("delete");
        let tree = list(&f.state).expect("list");
        assert_eq!(tree.folders.len(), 2, "root + okd");
    }

    #[test]
    fn input_validation() {
        let f = unlocked();
        let root = root(&f.state);
        let cases = [
            create_folder(&f.state, "not-a-uuid", "x").map(drop),
            create_folder(&f.state, &root, "").map(drop),
            create_folder(&f.state, &root, &"n".repeat(121)).map(drop),
            create_folder(&f.state, &root, "a\u{7}b").map(drop),
            create_connection(&f.state, fields(&root, "x", "bad host")).map(drop),
            create_connection(&f.state, fields(&root, "x", &"h".repeat(2049))).map(drop),
            create_connection(
                &f.state,
                ConnectionFields { port: Some(0), ..fields(&root, "x", "h") },
            )
            .map(drop),
            create_connection(
                &f.state,
                ConnectionFields { protocol: "telnet".into(), ..fields(&root, "x", "h") },
            )
            .map(drop),
            create_connection(
                &f.state,
                ConnectionFields { tags: vec!["t".into(); 51], ..fields(&root, "x", "h") },
            )
            .map(drop),
            create_connection(
                &f.state,
                ConnectionFields { tags: vec!["t".repeat(65)], ..fields(&root, "x", "h") },
            )
            .map(drop),
            search(&f.state, &"q".repeat(MAX_QUERY_BYTES + 1), 10).map(drop),
        ];
        for (i, r) in cases.into_iter().enumerate() {
            assert_eq!(r.expect_err("must fail").code, "input.invalid", "case {i}");
        }
        let unknown_cred = ConnectionFields {
            credential_id: Some(mooring_core::CredentialId::new().to_string()),
            ..fields(&root, "x", "h")
        };
        let e = create_connection(&f.state, unknown_cred).expect_err("unknown credential");
        assert_eq!(e.code, "credential.not_found");
    }

    #[test]
    fn connection_round_trip_inheritance_and_search() {
        let f = unlocked();
        let root = root(&f.state);
        let prod = create_folder(&f.state, &root, "prod").expect("prod");
        let cred = crate::commands::credentials::create(
            &f.state,
            crate::commands::credentials::NewCredential::password_for_tests("ops"),
        )
        .expect("cred");
        set_default_credential(&f.state, &prod.id, Some(&cred.id)).expect("default");

        let c = create_connection(&f.state, fields(&prod.id, "xinfra01", "10.10.20.5"))
            .expect("create");
        assert_eq!(c.credential_id, None);
        assert_eq!(c.effective_credential_id.as_deref(), Some(cred.id.as_str()), "inherited");
        assert_eq!(c.tags, ["lab"]);

        let mut upd = fields(&prod.id, "xinfra01-new", "10.10.20.6");
        upd.port = Some(2222);
        let u = update_connection(&f.state, &c.id, upd).expect("update");
        assert_eq!(
            (u.name.as_str(), u.port, u.created_at.as_str()),
            ("xinfra01-new", Some(2222), c.created_at.as_str())
        );

        let hits = search(&f.state, "xinfra", 0).expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].folder_id, prod.id);

        let m = move_connection(&f.state, &c.id, &root).expect("move");
        assert_eq!(m.folder_id, root);
        assert_eq!(m.effective_credential_id, None, "root has no default");

        let tree = list(&f.state).expect("list");
        assert_eq!(tree.connections.len(), 1);
        delete_connection(&f.state, &c.id).expect("delete");
        assert_eq!(delete_connection(&f.state, &c.id).expect_err("gone").code, "tree.not_found");
    }
}
