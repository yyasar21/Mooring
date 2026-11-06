//! Importer apply (ADR-0019 §3): one plan goes into a **new** folder under the root in one
//! transaction. Nothing is merged or overwritten; a failure on any item rolls everything back.
//! The batch is plain data keyed by plan keys; the store assigns the ids.

use std::collections::HashMap;

use mooring_core::credential::check_compatible;
use mooring_core::{
    Connection, ConnectionId, CredentialFields, CredentialId, CredentialKind, FolderId, Protocol,
    Role,
};
use mooring_vault::Vault;
use rusqlite::params;

use crate::connections::{validate, write_tags};
use crate::credentials::{otp_consistent, prepare, put_secret, seal, Secrets};
use crate::error::{invalid, Result, StoreError};
use crate::util::{check_name, fmt_ts, now};
use crate::Store;

/// A folder of the batch; `parent == None` means the new import root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFolder {
    /// Plan key.
    pub key: String,
    /// Parent plan key.
    pub parent: Option<String>,
    /// Name.
    pub name: String,
}

/// A connection of the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportConnection {
    /// Folder plan key, `None` for the import root.
    pub folder: Option<String>,
    /// Name.
    pub name: String,
    /// Protocol.
    pub protocol: Protocol,
    /// Host.
    pub host: String,
    /// Port.
    pub port: Option<u16>,
    /// Credential plan key.
    pub credential: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
}

/// A credential of the batch; secrets are sealed inside the transaction.
#[derive(Debug)]
pub struct ImportCredential<'a> {
    /// Plan key.
    pub key: String,
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: CredentialKind,
    /// Plaintext fields (UI JSON shape).
    pub fields: serde_json::Value,
    /// Plaintext secrets, by name.
    pub secrets: Secrets<'a>,
}

/// Everything one apply writes.
#[derive(Debug, Default)]
pub struct ImportBatch<'a> {
    /// Name of the new root subfolder (`Imported from … (date)`).
    pub root_name: String,
    /// Folders, parents before children.
    pub folders: Vec<ImportFolder>,
    /// Connections.
    pub connections: Vec<ImportConnection>,
    /// Credentials.
    pub credentials: Vec<ImportCredential<'a>>,
}

/// What was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    /// The new root subfolder.
    pub root: FolderId,
    /// Folders created under it (not counting the root itself).
    pub folders: usize,
    /// Connections created.
    pub connections: usize,
    /// Credentials created.
    pub credentials: usize,
    /// Secrets sealed.
    pub secrets: usize,
}

fn insert_folder(tx: &rusqlite::Connection, parent: FolderId, name: &str) -> Result<FolderId> {
    let name = check_name("name", name)?;
    let id = FolderId::new();
    let ts = fmt_ts(now())?;
    tx.execute(
        "INSERT INTO folder (id, parent_id, name, default_credential_id, sort, created_at, updated_at)
         VALUES (?1, ?2, ?3, NULL, 0, ?4, ?4)",
        params![id.to_string(), parent.to_string(), name, ts],
    )?;
    Ok(id)
}

fn insert_credential(
    tx: &rusqlite::Connection,
    vault: &Vault,
    c: &ImportCredential<'_>,
) -> Result<(CredentialId, CredentialFields, usize)> {
    let name = check_name("name", &c.name)?;
    let mut f = CredentialFields::from_input(c.kind, &c.fields, None)?;
    prepare(&mut f, &c.secrets)?;
    let schema = c.kind.schema();
    if let Some(missing) = schema
        .secret_names()
        .find(|n| schema.secret(*n).is_some_and(|s| s.required) && !c.secrets.contains_key(n))
    {
        return Err(StoreError::Invalid { field: missing.as_str(), reason: "is required".into() });
    }
    otp_consistent(&mut f, c.secrets.contains_key(&mooring_core::SecretName::OtpSeed))?;
    let id = CredentialId::new();
    let ts = fmt_ts(now())?;
    tx.execute(
        "INSERT INTO credential (id, name, kind, fields_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![id.to_string(), name, c.kind.name(), f.to_json()?, ts],
    )?;
    for (n, plain) in &c.secrets {
        put_secret(tx, id, n.as_str(), &seal(vault, id, n.as_str(), plain)?)?;
    }
    Ok((id, f, c.secrets.len()))
}

fn insert_connection(tx: &rusqlite::Connection, c: &Connection) -> Result<()> {
    let v = validate(c)?;
    tx.execute(
        "INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id,
                                 created_at, updated_at, username_override, domain_override)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, NULL, NULL)",
        params![
            c.id.to_string(),
            c.folder.to_string(),
            v.name,
            c.protocol.name(),
            v.host,
            c.port,
            c.credential.map(|x| x.to_string()),
            fmt_ts(c.created_at)?,
        ],
    )?;
    write_tags(tx, c.id, &v.tags)
}

impl Store {
    /// Apply `batch` under a new subfolder of the root, all or nothing. Every item is
    /// validated again here (names, hosts, tags, credential fields and secrets, credential /
    /// protocol compatibility); the first failure rolls the transaction back.
    pub fn import_apply(&self, vault: &Vault, batch: &ImportBatch<'_>) -> Result<ImportOutcome> {
        let root = self.root_folder()?.ok_or_else(|| StoreError::Tree("no root folder".into()))?;
        let tx = self.conn.unchecked_transaction()?;
        let import_root = insert_folder(&tx, root.id, &batch.root_name)?;
        let mut folders: HashMap<&str, FolderId> = HashMap::new();
        for f in &batch.folders {
            let parent = match &f.parent {
                None => import_root,
                Some(p) => *folders
                    .get(p.as_str())
                    .ok_or_else(|| invalid("folder", "unknown parent key"))?,
            };
            let id = insert_folder(&tx, parent, &f.name)?;
            folders.insert(&f.key, id);
        }
        let mut creds: HashMap<&str, (CredentialId, CredentialFields)> = HashMap::new();
        let mut secrets = 0;
        for c in &batch.credentials {
            let (id, fields, n) = insert_credential(&tx, vault, c)?;
            secrets += n;
            creds.insert(&c.key, (id, fields));
        }
        for c in &batch.connections {
            let folder = match &c.folder {
                None => import_root,
                Some(k) => *folders
                    .get(k.as_str())
                    .ok_or_else(|| invalid("folder", "unknown folder key"))?,
            };
            let credential = match &c.credential {
                None => None,
                Some(k) => {
                    let (id, fields) = creds
                        .get(k.as_str())
                        .ok_or_else(|| invalid("credential", "unknown credential key"))?;
                    check_compatible(fields, c.protocol, Role::Primary)?;
                    Some(*id)
                }
            };
            let mut conn = Connection::new(folder, c.name.clone(), c.protocol, c.host.clone())?;
            conn.id = ConnectionId::new();
            conn.port = c.port;
            conn.credential = credential;
            conn.tags.clone_from(&c.tags);
            insert_connection(&tx, &conn)?;
        }
        tx.commit()?;
        tracing::info!(
            folders = batch.folders.len(),
            connections = batch.connections.len(),
            credentials = batch.credentials.len(),
            "import applied"
        );
        Ok(ImportOutcome {
            root: import_root,
            folders: batch.folders.len(),
            connections: batch.connections.len(),
            credentials: batch.credentials.len(),
            secrets,
        })
    }
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
