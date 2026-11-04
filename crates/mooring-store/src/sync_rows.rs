//! Raw row export / import for vault sync (ADR-0017 §1, task S1).
//!
//! The sync crate builds its logical snapshot from [`SyncRows`] and writes a merged snapshot
//! back with [`Store::replace_sync_rows`]. Rows are carried as stored: ids, timestamps and the
//! JSON columns verbatim, sealed credential secrets as their sealed JSON (bound to credential
//! id + secret name under the DEK, so they stay valid on every device of the vault).
//!
//! Device-local sync bookkeeping (`sync.*` keys: counter, hash, sealed base) lives in the
//! `setting` table behind [`Store::sync_setting`] / [`Store::set_sync_setting`].

use std::collections::BTreeMap;

use mooring_core::{ConnectionId, CredentialId, FolderId};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::connections::normalise_tags;
use crate::error::invalid;
use crate::util::{check_name, parse_id, parse_opt_id, parse_ts, protocol_from_str};
use crate::{schema, Result, Store, StoreError};

/// Prefix of the device-local sync keys.
pub const SYNC_PREFIX: &str = "sync.";
/// Longest sync setting value (the sealed base snapshot, hex in JSON).
pub const MAX_SYNC_VALUE: usize = 160 << 20;

/// One `folder` row. Fields are in alphabetical order (canonical JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRow {
    /// RFC 3339.
    pub created_at: String,
    /// Default credential id.
    pub default_credential_id: Option<String>,
    /// Folder id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Parent folder id; `None` for the root.
    pub parent_id: Option<String>,
    /// Sort key.
    pub sort: i64,
    /// RFC 3339.
    pub updated_at: String,
}

/// One `connection` row with its tags and role credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRow {
    /// RFC 3339.
    pub created_at: String,
    /// Primary credential id.
    pub credential_id: Option<String>,
    /// Domain override.
    pub domain_override: Option<String>,
    /// Folder id.
    pub folder_id: String,
    /// Host.
    pub host: String,
    /// Connection id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// `options_json`, verbatim.
    pub options_json: String,
    /// Port.
    pub port: Option<u16>,
    /// Protocol name.
    pub protocol: String,
    /// Role (`gateway`, `become`) → credential id.
    pub roles: BTreeMap<String, String>,
    /// Tags, sorted.
    pub tags: Vec<String>,
    /// RFC 3339.
    pub updated_at: String,
    /// Username override.
    pub username_override: Option<String>,
}

/// One `credential` row with its sealed secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRow {
    /// RFC 3339.
    pub created_at: String,
    /// `fields_json`, verbatim (plaintext fields, ADR-0009).
    pub fields_json: String,
    /// Credential id.
    pub id: String,
    /// Kind name.
    pub kind: String,
    /// Display name.
    pub name: String,
    /// Secret name → sealed JSON (`{"nonce":…,"ciphertext":…}`), never opened here.
    pub secrets: BTreeMap<String, String>,
    /// RFC 3339.
    pub updated_at: String,
}

/// Every synced row of the store, keyed by id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRows {
    /// Connections.
    pub connections: BTreeMap<String, ConnectionRow>,
    /// Credentials.
    pub credentials: BTreeMap<String, CredentialRow>,
    /// Folders.
    pub folders: BTreeMap<String, FolderRow>,
}

fn check_sync_key(key: &str) -> Result<()> {
    let rest = key.strip_prefix(SYNC_PREFIX).ok_or_else(|| invalid("key", "not a sync key"))?;
    if rest.is_empty()
        || key.len() > 64
        || !rest.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    {
        return Err(invalid("key", "must be sync.[a-z_]+, at most 64 bytes"));
    }
    Ok(())
}

impl Store {
    /// Read a device-local sync setting (`sync.*`).
    pub fn sync_setting(&self, key: &str) -> Result<Option<String>> {
        check_sync_key(key)?;
        schema::get_setting(&self.conn, key)
    }

    /// Write a device-local sync setting; `None` deletes it.
    pub fn set_sync_setting(&self, key: &str, value: Option<&str>) -> Result<()> {
        check_sync_key(key)?;
        match value {
            Some(v) if v.len() > MAX_SYNC_VALUE => Err(invalid("value", "too large")),
            Some(v) => schema::put_setting(&self.conn, key, v),
            None => {
                self.conn.execute("DELETE FROM setting WHERE key = ?1", [key])?;
                Ok(())
            }
        }
    }

    /// Export every folder, connection and credential row. Refused while legacy secrets wait
    /// for their reseal (their sealed names would not be valid on another device).
    pub fn export_sync_rows(&self) -> Result<SyncRows> {
        if self.reseal_pending()? {
            return Err(invalid("store", "legacy secrets are pending reseal; unlock first"));
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut rows = SyncRows::default();
        let mut st = tx.prepare(
            "SELECT id, parent_id, name, default_credential_id, sort, created_at, updated_at
             FROM folder",
        )?;
        for f in st.query_map([], |r| {
            Ok(FolderRow {
                id: r.get(0)?,
                parent_id: r.get(1)?,
                name: r.get(2)?,
                default_credential_id: r.get(3)?,
                sort: r.get(4)?,
                created_at: r.get(5)?,
                updated_at: r.get(6)?,
            })
        })? {
            let f = f?;
            rows.folders.insert(f.id.clone(), f);
        }
        let mut st = tx.prepare(
            "SELECT id, folder_id, name, protocol, host, port, credential_id, created_at,
                    updated_at, username_override, domain_override, options_json FROM connection",
        )?;
        for c in st.query_map([], |r| {
            Ok(ConnectionRow {
                id: r.get(0)?,
                folder_id: r.get(1)?,
                name: r.get(2)?,
                protocol: r.get(3)?,
                host: r.get(4)?,
                port: r.get(5)?,
                credential_id: r.get(6)?,
                created_at: r.get(7)?,
                updated_at: r.get(8)?,
                username_override: r.get(9)?,
                domain_override: r.get(10)?,
                options_json: r.get(11)?,
                roles: BTreeMap::new(),
                tags: Vec::new(),
            })
        })? {
            let c = c?;
            rows.connections.insert(c.id.clone(), c);
        }
        let mut st = tx.prepare("SELECT connection_id, tag FROM connection_tag ORDER BY tag")?;
        for t in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, tag) = t?;
            if let Some(c) = rows.connections.get_mut(&id) {
                c.tags.push(tag);
            }
        }
        let mut st =
            tx.prepare("SELECT connection_id, role, credential_id FROM connection_credential")?;
        for t in st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })? {
            let (id, role, cred) = t?;
            if let Some(c) = rows.connections.get_mut(&id) {
                c.roles.insert(role, cred);
            }
        }
        let mut st = tx.prepare(
            "SELECT id, name, kind, fields_json, created_at, updated_at FROM credential",
        )?;
        for c in st.query_map([], |r| {
            Ok(CredentialRow {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                fields_json: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                secrets: BTreeMap::new(),
            })
        })? {
            let c = c?;
            rows.credentials.insert(c.id.clone(), c);
        }
        let mut st = tx.prepare("SELECT credential_id, name, sealed FROM credential_secret")?;
        for s in st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
        })? {
            let (id, name, blob) = s?;
            let text = String::from_utf8(blob)
                .map_err(|_| StoreError::Corrupt { what: "sealed value" })?;
            if let Some(c) = rows.credentials.get_mut(&id) {
                c.secrets.insert(name, text);
            }
        }
        Ok(rows)
    }

    /// Bind this store to another vault for `vault_join` (ADR-0017 §5): a fresh device first
    /// creates a bootstrap vault, then adopts the remote one. Refused while the store holds
    /// any connection (only an empty bootstrap store may change vaults).
    pub fn rebind_vault_for_join(&self, vault_id: &str) -> Result<()> {
        let uuid = uuid::Uuid::parse_str(vault_id.trim())
            .map_err(|_| invalid("vault_id", "not a UUID"))?;
        if uuid.is_nil() {
            return Err(invalid("vault_id", "nil UUID"));
        }
        let tx = self.conn.unchecked_transaction()?;
        let connections: i64 = tx.query_row("SELECT COUNT(*) FROM connection", [], |r| r.get(0))?;
        if connections > 0 {
            return Err(invalid("store", "holds connections; only an empty store can join"));
        }
        schema::put_setting(&tx, schema::KEY_VAULT_ID, &uuid.hyphenated().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Replace every folder, connection and credential row with `rows` in one transaction
    /// (foreign keys deferred to the commit). Ids, names, protocols, ports and timestamps are
    /// validated; the schema's `CHECK`s cover kinds, roles and the JSON columns.
    ///
    /// Credentials are upserted, not deleted and re-inserted: `secret_source.credential_id` is
    /// `ON DELETE RESTRICT`, which `SQLite` enforces at once even with deferred keys. Secret
    /// sources are device-local (not synced), so the login credential of one is kept even when
    /// `rows` lacks it.
    pub fn replace_sync_rows(&self, rows: &SyncRows) -> Result<()> {
        validate(rows)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            "PRAGMA defer_foreign_keys = ON;
             DELETE FROM connection_tag; DELETE FROM connection_credential;
             DELETE FROM credential_secret; DELETE FROM connection; DELETE FROM folder;",
        )?;
        let stale: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT id FROM credential WHERE id NOT IN
                     (SELECT credential_id FROM secret_source WHERE credential_id IS NOT NULL)",
            )?;
            let ids = st.query_map([], |r| r.get::<_, String>(0))?;
            ids.filter(|id| id.as_ref().map_or(true, |id| !rows.credentials.contains_key(id)))
                .collect::<rusqlite::Result<_>>()?
        };
        for id in &stale {
            tx.execute("DELETE FROM credential WHERE id = ?1", params![id])?;
        }
        for c in rows.credentials.values() {
            tx.execute(
                "INSERT INTO credential (id, name, kind, fields_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
                     fields_json = excluded.fields_json, created_at = excluded.created_at,
                     updated_at = excluded.updated_at",
                params![c.id, c.name, c.kind, c.fields_json, c.created_at, c.updated_at],
            )?;
            for (name, sealed) in &c.secrets {
                tx.execute(
                    "INSERT INTO credential_secret (credential_id, name, sealed) VALUES (?1, ?2, ?3)",
                    params![c.id, name, sealed.as_bytes()],
                )?;
            }
        }
        for f in rows.folders.values() {
            tx.execute(
                "INSERT INTO folder (id, parent_id, name, default_credential_id, sort, created_at,
                                     updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    f.id,
                    f.parent_id,
                    f.name,
                    f.default_credential_id,
                    f.sort,
                    f.created_at,
                    f.updated_at
                ],
            )?;
        }
        for c in rows.connections.values() {
            tx.execute(
                "INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id,
                     created_at, updated_at, username_override, domain_override, options_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    c.id,
                    c.folder_id,
                    c.name,
                    c.protocol,
                    c.host,
                    c.port,
                    c.credential_id,
                    c.created_at,
                    c.updated_at,
                    c.username_override,
                    c.domain_override,
                    c.options_json
                ],
            )?;
            for tag in &c.tags {
                tx.execute(
                    "INSERT INTO connection_tag (connection_id, tag) VALUES (?1, ?2)",
                    params![c.id, tag],
                )?;
            }
            for (role, cred) in &c.roles {
                tx.execute(
                    "INSERT INTO connection_credential (connection_id, role, credential_id)
                     VALUES (?1, ?2, ?3)",
                    params![c.id, role, cred],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn validate(rows: &SyncRows) -> Result<()> {
    for (key, f) in &rows.folders {
        if key != &f.id {
            return Err(invalid("folder", "key does not match id"));
        }
        parse_id::<FolderId>(&f.id)?;
        parse_opt_id::<FolderId>(f.parent_id.as_deref())?;
        parse_opt_id::<CredentialId>(f.default_credential_id.as_deref())?;
        check_name("folder.name", &f.name)?;
        parse_ts(&f.created_at)?;
        parse_ts(&f.updated_at)?;
    }
    for (key, c) in &rows.connections {
        if key != &c.id {
            return Err(invalid("connection", "key does not match id"));
        }
        parse_id::<ConnectionId>(&c.id)?;
        parse_id::<FolderId>(&c.folder_id)?;
        parse_opt_id::<CredentialId>(c.credential_id.as_deref())?;
        check_name("connection.name", &c.name)?;
        mooring_core::validate_host(&c.host)?;
        protocol_from_str(&c.protocol)?;
        if c.port == Some(0) {
            return Err(invalid("connection.port", "0"));
        }
        if normalise_tags(&c.tags)? != c.tags {
            return Err(invalid("connection.tags", "not normalised"));
        }
        for cred in c.roles.values() {
            parse_id::<CredentialId>(cred)?;
        }
        parse_ts(&c.created_at)?;
        parse_ts(&c.updated_at)?;
    }
    for (key, c) in &rows.credentials {
        if key != &c.id {
            return Err(invalid("credential", "key does not match id"));
        }
        parse_id::<CredentialId>(&c.id)?;
        check_name("credential.name", &c.name)?;
        parse_ts(&c.created_at)?;
        parse_ts(&c.updated_at)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "sync_rows_tests.rs"]
mod tests;
