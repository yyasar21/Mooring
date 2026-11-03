//! Nexus Remote local store (ADR-0005).
//!
//! One `SQLite` database per application holds folders, connections, tags and credentials.
//! Credential secrets live in sealed columns: the caller passes an unlocked
//! [`nexus_vault::Vault`] and every secret is sealed with record id = credential id and
//! field = column name, so a sealed value cannot be moved between rows or columns. The store
//! itself never derives or holds key material.
//!
//! * [`Store::open`] / [`Store::open_in_memory`] — pragmas + migrations ([`schema`])
//! * folders, connections + tags, credentials, inheritance — methods on [`Store`]
//! * [`Store::search`] — FTS5 prefix search over connection name, host and tags

#![forbid(unsafe_code)]

mod connections;
mod credentials;
mod error;
mod folders;
pub mod schema;
mod search;
mod util;

use std::path::{Path, PathBuf};

use rusqlite::Connection;

pub use credentials::{CredentialKind, CredentialMeta, SecretField};
pub use error::{Result, StoreError};
pub use search::{ConnectionHit, MAX_SEARCH_LIMIT};

/// Maximum display-name length (characters), shared with `nexus_core::model`.
pub const MAX_NAME: usize = 120;
/// Maximum host length (bytes), shared with `nexus_core::model`.
pub const MAX_HOST: usize = 2048;
/// Maximum tag length (characters).
pub const MAX_TAG: usize = 64;
/// Maximum number of tags per connection.
pub const MAX_TAGS: usize = 50;

/// Handle to the database. Not `Sync`; wrap in a `Mutex` to share across threads.
pub struct Store {
    conn: Connection,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish_non_exhaustive()
    }
}

impl Store {
    /// Open (or create) a file-backed store: WAL, foreign keys, secure delete, migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        Self::init(conn, Some(path))
    }

    /// An in-memory store (tests, previews). No WAL.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(mut conn: Connection, path: Option<PathBuf>) -> Result<Self> {
        schema::configure(&conn, path.is_some())?;
        let version = schema::migrate(&mut conn)?;
        tracing::debug!(version, file_backed = path.is_some(), "store opened");
        Ok(Self { conn, path })
    }

    /// Schema version of the open database.
    pub fn schema_version(&self) -> Result<u32> {
        schema::current_version(&self.conn)
    }

    /// The vault this store belongs to, if recorded.
    pub fn vault_id(&self) -> Result<Option<String>> {
        schema::get_setting(&self.conn, schema::KEY_VAULT_ID)
    }

    /// Record the owning vault's id (text UUID). Idempotent for the same id; a different id
    /// is refused because A1 supports exactly one vault per app.
    pub fn set_vault_id(&self, vault_id: &str) -> Result<()> {
        let id = uuid::Uuid::parse_str(vault_id.trim())
            .map_err(|_| error::invalid("vault_id", "not a UUID"))?
            .hyphenated()
            .to_string();
        let tx = self.conn.unchecked_transaction()?;
        match schema::get_setting(&tx, schema::KEY_VAULT_ID)? {
            Some(existing) if existing == id => return Ok(()),
            Some(_) => return Err(StoreError::VaultIdMismatch),
            None => schema::put_setting(&tx, schema::KEY_VAULT_ID, &id)?,
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_id_is_set_once() {
        let s = Store::open_in_memory().expect("open");
        assert_eq!(s.vault_id().expect("get"), None);
        assert!(s.set_vault_id("not-a-uuid").is_err());
        let id = uuid::Uuid::new_v4().to_string();
        s.set_vault_id(&id).expect("set");
        s.set_vault_id(&id.to_uppercase()).expect("same id, other case");
        assert_eq!(s.vault_id().expect("get"), Some(id));
        let other = uuid::Uuid::new_v4().to_string();
        assert!(matches!(s.set_vault_id(&other), Err(StoreError::VaultIdMismatch)));
    }

    #[test]
    fn pragmas_are_on() {
        let s = Store::open_in_memory().expect("open");
        let fk: bool = s.conn.pragma_query_value(None, "foreign_keys", |r| r.get(0)).expect("fk");
        let sd: i64 = s.conn.pragma_query_value(None, "secure_delete", |r| r.get(0)).expect("sd");
        assert!(fk);
        assert_eq!(sd, 1);
        assert!(!format!("{s:?}").contains("conn"));
    }
}
