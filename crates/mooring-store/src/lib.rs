//! Mooring local store (ADR-0005).
//!
//! One `SQLite` database per application holds folders, connections, tags and credentials.
//! Credential secrets live in sealed columns: the caller passes an unlocked
//! [`mooring_vault::Vault`] and every secret is sealed with record id = credential id and
//! field = column name, so a sealed value cannot be moved between rows or columns. The store
//! itself never derives or holds key material.
//!
//! * [`Store::open`] / [`Store::open_in_memory`] — pragmas + migrations ([`schema`])
//! * folders, connections + tags, credentials, inheritance — methods on [`Store`]
//! * [`Store::search`] — FTS5 prefix search over connection name, host and tags
//! * [`Store::connection_options`] — per-protocol options (`options_json`, migration 0005)

#![forbid(unsafe_code)]

mod app_settings;
mod connections;
mod credentials;
mod error;
mod folders;
mod legacy;
mod options;
mod roles;
pub mod schema;
mod search;
#[doc(hidden)]
pub mod testing;
mod util;

use std::path::{Path, PathBuf};

use rusqlite::Connection;

pub use app_settings::{APP_PREFIX, MAX_APP_KEY, MAX_APP_VALUE};
pub use credentials::{CredentialMeta, Secrets};
pub use error::{Result, StoreError};
pub use mooring_core::{CredentialKind, Role, SecretName};
pub use roles::Resolved;
pub use search::{ConnectionHit, MAX_SEARCH_LIMIT};

/// Input limits, owned by `mooring_core::model` and re-exported for callers of the store.
pub use mooring_core::model::{MAX_HOST, MAX_NAME, MAX_TAG, MAX_TAGS};

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
    ///
    /// On unix the database file is created (or reset) to mode `0600` before `SQLite` opens
    /// it; `SQLite` copies that mode to `-wal` and `-shm`, so the plaintext inventory is not
    /// readable by other local accounts whatever the umask (review M2).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        restrict_db_file(&path)?;
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

    /// Purge deleted search tokens (FTS merge), then checkpoint the WAL into the main file and
    /// truncate `-wal` (file stores only). Also runs, best effort, when the store is dropped.
    pub fn checkpoint(&self) -> Result<()> {
        if self.path.is_some() {
            schema::purge_search(&self.conn)?;
            schema::checkpoint_truncate(&self.conn)?;
        }
        Ok(())
    }

    /// Close the store: checkpoint the WAL, then drop the connection. Use this instead of a
    /// plain drop when the caller wants to see a checkpoint error.
    pub fn close(self) -> Result<()> {
        self.checkpoint()
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
    ///
    /// The nil UUID is refused: a v1 vault header reports nil until its first password unlock
    /// assigns a real id, and binding to nil would pin the store to a value no vault will ever
    /// have again (A1-QA-2). Bind only after the vault has been unlocked.
    pub fn set_vault_id(&self, vault_id: &str) -> Result<()> {
        let uuid = uuid::Uuid::parse_str(vault_id.trim())
            .map_err(|_| error::invalid("vault_id", "not a UUID"))?;
        if uuid.is_nil() {
            return Err(error::invalid(
                "vault_id",
                "nil UUID (vault header not upgraded yet; unlock the vault first)",
            ));
        }
        let id = uuid.hyphenated().to_string();
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

/// Create the database file owner-only (unix), or tighten an existing one.
#[cfg(unix)]
fn restrict_db_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let io = |_: std::io::Error| error::invalid("path", "cannot create the database file");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(io)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)
}

/// Windows: the per-user `AppData` ACL already restricts access (review M2).
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_db_file(_path: &Path) -> Result<()> {
    Ok(())
}

impl Drop for Store {
    fn drop(&mut self) {
        if let Err(e) = self.checkpoint() {
            tracing::warn!(error = %e, "store checkpoint on close failed");
        }
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
        let nil = uuid::Uuid::nil().to_string();
        assert!(matches!(s.set_vault_id(&nil), Err(StoreError::Invalid { field: "vault_id", .. })));
        assert_eq!(s.vault_id().expect("get"), None, "nil is not recorded");
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
