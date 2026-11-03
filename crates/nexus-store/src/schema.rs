//! Embedded migrations, connection pragmas and the `setting` table.
//!
//! Migrations are numbered SQL scripts under `migrations/`, embedded at compile time. All
//! pending scripts run in one `IMMEDIATE` transaction and `schema_version` is written last, so
//! a crash mid-migration leaves the previous version intact. A database whose version is newer
//! than [`LATEST`] is refused (no silent downgrade).

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::error::{Result, StoreError};

/// `(version, sql)`, strictly increasing. Never edit a shipped script; add a new one.
const MIGRATIONS: &[(u32, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

/// Highest schema version this build understands.
pub const LATEST: u32 = 1;

pub(crate) const KEY_SCHEMA_VERSION: &str = "schema_version";
pub(crate) const KEY_VAULT_ID: &str = "vault_id";

/// Busy timeout for concurrent writers (WAL readers never block).
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Pragmas applied to every connection. WAL only for file databases.
pub(crate) fn configure(conn: &Connection, file_backed: bool) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "secure_delete", true)?;
    if file_backed {
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            tracing::warn!(mode = %mode, "SQLite refused WAL journal mode");
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
    }
    let fk: bool = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
    if !fk {
        return Err(StoreError::Corrupt { what: "foreign_keys pragma" });
    }
    Ok(())
}

/// Current schema version; 0 for an empty database.
pub(crate) fn current_version(conn: &Connection) -> Result<u32> {
    let has_setting: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'setting')",
        [],
        |r| r.get(0),
    )?;
    if !has_setting {
        return Ok(0);
    }
    let v: Option<String> = conn
        .query_row("SELECT value FROM setting WHERE key = ?1", [KEY_SCHEMA_VERSION], |r| r.get(0))
        .optional()?;
    match v {
        None => Ok(0),
        Some(s) => s.parse().map_err(|_| StoreError::Corrupt { what: "schema_version" }),
    }
}

/// Apply every pending migration in one transaction, then rebuild the search index.
pub(crate) fn migrate(conn: &mut Connection) -> Result<u32> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found = current_version(&tx)?;
    if found > LATEST {
        return Err(StoreError::Downgrade { found, supported: LATEST });
    }
    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > found) {
        tx.execute_batch(sql)?;
        tracing::info!(version, "applied store migration");
    }
    if found < LATEST {
        tx.execute(
            "INSERT INTO setting (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (KEY_SCHEMA_VERSION, LATEST.to_string()),
        )?;
    }
    rebuild_search(&tx)?;
    tx.commit()?;
    Ok(LATEST)
}

/// Repopulate the contentless FTS index from `connection` + `connection_tag`.
/// Connection rowids are implicit and may be renumbered by `VACUUM`; rebuilding on open
/// keeps `search.rowid` aligned with `connection.rowid`.
fn rebuild_search(conn: &Connection) -> Result<()> {
    conn.execute("INSERT INTO search (search) VALUES ('delete-all')", [])?;
    conn.execute(
        "INSERT INTO search (rowid, name, host, tags)
         SELECT c.rowid, c.name, c.host,
                (SELECT coalesce(group_concat(t.tag, ' '), '') FROM connection_tag t
                 WHERE t.connection_id = c.id)
         FROM connection c",
        [],
    )?;
    Ok(())
}

pub(crate) fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM setting WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

pub(crate) fn put_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO setting (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_strictly_increasing_and_end_at_latest() {
        let mut prev = 0;
        for (v, _) in MIGRATIONS {
            assert!(*v > prev, "migration versions must increase");
            prev = *v;
        }
        assert_eq!(prev, LATEST);
    }

    #[test]
    fn migrate_from_empty_then_again_is_a_no_op() {
        let mut conn = Connection::open_in_memory().expect("open");
        configure(&conn, false).expect("pragmas");
        assert_eq!(current_version(&conn).expect("v"), 0);
        assert_eq!(migrate(&mut conn).expect("migrate"), LATEST);
        assert_eq!(current_version(&conn).expect("v"), LATEST);
        assert_eq!(migrate(&mut conn).expect("again"), LATEST);
    }

    #[test]
    fn newer_database_is_refused() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn).expect("migrate");
        put_setting(&conn, KEY_SCHEMA_VERSION, &(LATEST + 1).to_string()).expect("bump");
        assert!(matches!(migrate(&mut conn), Err(StoreError::Downgrade { .. })));
    }
}
