//! Embedded migrations, connection pragmas and the `setting` table.
//!
//! Migrations are numbered SQL scripts under `migrations/`, embedded at compile time. All
//! pending scripts run in one `IMMEDIATE` transaction and `schema_version` is written last, so
//! a crash mid-migration leaves the previous version intact. A database whose version is newer
//! than [`LATEST`] is refused (no silent downgrade).
//!
//! A script whose first line is [`FK_OFF_DIRECTIVE`] needs foreign keys off (a table rebuild
//! that would otherwise fire `ON DELETE` actions). The runner then sets `foreign_keys = OFF`
//! before `BEGIN` (the pragma is a no-op inside a transaction), requires `PRAGMA
//! foreign_key_check` to be empty before `COMMIT`, and turns foreign keys back on afterwards,
//! whatever the outcome.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::error::{Result, StoreError};

/// `(version, sql)`, contiguous from 1. Never edit a shipped script; add a new one.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_fts_secure_delete.sql")),
    (3, include_str!("../migrations/0003_typed_credentials.sql")),
    (4, include_str!("../migrations/0004_migrated_username.sql")),
    (5, include_str!("../migrations/0005_connection_options.sql")),
    (6, include_str!("../migrations/0006_vsphere_sync.sql")),
    (7, include_str!("../migrations/0007_secret_sources.sql")),
];

/// Highest schema version this build understands.
pub const LATEST: u32 = 7;

/// First line of a migration that must run with foreign keys off.
pub const FK_OFF_DIRECTIVE: &str = "-- mooring:foreign_keys=off";

pub(crate) const KEY_SCHEMA_VERSION: &str = "schema_version";
pub(crate) const KEY_VAULT_ID: &str = "vault_id";
pub(crate) const KEY_RESEAL_PENDING: &str = "credential_reseal_pending";

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

fn needs_fk_off(sql: &str) -> bool {
    sql.lines().next().is_some_and(|l| l.trim() == FK_OFF_DIRECTIVE)
}

/// Apply every pending migration in one transaction, then rebuild the search index.
pub(crate) fn migrate(conn: &mut Connection) -> Result<u32> {
    let found = current_version(conn)?;
    let fk_off = MIGRATIONS.iter().any(|(v, sql)| *v > found && needs_fk_off(sql));
    if fk_off {
        conn.pragma_update(None, "foreign_keys", false)?;
    }
    let result = migrate_in_tx(conn, fk_off);
    if fk_off {
        conn.pragma_update(None, "foreign_keys", true)?;
    }
    result
}

fn migrate_in_tx(conn: &mut Connection, check_fks: bool) -> Result<u32> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found = current_version(&tx)?;
    if found > LATEST {
        return Err(StoreError::Downgrade { found, supported: LATEST });
    }
    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > found) {
        tx.execute_batch(sql)?;
        tracing::info!(version, "applied store migration");
    }
    if check_fks {
        let violations: i64 =
            tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
        if violations != 0 {
            return Err(StoreError::Corrupt { what: "foreign keys after migration" });
        }
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

/// Merge the FTS index into one segment. The index is `contentless_delete = 1`, which records
/// deletes as tombstones: the FTS5 `secure-delete` option does not apply to that mode, so the
/// deleted tokens stay in segment pages until a merge. `optimize` is that merge; the freed
/// pages are then wiped by the `secure_delete` pragma (review L4).
pub(crate) fn purge_search(conn: &Connection) -> Result<()> {
    conn.execute("INSERT INTO search (search) VALUES ('optimize')", [])?;
    Ok(())
}

/// Fold the WAL back into the main file and truncate it, so deleted rows do not linger in
/// `-wal` after the store is closed (review L4).
pub(crate) fn checkpoint_truncate(conn: &Connection) -> Result<()> {
    let (busy, _, _): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    if busy != 0 {
        tracing::warn!("WAL checkpoint could not complete (database busy)");
    }
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
    fn migrations_are_contiguous_and_end_at_latest() {
        let mut prev = 0;
        for (v, _) in MIGRATIONS {
            // A gap would be skipped forever by a database already past it.
            assert_eq!(*v, prev + 1, "migration versions must be contiguous");
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
    fn fts_secure_delete_is_on() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn).expect("migrate");
        let v: i64 = conn
            .query_row("SELECT v FROM search_config WHERE k = 'secure-delete'", [], |r| r.get(0))
            .expect("secure-delete config row");
        assert_eq!(v, 1);
    }

    #[test]
    fn fk_off_directive_is_detected_and_fks_come_back_on() {
        assert!(needs_fk_off(MIGRATIONS[2].1));
        assert!(!needs_fk_off(MIGRATIONS[0].1));
        let mut conn = Connection::open_in_memory().expect("open");
        configure(&conn, false).expect("pragmas");
        migrate(&mut conn).expect("migrate");
        let fk: bool = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0)).expect("fk");
        assert!(fk, "foreign keys are back on after an fk-off migration");
    }

    #[test]
    fn newer_database_is_refused() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn).expect("migrate");
        put_setting(&conn, KEY_SCHEMA_VERSION, &(LATEST + 1).to_string()).expect("bump");
        assert!(matches!(migrate(&mut conn), Err(StoreError::Downgrade { .. })));
    }
}
