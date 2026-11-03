//! File-backed open: pragmas, migrations from empty, idempotent reopen, downgrade refusal.

mod common;

use nexus_store::{schema, Store, StoreError};

#[test]
fn migrates_from_empty_and_reopens_idempotently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nexus.db");

    let id = {
        let s = Store::open(&path).expect("first open");
        assert_eq!(s.schema_version().expect("v"), schema::LATEST);
        let lab_root = s.create_folder(None, "root").expect("root");
        let c = common::conn(&s, &lab_root, "xinfra01", "10.10.20.5", &["infra"]);
        s.set_vault_id("8c6f5c0e-3a1b-4d8e-9f00-1234567890ab").expect("vault id");
        c.id
    };

    let s = Store::open(&path).expect("reopen");
    assert_eq!(s.schema_version().expect("v"), schema::LATEST);
    assert_eq!(s.get_connection(id).expect("persisted").tags, vec!["infra".to_owned()]);
    assert_eq!(s.vault_id().expect("get").as_deref(), Some("8c6f5c0e-3a1b-4d8e-9f00-1234567890ab"));
    // search index survives reopen (rebuilt on open)
    assert_eq!(s.search("xinfra", 10).expect("search").len(), 1);
}

#[test]
fn file_store_uses_wal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nexus.db");
    let _s = Store::open(&path).expect("open");
    let raw = rusqlite::Connection::open(&path).expect("raw");
    let mode: String = raw.pragma_query_value(None, "journal_mode", |r| r.get(0)).expect("mode");
    assert_eq!(mode.to_ascii_lowercase(), "wal");
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nexus.db");
    drop(Store::open(&path).expect("create"));

    let raw = rusqlite::Connection::open(&path).expect("raw");
    raw.execute(
        "UPDATE setting SET value = ?1 WHERE key = 'schema_version'",
        [(schema::LATEST + 1).to_string()],
    )
    .expect("bump");
    drop(raw);

    match Store::open(&path) {
        Err(StoreError::Downgrade { found, supported }) => {
            assert_eq!(found, schema::LATEST + 1);
            assert_eq!(supported, schema::LATEST);
        }
        other => panic!("expected downgrade refusal, got {other:?}"),
    }
}

#[test]
fn garbage_file_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nexus.db");
    std::fs::write(&path, b"this is not a sqlite database at all, just bytes......").expect("w");
    assert!(Store::open(&path).is_err());
}
