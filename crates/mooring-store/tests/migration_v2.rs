//! Migration 0003 from a real schema-v2 database (ADR-0009 §4 test plan): the three legacy
//! kinds move, folder / connection links survive the table rebuild, `foreign_key_check` is
//! empty, legacy secrets read through the alias table before the reseal, the reseal is
//! idempotent and survives a crash between credentials, and downgrade stays refused.

#![allow(clippy::many_single_char_names)] // s = store, v = vault, l = lab, f = fixture, as in the other store tests

mod common;

use common::vault;
use mooring_core::credential::testdata::{CERT_FP, CERT_PEM};
use mooring_core::{CredentialFields, CredentialId, FolderId};
use mooring_store::{schema, CredentialKind, SecretName, Store, StoreError};
use mooring_vault::Vault;
use rusqlite::{params, Connection};

const V1: &str = include_str!("../migrations/0001_init.sql");
const V2: &str = include_str!("../migrations/0002_fts_secure_delete.sql");
const TS: &str = "2026-11-01T10:00:00Z";

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    root: String,
    pw: CredentialId,
    key: CredentialId,
    cert: CredentialId,
    conn_id: String,
}

fn sealed(v: &Vault, id: CredentialId, column: &str, plain: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&v.seal(&id.to_string(), column, plain).expect("seal")).expect("json")
}

/// A v2 database written the way the A1 build wrote it: v1 + v2 scripts, three credentials
/// sealed under their column names, a folder default and a connection override.
fn v2_database(v: &Vault) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let raw = Connection::open(&path).expect("raw");
    raw.execute_batch(V1).expect("v1");
    raw.execute_batch(V2).expect("v2");
    raw.execute("INSERT INTO setting (key, value) VALUES ('schema_version', '2')", [])
        .expect("ver");
    let (pw, key, cert) = (CredentialId::new(), CredentialId::new(), CredentialId::new());
    let insert = |id: CredentialId,
                  name: &str,
                  kind: &str,
                  user: Option<&str>,
                  s1: &[u8],
                  s2: Option<&[u8]>| {
        raw.execute(
            "INSERT INTO credential (id, name, kind, username, secret, secret2, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                id.to_string(),
                name,
                kind,
                user,
                sealed(v, id, "secret", s1),
                s2.map(|s| sealed(v, id, "secret2", s)),
                TS
            ],
        )
        .expect("credential");
    };
    insert(pw, "ops pw", "password", Some("ops"), b"test-legacy-pw", None);
    let pem = mooring_core::credential::testdata::placeholder_key_pem();
    insert(key, "ops key", "ssh_key", None, pem.as_bytes(), Some(b"test-legacy-pp"));
    insert(
        cert,
        "client cert",
        "certificate",
        Some("svc"),
        CERT_PEM.as_bytes(),
        Some(b"test-legacy-key"),
    );
    let root = FolderId::new().to_string();
    raw.execute(
        "INSERT INTO folder (id, parent_id, name, default_credential_id, sort, created_at, updated_at)
         VALUES (?1, NULL, 'root', ?2, 0, ?3, ?3)",
        params![root, pw.to_string(), TS],
    )
    .expect("folder");
    let conn_id = mooring_core::ConnectionId::new().to_string();
    raw.execute(
        "INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id, created_at, updated_at)
         VALUES (?1, ?2, 'web01', 'ssh', 'web01.example.test', NULL, ?3, ?4, ?4)",
        params![conn_id, root, key.to_string(), TS],
    )
    .expect("connection");
    drop(raw);
    Fixture { _dir: dir, path, root, pw, key, cert, conn_id }
}

#[test]
fn v2_rows_move_links_survive_and_legacy_names_read_before_reseal() {
    let v = vault();
    let f = v2_database(&v);
    let s = Store::open(&f.path).expect("migrate");
    assert_eq!(s.schema_version().expect("v"), schema::LATEST);

    // links survived the rebuild (no ON DELETE SET NULL fired)
    let root = s.get_folder(f.root.parse().expect("id")).expect("root");
    assert_eq!(root.default_credential, Some(f.pw));
    let c = s.get_connection(f.conn_id.parse().expect("id")).expect("conn");
    assert_eq!(c.credential, Some(f.key));
    let raw = Connection::open(&f.path).expect("raw");
    let violations: i64 = raw
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r.get(0))
        .expect("fk");
    assert_eq!(violations, 0);

    // kinds and fields moved
    let pw = s.get_credential(f.pw).expect("pw");
    assert_eq!(pw.kind, CredentialKind::UserPassword);
    assert_eq!(pw.fields.account().0.as_deref(), Some("ops"));
    assert_eq!(pw.secret_names, [SecretName::Password]);
    let key = s.get_credential(f.key).expect("key");
    assert_eq!(key.kind, CredentialKind::SshKey);
    assert_eq!(
        key.fields.account().0.as_deref(),
        Some("(unset)"),
        "placeholder for a missing username"
    );
    assert_eq!(key.secret_names, [SecretName::PrivateKey, SecretName::Passphrase]);
    let cert = s.get_credential(f.cert).expect("cert");
    assert_eq!(cert.kind, CredentialKind::X509);
    assert_eq!(cert.secret_names, [SecretName::KeyPem], "the certificate becomes a field");

    // before the reseal: alias table
    assert!(s.reseal_pending().expect("flag"));
    assert_eq!(
        s.open_secret(&v, f.pw, SecretName::Password).expect("pw").as_slice(),
        b"test-legacy-pw"
    );
    assert_eq!(
        s.open_secret(&v, f.key, SecretName::Passphrase).expect("pp").as_slice(),
        b"test-legacy-pp"
    );
    assert_eq!(
        s.open_secret(&v, f.cert, SecretName::KeyPem).expect("key").as_slice(),
        b"test-legacy-key"
    );

    // reseal: new names, certificate in fields, legacy rows gone, flag cleared, idempotent
    assert_eq!(s.reseal_legacy(&v).expect("reseal"), 3);
    assert!(!s.reseal_pending().expect("flag"));
    assert_eq!(s.reseal_legacy(&v).expect("again"), 0);
    let legacy: i64 = raw
        .query_row(
            "SELECT count(*) FROM credential_secret WHERE name IN ('secret', 'secret2')",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(legacy, 0);
    let cert = s.get_credential(f.cert).expect("cert");
    let CredentialFields::X509(x) = &cert.fields else { panic!("kind") };
    assert_eq!(x.cert_pem, CERT_PEM);
    assert_eq!(cert.fingerprint(), Some(CERT_FP));
    assert_eq!(x.username.as_deref(), Some("svc"));
    assert_eq!(
        s.open_secret(&v, f.key, SecretName::Passphrase).expect("pp").as_slice(),
        b"test-legacy-pp"
    );
    // the new rows are bound to the new names: they cannot be opened under the legacy ones
    let blob: Vec<u8> = raw
        .query_row(
            "SELECT sealed FROM credential_secret WHERE credential_id = ?1 AND name = 'password'",
            [f.pw.to_string()],
            |r| r.get(0),
        )
        .expect("row");
    let sealed: mooring_vault::Sealed = serde_json::from_slice(&blob).expect("json");
    assert!(v.open(&f.pw.to_string(), "secret", &sealed).is_err());
}

#[test]
fn reseal_survives_a_crash_between_credentials() {
    let v = vault();
    let f = v2_database(&v);
    {
        let s = Store::open(&f.path).expect("migrate");
        assert_eq!(s.reseal_legacy_step(&v, 1).expect("one"), 1);
        assert!(s.reseal_pending().expect("still pending"));
    } // "crash": process ends after the first credential
    let s = Store::open(&f.path).expect("reopen");
    for id in [f.pw, f.key, f.cert] {
        assert!(s.get_credential(id).is_ok(), "every row readable mid-reseal");
    }
    assert_eq!(s.reseal_legacy(&v).expect("rest"), 2);
    assert!(!s.reseal_pending().expect("done"));
    assert_eq!(
        s.open_secret(&v, f.pw, SecretName::Password).expect("pw").as_slice(),
        b"test-legacy-pw"
    );
}

#[test]
fn reseal_needs_the_right_vault_and_writes_nothing_otherwise() {
    let v = vault();
    let f = v2_database(&v);
    let s = Store::open(&f.path).expect("migrate");
    let other = vault();
    assert!(matches!(s.reseal_legacy(&other), Err(StoreError::Vault(_))));
    assert!(s.reseal_pending().expect("flag kept"));
    assert_eq!(
        s.open_secret(&v, f.pw, SecretName::Password).expect("pw").as_slice(),
        b"test-legacy-pw"
    );
}

#[test]
fn replacing_a_legacy_secret_drops_its_alias() {
    let v = vault();
    let f = v2_database(&v);
    let s = Store::open(&f.path).expect("migrate");
    let set = common::secrets(&[(SecretName::Password, b"test-rotated")]);
    s.replace_secrets(&v, f.pw, &set, &[]).expect("rotate");
    assert_eq!(
        s.open_secret(&v, f.pw, SecretName::Password).expect("pw").as_slice(),
        b"test-rotated"
    );
    assert_eq!(s.get_credential(f.pw).expect("m").secret_names, [SecretName::Password]);
}

#[test]
fn empty_v2_database_migrates_without_the_pending_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let raw = Connection::open(&path).expect("raw");
    raw.execute_batch(V1).expect("v1");
    raw.execute_batch(V2).expect("v2");
    raw.execute("INSERT INTO setting (key, value) VALUES ('schema_version', '2')", [])
        .expect("ver");
    drop(raw);
    let s = Store::open(&path).expect("migrate");
    assert!(!s.reseal_pending().expect("flag"));
    assert_eq!(s.reseal_legacy(&vault()).expect("noop"), 0);
}
