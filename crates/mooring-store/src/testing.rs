//! Test support shared with other crates (the Tauri shell has no `rusqlite` of its own): a
//! schema-v2 database written exactly as the A1 build wrote it. Synthetic values only; nothing
//! here runs outside tests.

use std::path::Path;

use mooring_core::credential::testdata::{placeholder_key_pem, CERT_PEM};
use mooring_core::CredentialId;
use mooring_vault::Vault;
use rusqlite::{params, Connection};

use crate::error::{Result, StoreError};

const V1: &str = include_str!("../migrations/0001_init.sql");
const V2: &str = include_str!("../migrations/0002_fts_secure_delete.sql");
const TS: &str = "2026-11-01T10:00:00Z";

/// Synthetic legacy password of [`V2Credentials::pw`].
pub const LEGACY_PW: &[u8] = b"test-legacy-pw";
/// Synthetic legacy passphrase of [`V2Credentials::key`].
pub const LEGACY_PASSPHRASE: &[u8] = b"test-legacy-pp";
/// Synthetic legacy key PEM of [`V2Credentials::cert`].
pub const LEGACY_KEY_PEM: &[u8] = b"test-legacy-key";

/// Ids of the three v2 credentials.
#[derive(Debug, Clone, Copy)]
pub struct V2Credentials {
    /// `password` with username `ops`.
    pub pw: CredentialId,
    /// `ssh_key` without a username, with a passphrase.
    pub key: CredentialId,
    /// `certificate` (`secret` = certificate PEM, `secret2` = key PEM), username `svc`.
    pub cert: CredentialId,
}

fn sealed(v: &Vault, id: CredentialId, column: &str, plain: &[u8]) -> Result<Vec<u8>> {
    let s = v.seal(&id.to_string(), column, plain)?;
    serde_json::to_vec(&s).map_err(|_| StoreError::Corrupt { what: "sealed value" })
}

/// `(id, name, v2 kind, username, secret, secret2)`.
type V2Row<'a> = (CredentialId, &'a str, &'a str, Option<&'a str>, &'a [u8], Option<&'a [u8]>);

/// Write a schema-v2 database at `path` with three credentials sealed by `v` under their v2
/// column names (`secret` / `secret2`).
pub fn write_v2_database(path: &Path, v: &Vault) -> Result<V2Credentials> {
    let raw = Connection::open(path)?;
    raw.execute_batch(V1)?;
    raw.execute_batch(V2)?;
    raw.execute("INSERT INTO setting (key, value) VALUES ('schema_version', '2')", [])?;
    let ids = V2Credentials {
        pw: CredentialId::new(),
        key: CredentialId::new(),
        cert: CredentialId::new(),
    };
    let pem = placeholder_key_pem();
    let rows: [V2Row<'_>; 3] = [
        (ids.pw, "ops pw", "password", Some("ops"), LEGACY_PW, None),
        (ids.key, "ops key", "ssh_key", None, pem.as_bytes(), Some(LEGACY_PASSPHRASE)),
        (
            ids.cert,
            "client cert",
            "certificate",
            Some("svc"),
            CERT_PEM.as_bytes(),
            Some(LEGACY_KEY_PEM),
        ),
    ];
    for (id, name, kind, user, s1, s2) in rows {
        let s2 = s2.map(|s| sealed(v, id, "secret2", s)).transpose()?;
        raw.execute(
            "INSERT INTO credential (id, name, kind, username, secret, secret2, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![id.to_string(), name, kind, user, sealed(v, id, "secret", s1)?, s2, TS],
        )?;
    }
    Ok(ids)
}

/// Rows still stored under a legacy name (`secret` / `secret2`), read from the raw file.
pub fn legacy_secret_rows(path: &Path) -> Result<i64> {
    let raw = Connection::open(path)?;
    Ok(raw.query_row(
        "SELECT count(*) FROM credential_secret WHERE name IN ('secret', 'secret2')",
        [],
        |r| r.get(0),
    )?)
}
