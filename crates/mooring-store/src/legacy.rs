//! Credentials migrated from schema v2 (ADR-0009 §4, "Reseal").
//!
//! Migration 0003 copies the v2 sealed columns into `credential_secret` under their legacy
//! names `secret` / `secret2`, because those names are part of the AAD they were sealed with.
//! Until [`Store::reseal_legacy`] runs (first unlock), the fixed alias table below lets every
//! reader find them under their new names. The reseal opens each legacy secret under its old
//! AAD, writes it under the new name (or, for x509, moves the public certificate into
//! `fields_json.cert_pem`), and deletes the legacy row. One run is one transaction (every
//! converted credential plus the cleared flag, or nothing); it is idempotent.

use mooring_core::credential::fingerprint;
use mooring_core::{CredentialFields, CredentialId, CredentialKind, SecretName};
use mooring_vault::Vault;
use rusqlite::{params, OptionalExtension};
use zeroize::Zeroizing;

use crate::credentials::{put_secret, seal, unseal};
use crate::error::{Result, StoreError};
use crate::schema::{self, KEY_RESEAL_PENDING};
use crate::util::{fmt_ts, now, parse_id};
use crate::Store;

/// Legacy column names.
pub(crate) const LEGACY: [&str; 2] = ["secret", "secret2"];

/// Where a legacy row goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// A sealed secret under this name.
    Secret(SecretName),
    /// The x509 certificate: public, moves into `fields_json.cert_pem`.
    CertPem,
}

/// The fixed kind → name alias table.
pub(crate) fn target(kind: CredentialKind, legacy: &str) -> Option<Target> {
    use CredentialKind as K;
    match (kind, legacy) {
        (K::UserPassword, "secret") => Some(Target::Secret(SecretName::Password)),
        (K::SshKey, "secret") => Some(Target::Secret(SecretName::PrivateKey)),
        (K::SshKey, "secret2") => Some(Target::Secret(SecretName::Passphrase)),
        (K::X509, "secret") => Some(Target::CertPem),
        (K::X509, "secret2") => Some(Target::Secret(SecretName::KeyPem)),
        _ => None,
    }
}

fn legacy_name_for(kind: CredentialKind, name: SecretName) -> Option<&'static str> {
    LEGACY.into_iter().find(|l| target(kind, l) == Some(Target::Secret(name)))
}

/// Read a not-yet-resealed secret through the alias table.
pub(crate) fn open_alias(
    store: &Store,
    vault: &Vault,
    id: CredentialId,
    kind: CredentialKind,
    name: SecretName,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(legacy) = legacy_name_for(kind, name) else {
        return Ok(None);
    };
    match store.secret_blob(id, legacy)? {
        Some(blob) => unseal(vault, id, legacy, &blob).map(Some),
        None => Ok(None),
    }
}

/// A new value under `name` supersedes its legacy row.
pub(crate) fn drop_aliases_of(
    conn: &rusqlite::Connection,
    id: CredentialId,
    kind: CredentialKind,
    name: &str,
) -> Result<()> {
    if let Some(legacy) = SecretName::parse(name).and_then(|n| legacy_name_for(kind, n)) {
        conn.execute(
            "DELETE FROM credential_secret WHERE credential_id = ?1 AND name = ?2",
            params![id.to_string(), legacy],
        )?;
    }
    Ok(())
}

impl Store {
    /// Whether migrated v2 secrets still wait for [`Store::reseal_legacy`].
    pub fn reseal_pending(&self) -> Result<bool> {
        Ok(schema::get_setting(&self.conn, KEY_RESEAL_PENDING)?.is_some())
    }

    /// Re-seal every legacy secret under its ADR-0009 name (call after unlock). Returns how many
    /// credentials were converted. Idempotent; safe to interrupt between credentials.
    pub fn reseal_legacy(&self, vault: &Vault) -> Result<usize> {
        self.reseal_legacy_step(vault, usize::MAX)
    }

    /// Same as [`Store::reseal_legacy`] (name used by the A1 task brief).
    pub fn migrate_sealed_names(&self, vault: &Vault) -> Result<usize> {
        self.reseal_legacy(vault)
    }

    /// [`Store::reseal_legacy`] limited to `max` credentials (tests simulate a crash with it).
    ///
    /// One call is one transaction: every converted credential and the cleared flag commit
    /// together, or nothing does (a wrong vault or a damaged row leaves the store untouched and
    /// the alias table keeps the legacy secrets readable).
    #[doc(hidden)]
    pub fn reseal_legacy_step(&self, vault: &Vault, max: usize) -> Result<usize> {
        if !self.reseal_pending()? {
            return Ok(0);
        }
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT credential_id FROM credential_secret
                 WHERE name IN ('secret', 'secret2') ORDER BY credential_id",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut done = 0;
        for id in ids.iter().take(max) {
            reseal_one(&tx, vault, parse_id(id)?)?;
            done += 1;
        }
        let left: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM credential_secret WHERE name IN ('secret', 'secret2'))",
            [],
            |r| r.get(0),
        )?;
        if !left {
            tx.execute("DELETE FROM setting WHERE key = ?1", [KEY_RESEAL_PENDING])?;
        }
        tx.commit()?;
        if !left {
            tracing::info!("legacy credential secrets resealed");
        }
        Ok(done)
    }
}

fn reseal_one(tx: &rusqlite::Connection, vault: &Vault, id: CredentialId) -> Result<()> {
    let (kind, json): (String, String) = tx.query_row(
        "SELECT kind, fields_json FROM credential WHERE id = ?1",
        [id.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let kind =
        CredentialKind::parse(&kind).ok_or(StoreError::Corrupt { what: "credential kind" })?;
    let mut fields = CredentialFields::from_stored(kind, &json)
        .map_err(|_| StoreError::Corrupt { what: "credential fields" })?;
    for legacy in LEGACY {
        let Some(blob) = blob_of(tx, id, legacy)? else { continue };
        let plain = unseal(vault, id, legacy, &blob)?;
        match target(kind, legacy).ok_or(StoreError::Corrupt { what: "legacy secret" })? {
            Target::Secret(name) => {
                if blob_of(tx, id, name.as_str())?.is_none() {
                    put_secret(tx, id, name.as_str(), &seal(vault, id, name.as_str(), &plain)?)?;
                }
                if name == SecretName::PrivateKey {
                    // best effort: a v2 key that is not PEM keeps no fingerprint
                    let _ = fields.derive_from_secret(name, &plain);
                }
            }
            Target::CertPem => move_certificate(&mut fields, &plain)?,
        }
        tx.execute(
            "DELETE FROM credential_secret WHERE credential_id = ?1 AND name = ?2",
            params![id.to_string(), legacy],
        )?;
    }
    tx.execute(
        "UPDATE credential SET fields_json = ?2, updated_at = ?3 WHERE id = ?1",
        params![id.to_string(), fields.to_json()?, fmt_ts(now())?],
    )?;
    tracing::debug!(credential = %id, "legacy credential resealed");
    Ok(())
}

fn blob_of(tx: &rusqlite::Connection, id: CredentialId, name: &str) -> Result<Option<Vec<u8>>> {
    Ok(tx
        .query_row(
            "SELECT sealed FROM credential_secret WHERE credential_id = ?1 AND name = ?2",
            params![id.to_string(), name],
            |r| r.get(0),
        )
        .optional()?)
}

/// The v2 certificate (public) becomes `cert_pem`, with its fingerprint when it parses.
fn move_certificate(fields: &mut CredentialFields, plain: &[u8]) -> Result<()> {
    let CredentialFields::X509(f) = fields else {
        return Err(StoreError::Corrupt { what: "legacy certificate" });
    };
    let text = std::str::from_utf8(plain)
        .map_err(|_| StoreError::Corrupt { what: "legacy certificate" })?;
    text.clone_into(&mut f.cert_pem);
    f.fingerprint = fingerprint::x509_pem(text).ok();
    // re-validate the whole row: a v2 value that breaks the field rules is refused, not stored
    let json = fields.to_json()?;
    CredentialFields::from_stored(fields.kind(), &json)
        .map_err(|_| StoreError::Corrupt { what: "legacy certificate" })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_table_is_the_adr_one() {
        use CredentialKind as K;
        assert_eq!(target(K::UserPassword, "secret"), Some(Target::Secret(SecretName::Password)));
        assert_eq!(target(K::UserPassword, "secret2"), None);
        assert_eq!(target(K::SshKey, "secret2"), Some(Target::Secret(SecretName::Passphrase)));
        assert_eq!(target(K::X509, "secret"), Some(Target::CertPem));
        assert_eq!(target(K::X509, "secret2"), Some(Target::Secret(SecretName::KeyPem)));
        assert_eq!(target(K::ApiToken, "secret"), None, "only migrated kinds have aliases");
        assert_eq!(legacy_name_for(K::SshKey, SecretName::PrivateKey), Some("secret"));
        assert_eq!(legacy_name_for(K::SshKey, SecretName::OtpSeed), None);
    }
}
