//! ADR-0024 §1: `ssh_key` rows whose sealed `private_key` is a FIDO2 `sk-*` key handle become
//! `ssh_sk_key` (backend `agent`). Runs after unlock while migration 0010's flag is set; the
//! sealed values keep their names (`private_key`, `passphrase`; AAD = id ‖ name), so nothing
//! is re-sealed. A row that cannot move without losing data (a TOTP seed, which `ssh_sk_key`
//! has no slot for, or a migrated row without a username) stays `ssh_key` and is logged.

use mooring_core::credential::sk_key::{parse_sk_certificate_line, parse_sk_key_handle};
use mooring_core::credential::{SkBackend, SshSkKeyFields};
use mooring_core::{CredentialFields, CredentialId, CredentialKind, SecretName};
use mooring_vault::Vault;
use rusqlite::params;

use crate::credentials::unseal;
use crate::error::{Result, StoreError};
use crate::util::{fmt_ts, now, parse_id};
use crate::Store;

/// Setting written by migration 0010 while `ssh_key` rows wait for inspection.
pub(crate) const KEY_SK_SCAN_PENDING: &str = "credential_sk_scan_pending";

impl Store {
    /// Convert every `ssh_key` whose key is an `sk-*` handle to `ssh_sk_key` (call after
    /// unlock). Returns the converted ids (each is audited by the caller). One transaction;
    /// clears the flag, so later unlocks are no-ops.
    pub fn convert_sk_keys(&self, vault: &Vault) -> Result<Vec<CredentialId>> {
        if crate::schema::get_setting(&self.conn, KEY_SK_SCAN_PENDING)?.is_none() {
            return Ok(Vec::new());
        }
        let tx = self.conn.unchecked_transaction()?;
        let rows: Vec<(String, String, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT c.id, c.fields_json, s.sealed FROM credential c
                 JOIN credential_secret s ON s.credential_id = c.id AND s.name = 'private_key'
                 WHERE c.kind = 'ssh_key' ORDER BY c.id",
            )?;
            let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            it.collect::<rusqlite::Result<_>>()?
        };
        let mut done = Vec::new();
        for (id, json, blob) in rows {
            let id = parse_id(&id)?;
            let plain = unseal(vault, id, SecretName::PrivateKey.as_str(), &blob)?;
            let Ok(handle) = parse_sk_key_handle(&plain) else { continue };
            drop(plain);
            let Ok(CredentialFields::SshKey(old)) =
                CredentialFields::from_stored(CredentialKind::SshKey, &json)
            else {
                return Err(StoreError::Corrupt { what: "credential fields" });
            };
            let has_seed: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM credential_secret WHERE credential_id = ?1 AND name = 'otp_seed')",
                [id.to_string()],
                |r| r.get(0),
            )?;
            if has_seed || old.username.trim().is_empty() {
                tracing::warn!(credential = %id, "sk-* key left as ssh_key (TOTP seed or no username)");
                continue;
            }
            let certificate = old.certificate.filter(|c| {
                parse_sk_certificate_line(c).is_ok_and(|k| k.blob == handle.public.blob)
            });
            let fields = CredentialFields::SshSkKey(SshSkKeyFields {
                username: old.username,
                public_key: handle.public.line(),
                certificate,
                backend: SkBackend::Agent,
                resident: handle.resident().unwrap_or(false),
                application: Some(handle.public.application.clone()),
                fingerprint: Some(handle.public.fingerprint.clone()),
            });
            tx.execute(
                "UPDATE credential SET kind = 'ssh_sk_key', fields_json = ?2, updated_at = ?3 WHERE id = ?1",
                params![id.to_string(), fields.to_json()?, fmt_ts(now())?],
            )?;
            done.push(id);
        }
        tx.execute("DELETE FROM setting WHERE key = ?1", [KEY_SK_SCAN_PENDING])?;
        tx.commit()?;
        Ok(done)
    }
}

#[cfg(test)]
#[path = "sk_convert_tests.rs"]
mod tests;
