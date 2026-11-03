//! Typed credentials (ADR-0009 §4): plaintext `fields_json` validated by the kind's serde type
//! on every write and read, and one sealed row per secret in `credential_secret`, sealed with
//! AAD = credential id ‖ 0x1F ‖ secret name. Secret names are a closed set per kind; unknown
//! names are refused on read and write. Nothing here formats, logs or returns plaintext except
//! [`Store::open_secret`], whose buffer is zeroized on drop.

use std::collections::BTreeMap;

use mooring_core::credential::{validate_secret, CredentialError};
use mooring_core::{CredentialFields, CredentialId, CredentialKind, SecretName};
use mooring_vault::{Sealed, Vault};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{not_found, Result, StoreError};
use crate::legacy;
use crate::util::{check_name, fmt_ts, now, parse_id, parse_ts};
use crate::Store;

/// Credential metadata. Never holds secret material, so `Debug` and serialisation to the UI
/// are safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMeta {
    /// Credential id (also the vault record id).
    pub id: CredentialId,
    /// Display name, 1..=120 chars.
    pub name: String,
    /// Kind (immutable).
    pub kind: CredentialKind,
    /// Plaintext fields (non-secret).
    pub fields: CredentialFields,
    /// Which secrets are stored (presence only), sorted. Legacy names are reported under the
    /// name they will have after the reseal.
    pub secret_names: Vec<SecretName>,
    /// Creation time (UTC).
    pub created_at: OffsetDateTime,
    /// Last change (UTC).
    pub updated_at: OffsetDateTime,
}

impl CredentialMeta {
    /// `SHA256:` fingerprint for `ssh_key` / `x509`.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fields.fingerprint()
    }
}

pub(crate) fn seal(vault: &Vault, id: CredentialId, name: &str, plain: &[u8]) -> Result<Vec<u8>> {
    let sealed = vault.seal(&id.to_string(), name, plain)?;
    serde_json::to_vec(&sealed).map_err(|_| StoreError::Corrupt { what: "sealed value" })
}

pub(crate) fn unseal(
    vault: &Vault,
    id: CredentialId,
    name: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let sealed: Sealed =
        serde_json::from_slice(blob).map_err(|_| StoreError::Corrupt { what: "sealed value" })?;
    Ok(vault.open(&id.to_string(), name, &sealed)?)
}

pub(crate) fn put_secret(
    conn: &rusqlite::Connection,
    id: CredentialId,
    name: &str,
    blob: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO credential_secret (credential_id, name, sealed) VALUES (?1, ?2, ?3)
         ON CONFLICT (credential_id, name) DO UPDATE SET sealed = excluded.sealed",
        params![id.to_string(), name, blob],
    )?;
    Ok(())
}

/// Plaintext secrets for create / replace, keyed by name.
pub type Secrets<'a> = BTreeMap<SecretName, &'a [u8]>;

/// Check every secret against the kind and fold derived values (fingerprint, contexts) and the
/// otp slot rule into `fields`.
fn prepare(fields: &mut CredentialFields, secrets: &Secrets<'_>) -> Result<()> {
    let kind = fields.kind();
    for (name, plain) in secrets {
        validate_secret(kind, *name, plain)?;
        fields.derive_from_secret(*name, plain)?;
    }
    Ok(())
}

fn otp_consistent(fields: &mut CredentialFields, has_seed: bool) -> Result<()> {
    if has_seed && fields.otp().is_none() {
        fields.set_otp(Some(mooring_core::credential::OtpParams::default()))?;
    }
    if !has_seed {
        fields.set_otp(None)?;
    }
    Ok(())
}

impl Store {
    /// Create a credential: validate `fields` (UI JSON) for `kind`, check and seal every
    /// secret under its own name, insert all in one transaction. Required secrets must be set.
    pub fn create_credential(
        &self,
        vault: &Vault,
        name: &str,
        kind: CredentialKind,
        fields: &Value,
        secrets: &Secrets<'_>,
    ) -> Result<CredentialMeta> {
        let name = check_name("name", name)?;
        let mut f = CredentialFields::from_input(kind, fields, None)?;
        prepare(&mut f, secrets)?;
        let schema = kind.schema();
        if let Some(missing) = schema
            .secret_names()
            .find(|n| schema.secret(*n).is_some_and(|s| s.required) && !secrets.contains_key(n))
        {
            return Err(CredentialError::invalid(missing.as_str(), "is required").into());
        }
        otp_consistent(&mut f, secrets.contains_key(&SecretName::OtpSeed))?;
        let id = CredentialId::new();
        let blobs = secrets
            .iter()
            .map(|(n, p)| Ok((n.as_str(), seal(vault, id, n.as_str(), p)?)))
            .collect::<Result<Vec<_>>>()?;
        let ts = fmt_ts(now())?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO credential (id, name, kind, fields_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![id.to_string(), name, kind.name(), f.to_json()?, ts],
        )?;
        for (n, blob) in &blobs {
            put_secret(&tx, id, n, blob)?;
        }
        tx.commit()?;
        tracing::info!(credential = %id, kind = kind.name(), "credential stored");
        self.get_credential(id)
    }

    /// Metadata of one credential (fields re-validated; a bad row is `Corrupt`).
    pub fn get_credential(&self, id: CredentialId) -> Result<CredentialMeta> {
        let row: Option<(String, String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT name, kind, fields_json, created_at, updated_at FROM credential
                 WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let (name, kind, json, created, updated) =
            row.ok_or_else(|| not_found("credential", &id))?;
        let kind =
            CredentialKind::parse(&kind).ok_or(StoreError::Corrupt { what: "credential kind" })?;
        let fields = CredentialFields::from_stored(kind, &json)
            .map_err(|_| StoreError::Corrupt { what: "credential fields" })?;
        Ok(CredentialMeta {
            id,
            name,
            kind,
            fields,
            secret_names: self.secret_names(id, kind)?,
            created_at: parse_ts(&created)?,
            updated_at: parse_ts(&updated)?,
        })
    }

    fn secret_names(&self, id: CredentialId, kind: CredentialKind) -> Result<Vec<SecretName>> {
        let mut stmt =
            self.conn.prepare("SELECT name FROM credential_secret WHERE credential_id = ?1")?;
        let raw = stmt
            .query_map([id.to_string()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Vec::with_capacity(raw.len());
        for n in raw {
            if let Some(name) = SecretName::parse(&n).filter(|n| kind.schema().secret(*n).is_some())
            {
                out.push(name);
                continue;
            }
            match legacy::target(kind, &n) {
                Some(legacy::Target::Secret(name)) => out.push(name),
                Some(legacy::Target::CertPem) => {}
                None => return Err(StoreError::Corrupt { what: "secret name" }),
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Metadata of every credential, sorted by name. Never returns secrets.
    pub fn list_credentials(&self) -> Result<Vec<CredentialMeta>> {
        let mut stmt = self.conn.prepare("SELECT id FROM credential ORDER BY name, id")?;
        let ids =
            stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter().map(|id| self.get_credential(parse_id(id)?)).collect()
    }

    /// Change the name and plaintext fields (kind is immutable). Derived values that need a
    /// secret (SSH private key fingerprint, kubeconfig contexts) are carried over; the `otp`
    /// parameters are kept only while an `otp_seed` is stored.
    pub fn update_credential_fields(
        &self,
        id: CredentialId,
        name: &str,
        fields: &Value,
    ) -> Result<CredentialMeta> {
        let name = check_name("name", name)?;
        let current = self.get_credential(id)?;
        let mut f = CredentialFields::from_input(current.kind, fields, Some(&current.fields))?;
        let has_seed = current.secret_names.contains(&SecretName::OtpSeed);
        if has_seed && f.otp().is_none() {
            f.set_otp(current.fields.otp())?;
        }
        otp_consistent(&mut f, has_seed)?;
        self.conn.execute(
            "UPDATE credential SET name = ?2, fields_json = ?3, updated_at = ?4 WHERE id = ?1",
            params![id.to_string(), name, f.to_json()?, fmt_ts(now())?],
        )?;
        self.get_credential(id)
    }

    /// Set and clear secrets in one transaction. Required secrets cannot be cleared; a name in
    /// both `set` and `clear` is refused. Derived fields follow (fingerprint, contexts, otp).
    pub fn replace_secrets(
        &self,
        vault: &Vault,
        id: CredentialId,
        set: &Secrets<'_>,
        clear: &[SecretName],
    ) -> Result<CredentialMeta> {
        let current = self.get_credential(id)?;
        let schema = current.kind.schema();
        for n in clear {
            let spec = schema.secret(*n).ok_or_else(|| {
                StoreError::from(CredentialError::invalid(
                    n.as_str(),
                    "is not a secret of this kind",
                ))
            })?;
            if spec.required {
                return Err(CredentialError::invalid(
                    n.as_str(),
                    "is required and cannot be cleared",
                )
                .into());
            }
            if set.contains_key(n) {
                return Err(
                    CredentialError::invalid(n.as_str(), "cannot be set and cleared").into()
                );
            }
        }
        let mut f = current.fields.clone();
        prepare(&mut f, set)?;
        let has_seed = (current.secret_names.contains(&SecretName::OtpSeed)
            || set.contains_key(&SecretName::OtpSeed))
            && !clear.contains(&SecretName::OtpSeed);
        otp_consistent(&mut f, has_seed)?;
        let blobs = set
            .iter()
            .map(|(n, p)| Ok((n.as_str(), seal(vault, id, n.as_str(), p)?)))
            .collect::<Result<Vec<_>>>()?;
        let tx = self.conn.unchecked_transaction()?;
        for (n, blob) in &blobs {
            put_secret(&tx, id, n, blob)?;
            legacy::drop_aliases_of(&tx, id, current.kind, n)?;
        }
        for n in clear {
            tx.execute(
                "DELETE FROM credential_secret WHERE credential_id = ?1 AND name = ?2",
                params![id.to_string(), n.as_str()],
            )?;
            legacy::drop_aliases_of(&tx, id, current.kind, n.as_str())?;
        }
        tx.execute(
            "UPDATE credential SET fields_json = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), f.to_json()?, fmt_ts(now())?],
        )?;
        tx.commit()?;
        tracing::info!(credential = %id, set = set.len(), cleared = clear.len(), "credential secrets replaced");
        self.get_credential(id)
    }

    /// Delete a credential and its secrets. Folders / connections referencing it as primary
    /// fall back to inheritance (`ON DELETE SET NULL`); secondary roles are removed.
    pub fn delete_credential(&self, id: CredentialId) -> Result<()> {
        let n = self.conn.execute("DELETE FROM credential WHERE id = ?1", [id.to_string()])?;
        if n == 0 {
            return Err(not_found("credential", &id));
        }
        tracing::info!(credential = %id, "credential deleted");
        Ok(())
    }

    /// Decrypt one secret. The name must belong to the credential's kind. Before the reseal a
    /// legacy row (`secret` / `secret2`) is read through the fixed alias table. `NotFound
    /// { kind: "secret" }` when absent; `Vault(Tampered)` when the blob was moved between
    /// credentials or names.
    pub fn open_secret(
        &self,
        vault: &Vault,
        id: CredentialId,
        name: SecretName,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let kind: Option<String> = self
            .conn
            .query_row("SELECT kind FROM credential WHERE id = ?1", [id.to_string()], |r| r.get(0))
            .optional()?;
        let kind = kind.ok_or_else(|| not_found("credential", &id))?;
        let kind =
            CredentialKind::parse(&kind).ok_or(StoreError::Corrupt { what: "credential kind" })?;
        if kind.schema().secret(name).is_none() {
            return Err(
                CredentialError::invalid(name.as_str(), "is not a secret of this kind").into()
            );
        }
        if let Some(blob) = self.secret_blob(id, name.as_str())? {
            return unseal(vault, id, name.as_str(), &blob);
        }
        if let Some(plain) = legacy::open_alias(self, vault, id, kind, name)? {
            return Ok(plain);
        }
        Err(not_found("secret", &id))
    }

    pub(crate) fn secret_blob(&self, id: CredentialId, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT sealed FROM credential_secret WHERE credential_id = ?1 AND name = ?2",
                params![id.to_string(), name],
                |r| r.get(0),
            )
            .optional()?)
    }
}

/// `NotFound` unless the credential exists (used before writing a reference to it).
pub(crate) fn ensure_credential(conn: &rusqlite::Connection, id: CredentialId) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM credential WHERE id = ?1)",
        [id.to_string()],
        |r| r.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(not_found("credential", &id))
    }
}
