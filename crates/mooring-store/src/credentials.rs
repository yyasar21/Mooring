//! Credentials: plaintext metadata plus vault-sealed secret columns.
//!
//! `secret` / `secret2` hold the JSON encoding of [`mooring_vault::Sealed`], sealed with record
//! id = credential id and field = column name (ADR-0005). Nothing in this module formats,
//! logs or returns plaintext except [`Store::open_credential_secret`], whose buffer is
//! zeroized on drop.

use mooring_core::CredentialId;
use mooring_vault::{Sealed, Vault};
use rusqlite::{params, OptionalExtension, Row};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{invalid, not_found, Result, StoreError};
use crate::util::{check_name, fmt_ts, now, parse_id, parse_ts};
use crate::Store;

/// Maximum username length (characters).
pub const MAX_USERNAME: usize = 256;
/// Maximum plaintext size of one secret (bytes); large enough for a PEM chain.
pub const MAX_SECRET: usize = 64 * 1024;

/// What a credential holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// `secret` = password.
    Password,
    /// `secret` = private key, `secret2` = optional passphrase.
    SshKey,
    /// `secret` = certificate, `secret2` = private key.
    Certificate,
}

impl CredentialKind {
    /// Stable name stored in `credential.kind`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::SshKey => "ssh_key",
            Self::Certificate => "certificate",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "password" => Ok(Self::Password),
            "ssh_key" => Ok(Self::SshKey),
            "certificate" => Ok(Self::Certificate),
            _ => Err(StoreError::Corrupt { what: "credential kind" }),
        }
    }
}

/// A sealed column of `credential`. The variant's column name is the vault AAD field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretField {
    /// Primary secret (password, private key, certificate).
    Secret,
    /// Secondary secret (key passphrase, certificate private key).
    Secret2,
}

impl SecretField {
    /// Column name, also the vault `field` bound into the AAD.
    #[must_use]
    pub const fn column(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Secret2 => "secret2",
        }
    }
}

/// Credential metadata. Never holds secret material, so `Debug` and serialisation to the UI
/// are safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMeta {
    /// Credential id (also the vault record id).
    pub id: CredentialId,
    /// Display name, 1..=120 chars.
    pub name: String,
    /// Kind.
    pub kind: CredentialKind,
    /// Optional user name, at most [`MAX_USERNAME`] chars.
    pub username: Option<String>,
    /// Creation time (UTC).
    pub created_at: OffsetDateTime,
    /// Last change (UTC).
    pub updated_at: OffsetDateTime,
}

impl CredentialMeta {
    /// Fresh metadata with a new id and current timestamps.
    pub fn new(name: &str, kind: CredentialKind, username: Option<&str>) -> Result<Self> {
        let t = now();
        let meta = Self {
            id: CredentialId::new(),
            name: check_name("name", name)?,
            kind,
            username: check_username(username)?,
            created_at: t,
            updated_at: t,
        };
        Ok(meta)
    }
}

fn check_username(u: Option<&str>) -> Result<Option<String>> {
    let Some(u) = u.map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    if u.chars().count() > MAX_USERNAME || u.chars().any(char::is_control) {
        return Err(invalid("username", "at most 256 characters, no control characters"));
    }
    Ok(Some(u.to_owned()))
}

fn check_secret(field: SecretField, s: &[u8]) -> Result<()> {
    if s.len() > MAX_SECRET {
        return Err(invalid(field.column(), "larger than 64 KiB"));
    }
    Ok(())
}

fn seal(vault: &Vault, id: CredentialId, field: SecretField, plain: &[u8]) -> Result<Vec<u8>> {
    check_secret(field, plain)?;
    let sealed = vault.seal(&id.to_string(), field.column(), plain)?;
    serde_json::to_vec(&sealed).map_err(|_| StoreError::Corrupt { what: "sealed value" })
}

const META_COLS: &str = "id, name, kind, username, created_at, updated_at";

fn row_to_meta(r: &Row<'_>) -> rusqlite::Result<[Option<String>; 6]> {
    Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?])
}

fn decode(raw: [Option<String>; 6]) -> Result<CredentialMeta> {
    let [id, name, kind, username, created, updated] = raw;
    let req = |v: Option<String>| v.ok_or(StoreError::Corrupt { what: "credential" });
    Ok(CredentialMeta {
        id: parse_id(&req(id)?)?,
        name: req(name)?,
        kind: CredentialKind::parse(&req(kind)?)?,
        username,
        created_at: parse_ts(&req(created)?)?,
        updated_at: parse_ts(&req(updated)?)?,
    })
}

impl Store {
    /// Store a credential, sealing `secret` (and `secret2`) under the unlocked vault.
    /// Metadata is re-validated; the stored form is returned.
    pub fn create_credential(
        &self,
        vault: &Vault,
        meta: &CredentialMeta,
        secret: &[u8],
        secret2: Option<&[u8]>,
    ) -> Result<CredentialMeta> {
        let name = check_name("name", &meta.name)?;
        let username = check_username(meta.username.as_deref())?;
        let s1 = seal(vault, meta.id, SecretField::Secret, secret)?;
        let s2 = secret2.map(|s| seal(vault, meta.id, SecretField::Secret2, s)).transpose()?;
        self.conn.execute(
            "INSERT INTO credential (id, name, kind, username, secret, secret2, created_at,
                                     updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                meta.id.to_string(),
                name,
                meta.kind.name(),
                username,
                s1,
                s2,
                fmt_ts(meta.created_at)?,
                fmt_ts(meta.updated_at)?,
            ],
        )?;
        tracing::info!(credential = %meta.id, kind = meta.kind.name(), "credential stored");
        self.get_credential(meta.id)
    }

    /// Metadata of one credential.
    pub fn get_credential(&self, id: CredentialId) -> Result<CredentialMeta> {
        let sql = format!("SELECT {META_COLS} FROM credential WHERE id = ?1");
        let raw = self.conn.query_row(&sql, [id.to_string()], row_to_meta).optional()?;
        decode(raw.ok_or_else(|| not_found("credential", &id))?)
    }

    /// Metadata of every credential, sorted by name. Never returns secrets.
    pub fn list_credentials(&self) -> Result<Vec<CredentialMeta>> {
        let sql = format!("SELECT {META_COLS} FROM credential ORDER BY name, id");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_meta)?;
        rows.map(|r| decode(r?)).collect()
    }

    /// Change name / username.
    pub fn update_credential_meta(
        &self,
        id: CredentialId,
        name: &str,
        username: Option<&str>,
    ) -> Result<CredentialMeta> {
        let name = check_name("name", name)?;
        let username = check_username(username)?;
        let n = self.conn.execute(
            "UPDATE credential SET name = ?2, username = ?3, updated_at = ?4 WHERE id = ?1",
            params![id.to_string(), name, username, fmt_ts(now())?],
        )?;
        if n == 0 {
            return Err(not_found("credential", &id));
        }
        self.get_credential(id)
    }

    /// Re-seal one secret column with a new value (`None` clears `secret2`; the primary
    /// secret cannot be cleared).
    pub fn replace_credential_secret(
        &self,
        vault: &Vault,
        id: CredentialId,
        field: SecretField,
        secret: Option<&[u8]>,
    ) -> Result<()> {
        let blob = match (field, secret) {
            (SecretField::Secret, None) => return Err(invalid("secret", "cannot be cleared")),
            (_, Some(s)) => Some(seal(vault, id, field, s)?),
            (SecretField::Secret2, None) => None,
        };
        let sql = format!(
            "UPDATE credential SET {} = ?2, updated_at = ?3 WHERE id = ?1",
            field.column() // static column name from the enum, never user input
        );
        let n = self.conn.execute(&sql, params![id.to_string(), blob, fmt_ts(now())?])?;
        if n == 0 {
            return Err(not_found("credential", &id));
        }
        tracing::info!(credential = %id, field = field.column(), "credential secret replaced");
        Ok(())
    }

    /// Delete a credential. Folders / connections referencing it fall back to inheritance
    /// (`ON DELETE SET NULL`).
    pub fn delete_credential(&self, id: CredentialId) -> Result<()> {
        let n = self.conn.execute("DELETE FROM credential WHERE id = ?1", [id.to_string()])?;
        if n == 0 {
            return Err(not_found("credential", &id));
        }
        tracing::info!(credential = %id, "credential deleted");
        Ok(())
    }

    /// Decrypt one secret column. Fails with `Vault(Tampered)` if the stored value was moved
    /// from another row or column, `NotFound { kind: "secret" }` if `secret2` is empty.
    pub fn open_credential_secret(
        &self,
        vault: &Vault,
        id: CredentialId,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let sql = format!("SELECT {} FROM credential WHERE id = ?1", field.column());
        let blob: Option<Option<Vec<u8>>> =
            self.conn.query_row(&sql, [id.to_string()], |r| r.get(0)).optional()?;
        let blob = blob.ok_or_else(|| not_found("credential", &id))?;
        let blob = blob.ok_or_else(|| not_found("secret", &id))?;
        let sealed: Sealed = serde_json::from_slice(&blob)
            .map_err(|_| StoreError::Corrupt { what: "sealed value" })?;
        Ok(vault.open(&id.to_string(), field.column(), &sealed)?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip() {
        for k in [CredentialKind::Password, CredentialKind::SshKey, CredentialKind::Certificate] {
            assert_eq!(CredentialKind::parse(k.name()).expect("known"), k);
        }
        assert!(CredentialKind::parse("token").is_err());
    }

    #[test]
    fn meta_validation() {
        assert!(CredentialMeta::new("", CredentialKind::Password, None).is_err());
        assert!(CredentialMeta::new("x", CredentialKind::Password, Some(&"u".repeat(257))).is_err());
        let m = CredentialMeta::new(" lab ", CredentialKind::SshKey, Some("  ")).expect("ok");
        assert_eq!(m.name, "lab");
        assert_eq!(m.username, None);
    }
}
