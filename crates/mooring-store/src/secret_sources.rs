//! Secret sources (ADR-0016 §1, migration 0007). The table holds no secret material: the
//! login is a credential id (`api_token` / `vault_approle`, kind checked here) or an OIDC
//! role. A source cannot be deleted while an `external_ref` names it, and a credential cannot
//! be deleted while a source logs in with it (`StoreError::InUse`).

use mooring_core::credential::{check_consumer, Consumer};
use mooring_core::secret_source::{
    SecretSource, SecretSourceAuth, SecretSourceInput, SourceAuthMethod, SourceKind, SourceOptions,
    ValidSource,
};
use mooring_core::{CredentialFields, CredentialId, CredentialKind, SecretSourceId};
use rusqlite::{params, OptionalExtension, Row};

use crate::error::{not_found, Result, StoreError};
use crate::util::{fmt_ts, now, parse_id, parse_ts};
use crate::Store;

const COLUMNS: &str = "id, name, kind, address, namespace, auth_method, auth_mount, credential_id,
                       oidc_role, options_json, created_at, updated_at";

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt { what }
}

type RawRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
);

fn raw(r: &Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
    ))
}

/// Rebuild a row through the same validation as input: a row that no longer validates is
/// `Corrupt`, never a partially used source.
fn decode(row: RawRow) -> Result<SecretSource> {
    let (id, name, kind, address, namespace, method, mount, cred, role, options, created, updated) =
        row;
    if kind != "vault" {
        return Err(corrupt("secret source kind"));
    }
    let auth_method =
        SourceAuthMethod::parse(&method).ok_or(corrupt("secret source auth method"))?;
    let options: SourceOptions =
        serde_json::from_str(&options).map_err(|_| corrupt("secret source options"))?;
    let input = SecretSourceInput {
        name,
        address,
        namespace,
        auth_method,
        auth_mount: Some(mount),
        credential_id: cred.as_deref().map(parse_id).transpose()?,
        oidc_role: role,
        options,
    };
    let v = input.validate().map_err(|_| corrupt("secret source"))?;
    Ok(SecretSource {
        id: parse_id(&id)?,
        name: v.name,
        kind: SourceKind::Vault,
        address: v.address,
        namespace: v.namespace,
        auth: v.auth,
        options: v.options,
        created_at: parse_ts(&created)?,
        updated_at: parse_ts(&updated)?,
    })
}

/// The login credential must exist and be of the method's kind.
fn check_login_credential(store: &Store, auth: &SecretSourceAuth) -> Result<()> {
    let Some(id) = auth.credential_id() else {
        return Ok(());
    };
    let meta = store.get_credential(id)?;
    check_consumer(meta.kind, Consumer::SecretSource)?;
    if auth.method().credential_kind() != Some(meta.kind) {
        return Err(StoreError::Invalid {
            field: "credentialId",
            reason: format!(
                "the {} method needs a {} credential",
                auth.method().name(),
                auth.method().credential_kind().map_or("", CredentialKind::name)
            ),
        });
    }
    Ok(())
}

fn options_json(o: &SourceOptions) -> Result<String> {
    serde_json::to_string(o).map_err(|_| corrupt("secret source options"))
}

fn oidc_role(auth: &SecretSourceAuth) -> Option<&str> {
    match auth {
        SecretSourceAuth::Oidc { role, .. } => Some(role),
        _ => None,
    }
}

impl Store {
    /// Create a source (validated; the login credential's kind is checked).
    pub fn create_secret_source(&self, input: &SecretSourceInput) -> Result<SecretSource> {
        let v: ValidSource = input.validate()?;
        check_login_credential(self, &v.auth)?;
        let id = SecretSourceId::new();
        let ts = fmt_ts(now())?;
        self.conn.execute(
            &format!(
                "INSERT INTO secret_source ({COLUMNS})
                 VALUES (?1, ?2, 'vault', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)"
            ),
            params![
                id.to_string(),
                v.name,
                v.address,
                v.namespace,
                v.auth.method().name(),
                v.auth.mount(),
                v.auth.credential_id().map(|c| c.to_string()),
                oidc_role(&v.auth),
                options_json(&v.options)?,
                ts
            ],
        )?;
        tracing::info!(source = %id, method = v.auth.method().name(), "secret source created");
        self.get_secret_source(id)
    }

    /// One source.
    pub fn get_secret_source(&self, id: SecretSourceId) -> Result<SecretSource> {
        let row = self
            .conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM secret_source WHERE id = ?1"),
                [id.to_string()],
                raw,
            )
            .optional()?;
        decode(row.ok_or_else(|| not_found("secret_source", &id))?)
    }

    /// Every source, sorted by name.
    pub fn list_secret_sources(&self) -> Result<Vec<SecretSource>> {
        let mut stmt =
            self.conn.prepare(&format!("SELECT {COLUMNS} FROM secret_source ORDER BY name, id"))?;
        let rows = stmt.query_map([], raw)?.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode).collect()
    }

    /// Replace every field of a source (id and `created_at` stay). Returns the new row and
    /// the names of the changed fields (for `secret.source_changed`).
    pub fn update_secret_source(
        &self,
        id: SecretSourceId,
        input: &SecretSourceInput,
    ) -> Result<(SecretSource, Vec<&'static str>)> {
        let before = self.get_secret_source(id)?;
        let v = input.validate()?;
        check_login_credential(self, &v.auth)?;
        self.conn.execute(
            "UPDATE secret_source SET name = ?2, address = ?3, namespace = ?4, auth_method = ?5,
                    auth_mount = ?6, credential_id = ?7, oidc_role = ?8, options_json = ?9,
                    updated_at = ?10
             WHERE id = ?1",
            params![
                id.to_string(),
                v.name,
                v.address,
                v.namespace,
                v.auth.method().name(),
                v.auth.mount(),
                v.auth.credential_id().map(|c| c.to_string()),
                oidc_role(&v.auth),
                options_json(&v.options)?,
                fmt_ts(now())?
            ],
        )?;
        let after = self.get_secret_source(id)?;
        Ok((after.clone(), changed(&before, &after)))
    }

    /// Delete a source; refused while an `external_ref` credential names it.
    pub fn delete_secret_source(&self, id: SecretSourceId) -> Result<()> {
        self.get_secret_source(id)?;
        if !self.external_refs_of(id)?.is_empty() {
            return Err(StoreError::InUse { kind: "secret_source", id: id.to_string() });
        }
        self.conn.execute("DELETE FROM secret_source WHERE id = ?1", [id.to_string()])?;
        tracing::info!(source = %id, "secret source deleted");
        Ok(())
    }

    /// `external_ref` credentials that resolve from `source`.
    pub fn external_refs_of(&self, source: SecretSourceId) -> Result<Vec<CredentialId>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM credential
             WHERE kind = 'external_ref' AND json_extract(fields_json, '$.source') = ?1
             ORDER BY id",
        )?;
        let ids = stmt
            .query_map([source.to_string()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter().map(|s| parse_id(s)).collect()
    }

    /// Sources that log in with `credential`.
    pub fn sources_using_credential(
        &self,
        credential: CredentialId,
    ) -> Result<Vec<SecretSourceId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM secret_source WHERE credential_id = ?1 ORDER BY id")?;
        let ids = stmt
            .query_map([credential.to_string()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter().map(|s| parse_id(s)).collect()
    }

    /// The source an `external_ref` credential names, checked to exist.
    pub fn source_of(&self, fields: &CredentialFields) -> Result<Option<SecretSource>> {
        match fields {
            CredentialFields::ExternalRef(f) => {
                f.source.map(|id| self.get_secret_source(id)).transpose()
            }
            _ => Ok(None),
        }
    }
}

fn changed(a: &SecretSource, b: &SecretSource) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut diff = |name, differs: bool| {
        if differs {
            out.push(name);
        }
    };
    diff("name", a.name != b.name);
    diff("address", a.address != b.address);
    diff("namespace", a.namespace != b.namespace);
    diff("auth", a.auth != b.auth);
    diff("caPem", a.options.ca_pem != b.options.ca_pem);
    diff("allowHttp", a.options.allow_http != b.options.allow_http);
    diff("allowedOrigins", a.options.allowed_origins != b.options.allowed_origins);
    out
}

#[cfg(test)]
#[path = "secret_sources_tests.rs"]
mod tests;
