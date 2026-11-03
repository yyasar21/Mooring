//! Credential roles on a connection (ADR-0009 §3): the primary credential (own or inherited
//! through folders), per-connection secondary roles (`gateway`, `become`) and the username /
//! domain overrides. Compatibility with the connection's protocol is checked against the
//! matrix in `mooring_core::credential` whenever a credential is linked; an inherited
//! credential is not skipped when incompatible, the caller reports it.

use mooring_core::credential::{check_compatible, CredentialError};
use mooring_core::{Connection, ConnectionId, CredentialFields, CredentialId, Role};
use rusqlite::{params, OptionalExtension};

use crate::error::{invalid, Result, StoreError};
use crate::util::{fmt_ts, now, parse_opt_id};
use crate::Store;

/// Longest username override (bytes).
const MAX_USERNAME_OVERRIDE: usize = 256;
/// Longest domain override (bytes).
const MAX_DOMAIN_OVERRIDE: usize = 253;

/// Trim and check an override value; blank becomes `None`.
pub(crate) fn check_override(
    field: &'static str,
    v: Option<&str>,
    max: usize,
) -> Result<Option<String>> {
    let Some(v) = v.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if v.len() > max {
        return Err(invalid(field, &format!("longer than {max} bytes")));
    }
    if v.chars().any(mooring_core::credential::is_forbidden) {
        return Err(invalid(field, "contains a control or invisible formatting character"));
    }
    Ok(Some(v.to_owned()))
}

pub(crate) fn check_overrides(c: &Connection) -> Result<(Option<String>, Option<String>)> {
    Ok((
        check_override("usernameOverride", c.username_override.as_deref(), MAX_USERNAME_OVERRIDE)?,
        check_override("domainOverride", c.domain_override.as_deref(), MAX_DOMAIN_OVERRIDE)?,
    ))
}

/// The credential a connection uses in one role, with overrides applied (primary only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Credential id.
    pub id: CredentialId,
    /// Fields after the connection's overrides.
    pub fields: CredentialFields,
    /// Whether the credential came from the folder chain.
    pub inherited: bool,
}

impl Store {
    pub(crate) fn credential_fields(&self, id: CredentialId) -> Result<CredentialFields> {
        Ok(self.get_credential(id)?.fields)
    }

    /// Refuse a link whose kind cannot fill `role` on the connection's protocol.
    pub(crate) fn check_link(&self, c: &Connection, role: Role, cred: CredentialId) -> Result<()> {
        let fields = self.credential_fields(cred)?;
        check_compatible(&fields, c.protocol, role)?;
        Ok(())
    }

    /// Overrides must fit the effective credential's kind (validation error otherwise).
    pub(crate) fn check_override_fit(&self, c: &Connection) -> Result<()> {
        if c.username_override.is_none() && c.domain_override.is_none() {
            return Ok(());
        }
        let Some(cred) = self.effective_credential_for(c)? else {
            return Ok(());
        };
        let kind = self.credential_fields(cred)?.kind();
        if c.username_override.is_some() && !CredentialFields::supports_override(kind, false) {
            return Err(invalid("usernameOverride", "the effective credential has no username"));
        }
        if c.domain_override.is_some() && !CredentialFields::supports_override(kind, true) {
            return Err(invalid("domainOverride", "the effective credential has no domain"));
        }
        Ok(())
    }

    fn effective_credential_for(&self, c: &Connection) -> Result<Option<CredentialId>> {
        match c.credential {
            Some(id) => Ok(Some(id)),
            None => self.folder_default_chain(c.folder),
        }
    }

    /// Set or clear a secondary role. `Role::Primary` is the connection's own `credential`
    /// (use `update_connection`) and is refused here.
    pub fn set_connection_role_credential(
        &self,
        connection: ConnectionId,
        role: Role,
        credential: Option<CredentialId>,
    ) -> Result<Connection> {
        if role == Role::Primary {
            return Err(invalid("role", "must be gateway or become"));
        }
        let c = self.get_connection(connection)?;
        let tx = self.conn.unchecked_transaction()?;
        match credential {
            Some(cred) => {
                self.check_link(&c, role, cred)?;
                tx.execute(
                    "INSERT INTO connection_credential (connection_id, role, credential_id)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (connection_id, role) DO UPDATE SET credential_id = excluded.credential_id",
                    params![connection.to_string(), role.name(), cred.to_string()],
                )?;
            }
            None => {
                tx.execute(
                    "DELETE FROM connection_credential WHERE connection_id = ?1 AND role = ?2",
                    params![connection.to_string(), role.name()],
                )?;
            }
        }
        tx.execute(
            "UPDATE connection SET updated_at = ?2 WHERE id = ?1",
            params![connection.to_string(), fmt_ts(now())?],
        )?;
        tx.commit()?;
        self.get_connection(connection)
    }

    pub(crate) fn role_credential(
        &self,
        connection: &str,
        role: Role,
    ) -> Result<Option<CredentialId>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT credential_id FROM connection_credential
                 WHERE connection_id = ?1 AND role = ?2",
                params![connection, role.name()],
                |r| r.get(0),
            )
            .optional()?;
        parse_opt_id(raw.as_deref())
    }

    /// The credential a connection uses in `role`, with the username / domain overrides
    /// applied to the primary one. `None` when nothing is set (or inherited, for primary).
    /// Fails with `Credential(Incompatible)` when the credential cannot fill the role on the
    /// connection's protocol (an incompatible inherited credential is not skipped).
    pub fn resolve_credential(
        &self,
        connection: ConnectionId,
        role: Role,
    ) -> Result<Option<Resolved>> {
        let c = self.get_connection(connection)?;
        let (id, inherited) = match role {
            Role::Primary => match c.credential {
                Some(id) => (id, false),
                None => match self.effective_credential(connection)? {
                    Some(id) => (id, true),
                    None => return Ok(None),
                },
            },
            Role::Gateway => match c.gateway_credential {
                Some(id) => (id, false),
                None => return Ok(None),
            },
            Role::Become => match c.become_credential {
                Some(id) => (id, false),
                None => return Ok(None),
            },
        };
        let mut fields = self.credential_fields(id)?;
        check_compatible(&fields, c.protocol, role).map_err(StoreError::from)?;
        if role == Role::Primary {
            let kind = fields.kind();
            let user = c
                .username_override
                .as_deref()
                .filter(|_| CredentialFields::supports_override(kind, false));
            let dom = c
                .domain_override
                .as_deref()
                .filter(|_| CredentialFields::supports_override(kind, true));
            fields.apply_overrides(user, dom).map_err(|e| match e {
                CredentialError::Invalid { field, reason } => StoreError::Invalid { field, reason },
                other => other.into(),
            })?;
        }
        Ok(Some(Resolved { id, fields, inherited }))
    }

    /// Ensure a credential exists before linking it.
    pub(crate) fn ensure_role_credentials(&self, c: &Connection) -> Result<()> {
        for (role, cred) in
            [(Role::Gateway, c.gateway_credential), (Role::Become, c.become_credential)]
        {
            if let Some(cred) = cred {
                crate::credentials::ensure_credential(&self.conn, cred)?;
                self.check_link(c, role, cred)?;
            }
        }
        if let Some(cred) = c.credential {
            crate::credentials::ensure_credential(&self.conn, cred)?;
            self.check_link(c, Role::Primary, cred)?;
        }
        Ok(())
    }

    pub(crate) fn write_roles(tx: &rusqlite::Connection, c: &Connection) -> Result<()> {
        let id = c.id.to_string();
        tx.execute("DELETE FROM connection_credential WHERE connection_id = ?1", [&id])?;
        for (role, cred) in
            [(Role::Gateway, c.gateway_credential), (Role::Become, c.become_credential)]
        {
            if let Some(cred) = cred {
                tx.execute(
                    "INSERT INTO connection_credential (connection_id, role, credential_id)
                     VALUES (?1, ?2, ?3)",
                    params![id, role.name(), cred.to_string()],
                )?;
            }
        }
        Ok(())
    }
}
