//! ADR-0016 §3 at connect: an `external_ref` primary (or SSH `become`) credential is resolved
//! through the [`mooring_secrets::SecretsEngine`] **before** the plan takes the vault and
//! store locks, then mapped into the `ConnectSecret` of its `target_kind` exactly as a stored
//! credential of that kind would be. The [`ResolvedSecrets`] are dropped (zeroized) as soon as
//! the plan is built; nothing is cached or written. Reconnects resolve again.

use mooring_core::credential::{AccountForm, CredentialError, CredentialFields, ExternalRefFields, RefProvider};
use mooring_core::secret_source::SecretSource;
use mooring_core::session::{Become, ConnectSecret};
use mooring_core::{CredentialId, Protocol, Role, SecretName};
use mooring_secrets::ResolvedSecrets;
use mooring_store::StoreError;
use secrecy::SecretString;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::secrets_runtime::{ipc_error, login_provider, with_connection};
use crate::state::Ready;

/// What [`prefetch`] resolved, by role.
#[derive(Debug, Default)]
pub(super) struct External {
    primary: Option<(CredentialId, ResolvedSecrets)>,
    become_: Option<(CredentialId, ResolvedSecrets)>,
}

fn changed() -> IpcError {
    IpcError::session_failed("the credential changed while it was being resolved; try again")
}

impl External {
    pub(super) fn primary(&self, id: CredentialId) -> IpcResult<&ResolvedSecrets> {
        match &self.primary {
            Some((c, r)) if *c == id => Ok(r),
            _ => Err(changed()),
        }
    }

    pub(super) fn r#become(&self, id: CredentialId) -> IpcResult<&ResolvedSecrets> {
        match &self.become_ {
            Some((c, r)) if *c == id => Ok(r),
            _ => Err(changed()),
        }
    }
}

/// `source.not_found` for a missing source row.
pub(crate) fn source_error(e: StoreError) -> IpcError {
    match e {
        StoreError::NotFound { kind: "secret_source", .. } => {
            IpcError::new("source.not_found", "the secret source does not exist")
        }
        other => other.into(),
    }
}

struct Pending {
    role: Role,
    id: CredentialId,
    fields: ExternalRefFields,
    source: SecretSource,
}

/// The `external_ref` credentials of one connect, with their sources (read under the locks).
fn pending(ready: &Ready, connection_id: &str) -> IpcResult<Vec<Pending>> {
    let id = dto::connection_id("connectionId", connection_id)?;
    ready.with_ready(|_, store| {
        let protocol = store.get_connection(id)?.protocol;
        let roles: &[Role] = match protocol {
            Protocol::Ssh => &[Role::Primary, Role::Become],
            Protocol::Rdp | Protocol::Vnc => &[Role::Primary],
            _ => &[],
        };
        let mut out = Vec::new();
        for &role in roles {
            let Some(r) = store.resolve_credential(id, role)? else { continue };
            let CredentialFields::ExternalRef(f) = &r.fields else { continue };
            if f.provider != RefProvider::Vault {
                return Err(CredentialError::KindUnsupported(
                    "1Password and Bitwarden references are not supported in this version.".into(),
                )
                .into());
            }
            let source = store
                .source_of(&r.fields)
                .map_err(source_error)?
                .ok_or_else(|| IpcError::new("source.not_found", "the reference names no secret source"))?;
            out.push(Pending { role, id: r.id, fields: f.clone(), source });
        }
        Ok(out)
    })
}

/// Resolve every `external_ref` of the connection (network I/O, no lock held).
pub(super) async fn prefetch(ready: &Ready, connection_id: &str) -> IpcResult<External> {
    let todo = pending(ready, connection_id)?;
    let mut ext = External::default();
    if todo.is_empty() {
        return Ok(ext);
    }
    let provider = login_provider(ready.clone());
    let connection = dto::connection_id("connectionId", connection_id)?.to_string();
    for p in todo {
        // A cached token must not outlive a lock that raced this connect.
        if !ready.unlocked() {
            return Err(IpcError::locked());
        }
        let engine = ready.secrets.engine();
        let resolve = engine.resolve(&p.source, p.id, &p.fields, &provider);
        let r = with_connection(connection.clone(), resolve).await.map_err(|e| ipc_error(&e))?;
        match p.role {
            Role::Primary => ext.primary = Some((p.id, r)),
            _ => ext.become_ = Some((p.id, r)),
        }
    }
    Ok(ext)
}

fn text(r: &ResolvedSecrets, name: SecretName) -> IpcResult<Option<SecretString>> {
    r.secret(name)
        .map(|b| {
            std::str::from_utf8(b)
                .map(|s| SecretString::from(s.to_owned()))
                .map_err(|_| IpcError::session_failed("resolved secret is not text"))
        })
        .transpose()
}

fn required(r: &ResolvedSecrets, name: SecretName) -> IpcResult<SecretString> {
    text(r, name)?.ok_or_else(|| CredentialError::SecretMissing(name).into())
}

/// The `ConnectSecret` (and login name) of a resolved target credential.
pub(super) fn secret(r: &ResolvedSecrets, protocol: Protocol) -> IpcResult<(Option<String>, ConnectSecret)> {
    let password = || required(r, SecretName::Password);
    Ok(match (&r.fields, protocol) {
        (CredentialFields::UserPassword(f), Protocol::Ssh | Protocol::Rdp | Protocol::Vnc) => {
            (Some(f.username.clone()), ConnectSecret::Password(password()?))
        }
        (CredentialFields::DomainUser(f), Protocol::Ssh | Protocol::Rdp) => {
            let (user, domain) = match f.form {
                AccountForm::Netbios => (f.user.clone(), f.domain.clone()),
                AccountForm::Upn => (format!("{}@{}", f.user, f.domain), String::new()),
            };
            (Some(user.clone()), ConnectSecret::DomainPassword { user, domain, password: password()? })
        }
        (CredentialFields::SshKey(f), Protocol::Ssh) => {
            let pem = required(r, SecretName::PrivateKey)?;
            let passphrase = text(r, SecretName::Passphrase)?;
            (Some(f.username.clone()), ConnectSecret::PrivateKey { pem, passphrase })
        }
        (CredentialFields::VncPassword(_), Protocol::Vnc) => (None, ConnectSecret::Password(password()?)),
        (CredentialFields::VncUserPassword(f), Protocol::Vnc) => {
            (Some(f.username.clone()), ConnectSecret::Password(password()?))
        }
        _ => return Err(super::unsupported("This secret manager reference", protocol)),
    })
}

/// The SSH `become` of a resolved `sudo_become` target.
pub(super) fn become_of(r: &ResolvedSecrets) -> IpcResult<Become> {
    let CredentialFields::SudoBecome(f) = &r.fields else {
        return Err(super::unsupported("This become reference", Protocol::Ssh));
    };
    Ok(Become { method: f.method, user: f.become_user.clone(), password: text(r, SecretName::Password)? })
}
