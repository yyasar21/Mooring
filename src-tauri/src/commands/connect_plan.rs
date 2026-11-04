//! What `session_open` resolves from the store before any network I/O (ADR-0009 §3, §6):
//! the connection, its effective primary credential with overrides applied, the `become`
//! credential, and the `ConnectSecret` each typed kind maps to. SSH, RDP and VNC sessions
//! exist (ADR-0011/0012); other protocols fail with `session.failed`. Graphical sessions call
//! this again on every reconnect attempt, so a locked vault stops the retries.

use mooring_core::credential::{CredentialError, CredentialFields};
use mooring_core::session::{Become, ConnectParams, ConnectSecret, PromptAccount, Size};
use mooring_core::{CredentialId, Protocol, ProtocolOptions, Role, SecretName};
use mooring_store::{Resolved, Store, StoreError};
use mooring_vault::Vault;
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::Ready;

/// The resolved plan: parameters for the protocol crate and the credentials used (for audit).
#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) params: ConnectParams,
    pub(crate) used: Vec<String>,
    pub(crate) protocol: Protocol,
    /// The connection's validated options (ADR-0011 migration 0005).
    pub(crate) options: ProtocolOptions,
}

fn secret_text(bytes: Zeroizing<Vec<u8>>) -> IpcResult<SecretString> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| IpcError::session_failed("stored secret is not text"))?;
    drop(bytes);
    Ok(SecretString::from(text))
}

fn open(store: &Store, vault: &Vault, id: CredentialId, name: SecretName) -> IpcResult<SecretString> {
    match store.open_secret(vault, id, name) {
        Ok(b) => secret_text(b),
        Err(StoreError::NotFound { kind: "secret", .. }) => {
            Err(CredentialError::SecretMissing(name).into())
        }
        Err(e) => Err(e.into()),
    }
}

fn open_opt(store: &Store, vault: &Vault, id: CredentialId, name: SecretName) -> IpcResult<Option<SecretString>> {
    match store.open_secret(vault, id, name) {
        Ok(b) => secret_text(b).map(Some),
        Err(StoreError::NotFound { kind: "secret", .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn unsupported(what: &str, p: Protocol) -> IpcError {
    let p = p.name().to_uppercase();
    CredentialError::KindUnsupported(format!("{what} is not supported for {p} in this version.")).into()
}

/// SSH: the `ConnectSecret` and login name for a resolved primary credential.
fn ssh_secret(store: &Store, vault: &Vault, r: &Resolved) -> IpcResult<(Option<String>, ConnectSecret)> {
    let id = r.id;
    Ok(match &r.fields {
        CredentialFields::UserPassword(f) => {
            (Some(f.username.clone()), ConnectSecret::Password(open(store, vault, id, SecretName::Password)?))
        }
        CredentialFields::DomainUser(f) => {
            let password = open(store, vault, id, SecretName::Password)?;
            let (user, domain) = match f.form {
                mooring_core::credential::AccountForm::Netbios => (f.user.clone(), f.domain.clone()),
                mooring_core::credential::AccountForm::Upn => (format!("{}@{}", f.user, f.domain), String::new()),
            };
            (Some(user.clone()), ConnectSecret::DomainPassword { user, domain, password })
        }
        CredentialFields::SshKey(f) => {
            let pem = open(store, vault, id, SecretName::PrivateKey)?;
            let passphrase = open_opt(store, vault, id, SecretName::Passphrase)?;
            (Some(f.username.clone()), ConnectSecret::PrivateKey { pem, passphrase })
        }
        CredentialFields::SshAgent(f) => {
            (Some(f.username.clone()), ConnectSecret::Agent { fingerprint: f.key_fingerprint.clone() })
        }
        CredentialFields::Prompt(f) => {
            let account = PromptAccount {
                username: f.username.clone(),
                domain: f.domain.clone(),
                needs_username: f.username.is_none(),
                needs_domain: false,
            };
            (f.username.clone(), ConnectSecret::Prompt(account))
        }
        CredentialFields::ExternalRef(_) => return Err(unsupported("A secret manager reference", Protocol::Ssh)),
        // Every other kind is refused by the matrix before this point.
        _ => return Err(unsupported("This credential", Protocol::Ssh)),
    })
}

/// RDP / VNC: `user_password`, `domain_user`, `vnc_*` and `prompt` (ADR-0009 matrix,
/// ADR-0011 §credentials). The RDP prompt form always asks for the domain.
fn graphical_secret(
    store: &Store,
    vault: &Vault,
    r: &Resolved,
    protocol: Protocol,
) -> IpcResult<(Option<String>, ConnectSecret)> {
    let id = r.id;
    let password = || open(store, vault, id, SecretName::Password);
    Ok(match &r.fields {
        CredentialFields::UserPassword(f) => (Some(f.username.clone()), ConnectSecret::Password(password()?)),
        CredentialFields::DomainUser(_) => ssh_secret(store, vault, r)?,
        CredentialFields::VncPassword(_) => (None, ConnectSecret::Password(password()?)),
        CredentialFields::VncUserPassword(f) => (Some(f.username.clone()), ConnectSecret::Password(password()?)),
        CredentialFields::Prompt(f) => {
            let rdp = protocol == Protocol::Rdp;
            let account = PromptAccount {
                username: f.username.clone(),
                domain: f.domain.clone(),
                needs_username: f.username.is_none() && rdp,
                needs_domain: rdp,
            };
            (f.username.clone(), ConnectSecret::Prompt(account))
        }
        _ => return Err(unsupported("This credential", protocol)),
    })
}

fn become_of(store: &Store, vault: &Vault, r: &Resolved) -> IpcResult<Become> {
    let CredentialFields::SudoBecome(f) = &r.fields else {
        return Err(unsupported("This become credential", Protocol::Ssh));
    };
    Ok(Become {
        method: f.method,
        user: f.become_user.clone(),
        password: open_opt(store, vault, r.id, SecretName::Password)?,
    })
}

/// Resolve everything for `session_open` (and each graphical reconnect).
pub(crate) fn plan(ready: &Ready, connection_id: &str, size: Size) -> IpcResult<Plan> {
    let id = dto::connection_id("connectionId", connection_id)?;
    ready.with_ready(|vault, store| {
        let c = store.get_connection(id)?;
        let protocol = c.protocol;
        if !matches!(protocol, Protocol::Ssh | Protocol::Rdp | Protocol::Vnc) {
            return Err(IpcError::session_failed(format!(
                "{} sessions are not available in this version",
                protocol.name()
            )));
        }
        let options = if protocol == Protocol::Ssh {
            ProtocolOptions::default_for(protocol)
        } else {
            store.connection_options(id)?
        };
        let port = c.effective_port().unwrap_or(22);
        let mut used = Vec::new();
        let (username, secret) = match store.resolve_credential(id, Role::Primary)? {
            None => (None, ConnectSecret::None),
            Some(r) => {
                used.push(r.id.to_string());
                if protocol == Protocol::Ssh {
                    ssh_secret(store, vault, &r)?
                } else {
                    graphical_secret(store, vault, &r, protocol)?
                }
            }
        };
        let r#become = match store.resolve_credential(id, Role::Become)? {
            Some(r) if protocol == Protocol::Ssh => {
                used.push(r.id.to_string());
                Some(become_of(store, vault, &r)?)
            }
            _ => None,
        };
        let params = ConnectParams { host: c.host, port, username, secret, r#become, size };
        Ok(Plan { params, used, protocol, options })
    })
}
