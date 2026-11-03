//! What `session_open` resolves from the store before any network I/O (ADR-0009 §3, §6):
//! the connection, its effective primary credential with overrides applied, the `become`
//! credential, and the `ConnectSecret` each typed kind maps to. Only SSH sessions exist in
//! this version; other protocols fail with `session.failed`.

use mooring_core::credential::{CredentialError, CredentialFields};
use mooring_core::session::{Become, ConnectParams, ConnectSecret, PromptAccount, Size};
use mooring_core::{CredentialId, Protocol, Role, SecretName};
use mooring_store::{Resolved, Store, StoreError};
use mooring_vault::Vault;
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// The resolved plan: parameters for the protocol crate and the credentials used (for audit).
#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) params: ConnectParams,
    pub(crate) used: Vec<String>,
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

fn unsupported(what: &str) -> IpcError {
    CredentialError::KindUnsupported(format!("{what} is not supported for SSH in this version.")).into()
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
        CredentialFields::ExternalRef(_) => return Err(unsupported("A secret manager reference")),
        // Every other kind is refused by the matrix before this point.
        _ => return Err(unsupported("This credential")),
    })
}

fn become_of(store: &Store, vault: &Vault, r: &Resolved) -> IpcResult<Become> {
    let CredentialFields::SudoBecome(f) = &r.fields else {
        return Err(unsupported("This become credential"));
    };
    Ok(Become {
        method: f.method,
        user: f.become_user.clone(),
        password: open_opt(store, vault, r.id, SecretName::Password)?,
    })
}

/// Resolve everything for `session_open`.
pub(crate) fn plan(state: &AppState, connection_id: &str, size: Size) -> IpcResult<Plan> {
    let id = dto::connection_id("connectionId", connection_id)?;
    state.with_ready(|vault, store| {
        let c = store.get_connection(id)?;
        if c.protocol != Protocol::Ssh {
            return Err(IpcError::session_failed(format!(
                "{} sessions are not available in this version",
                c.protocol.name()
            )));
        }
        let port = c.effective_port().unwrap_or(22);
        let mut used = Vec::new();
        let (username, secret) = match store.resolve_credential(id, Role::Primary)? {
            None => (None, ConnectSecret::None),
            Some(r) => {
                used.push(r.id.to_string());
                ssh_secret(store, vault, &r)?
            }
        };
        let r#become = match store.resolve_credential(id, Role::Become)? {
            None => None,
            Some(r) => {
                used.push(r.id.to_string());
                Some(become_of(store, vault, &r)?)
            }
        };
        let params = ConnectParams { host: c.host, port, username, secret, r#become, size };
        Ok(Plan { params, used })
    })
}
