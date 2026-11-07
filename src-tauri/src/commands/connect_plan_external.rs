//! ADR-0016 §3 / ADR-0026 at connect: an `external_ref` primary (or SSH `become`) credential is
//! resolved through the [`mooring_secrets::SecretsEngine`] **before** the plan takes the vault
//! and store locks, then mapped into the `ConnectSecret` of its `target_kind` exactly as a
//! stored credential of that kind would be. A Vault `ssh_sign` reference in the SSH
//! `certificate` role has the key credential's **public** key signed and the certificate is
//! attached to the key. Dynamic leases belong to the session (`owner`); a reconnect revokes
//! the old ones first. The [`ResolvedSecrets`] are dropped (zeroized) as soon as the plan is
//! built; nothing is cached or written.

use mooring_core::credential::{
    ssh_public_key_line, AccountForm, CredentialError, CredentialFields, ExternalRefFields,
    VaultEngine,
};
use mooring_core::secret_source::SecretSource;
use mooring_core::session::{Become, ConnectSecret};
use mooring_core::{CredentialId, CredentialKind, Protocol, Role, SecretName};
use mooring_secrets::{ResolveCtx, ResolvedSecrets};
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
    certificate: Option<(CredentialId, String)>,
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

    /// The certificate signed for the `certificate` role credential `id`.
    pub(super) fn certificate(&self, id: CredentialId) -> IpcResult<String> {
        match &self.certificate {
            Some((c, line)) if *c == id => Ok(line.clone()),
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

fn engine_error(reason: &str) -> IpcError {
    IpcError::new("credential.external_engine", reason)
}

struct Pending {
    role: Role,
    id: CredentialId,
    fields: ExternalRefFields,
    source: SecretSource,
}

/// The public key the `certificate` role signs.
enum KeyPub {
    /// Of a stored `ssh_key` (public field or the clear half of an OpenSSH key).
    Line(String),
    /// Of the `external_ref` primary, once resolved.
    FromPrimary,
}

struct Todo {
    pending: Vec<Pending>,
    host: String,
    port: u16,
    key: Option<KeyPub>,
}

/// The `external_ref` credentials of one connect, with their sources (read under the locks).
fn pending(ready: &Ready, connection_id: &str) -> IpcResult<Todo> {
    let id = dto::connection_id("connectionId", connection_id)?;
    ready.with_ready(|vault, store| {
        let c = store.get_connection(id)?;
        let roles: &[Role] = match c.protocol {
            Protocol::Ssh => &[Role::Primary, Role::Become, Role::Certificate],
            Protocol::Rdp | Protocol::Vnc => &[Role::Primary],
            _ => &[],
        };
        let mut todo = Todo {
            pending: Vec::new(),
            host: c.host.clone(),
            port: c.effective_port().unwrap_or(22),
            key: None,
        };
        for &role in roles {
            let Some(r) = store.resolve_credential(id, role)? else { continue };
            let CredentialFields::ExternalRef(f) = &r.fields else { continue };
            if role == Role::Certificate {
                let primary = store.resolve_credential(id, Role::Primary)?;
                todo.key = Some(match primary.as_ref().map(|p| (p.id, &p.fields)) {
                    Some((pid, CredentialFields::SshKey(k))) => {
                        let pem = match k.public_key {
                            None => store.open_secret(vault, pid, SecretName::PrivateKey)?,
                            Some(_) => zeroize::Zeroizing::new(Vec::new()),
                        };
                        KeyPub::Line(ssh_public_key_line(k.public_key.as_deref(), &pem)?)
                    }
                    // ADR-0024: an sk key is signed like any other (`sk-*-cert-v01`).
                    Some((_, CredentialFields::SshSkKey(k))) => {
                        KeyPub::Line(ssh_public_key_line(Some(&k.public_key), &[])?)
                    }
                    Some((_, CredentialFields::ExternalRef(p))) if p.target_kind == CredentialKind::SshKey => {
                        KeyPub::FromPrimary
                    }
                    _ => return Err(engine_error("the SSH certificate role needs an SSH key as the sign-in credential")),
                });
            }
            let source = store
                .source_of(&r.fields)
                .map_err(source_error)?
                .ok_or_else(|| IpcError::new("source.not_found", "the reference names no secret source"))?;
            todo.pending.push(Pending { role, id: r.id, fields: f.clone(), source });
        }
        Ok(todo)
    })
}

/// The IP address Vault issues an SSH one-time password for (a literal, or the first
/// address the host resolves to).
async fn target_ip(host: &str, port: u16) -> IpcResult<std::net::IpAddr> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| IpcError::session_failed("the host name could not be resolved for the one-time password"))?;
    addrs
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| IpcError::session_failed("the host name could not be resolved for the one-time password"))
}

/// Resolve every `external_ref` of the connection (network I/O, no lock held). `owner` is
/// the session the dynamic leases belong to; its earlier leases are revoked first.
pub(super) async fn prefetch(ready: &Ready, connection_id: &str, owner: &str) -> IpcResult<External> {
    ready.secrets.engine().leases().release(owner, "reconnect").retire().await;
    let todo = pending(ready, connection_id)?;
    let mut ext = External::default();
    if todo.pending.is_empty() {
        return Ok(ext);
    }
    let otp = todo.pending.iter().any(|p| p.fields.engine == VaultEngine::SshOtp);
    let ip = if otp { Some(target_ip(&todo.host, todo.port).await?) } else { None };
    let ctx = ResolveCtx { owner: Some(owner), ip, revoke_cert: false };
    let provider = login_provider(ready.clone());
    let connection = dto::connection_id("connectionId", connection_id)?.to_string();
    let (certs, logins): (Vec<Pending>, Vec<Pending>) =
        todo.pending.into_iter().partition(|p| p.role == Role::Certificate);
    for p in logins {
        // A cached token must not outlive a lock that raced this connect.
        if !ready.unlocked() {
            return Err(IpcError::locked());
        }
        let engine = ready.secrets.engine();
        let resolve = engine.resolve_in(&p.source, p.id, &p.fields, &provider, &ctx);
        let r = Box::pin(with_connection(connection.clone(), resolve)).await.map_err(|e| ipc_error(&e))?;
        match p.role {
            Role::Primary => ext.primary = Some((p.id, r)),
            _ => ext.become_ = Some((p.id, r)),
        }
    }
    for p in certs {
        if !ready.unlocked() {
            return Err(IpcError::locked());
        }
        let line = match &todo.key {
            Some(KeyPub::Line(l)) => l.clone(),
            Some(KeyPub::FromPrimary) => {
                let (_, r) = ext.primary.as_ref().ok_or_else(changed)?;
                let public = match &r.fields {
                    CredentialFields::SshKey(k) => k.public_key.clone(),
                    _ => None,
                };
                let pem = r.secret(SecretName::PrivateKey).unwrap_or_default();
                ssh_public_key_line(public.as_deref(), pem)?
            }
            None => return Err(changed()),
        };
        let engine = ready.secrets.engine();
        let sign = engine.sign_ssh_key(&p.source, p.id, &p.fields, &provider, &line);
        let c = Box::pin(with_connection(connection.clone(), sign)).await.map_err(|e| ipc_error(&e))?;
        ext.certificate = Some((p.id, c.line));
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
            let certificate = f.certificate.clone();
            (Some(f.username.clone()), ConnectSecret::PrivateKey { pem, passphrase, certificate })
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
