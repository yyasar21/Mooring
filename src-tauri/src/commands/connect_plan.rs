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
    /// ADR-0025: the jump hosts, first hop first (empty = direct).
    pub(crate) hops: Vec<HopPlan>,
}

/// One resolved jump host: its connection id (audit) and SSH parameters with its own
/// credential (ADR-0009 §3 resolution of the hop's connection, never the leaf's).
#[derive(Debug)]
pub(crate) struct HopPlan {
    pub(crate) connection: String,
    pub(crate) params: ConnectParams,
}

fn hop_failed(reason: impl Into<String>) -> IpcError {
    IpcError::new("session.hop_failed", reason)
}

/// ADR-0025 §1: resolve every hop of `c.via` (its own credential, port, host). A hop's own
/// `via` is ignored. A hop that is not SSH (the store refuses that on save; a hand-edited
/// database could still hold one) or whose credential cannot log in fails with
/// `session.hop_failed` before any network I/O.
pub(crate) fn hops_of(
    store: &Store,
    vault: &Vault,
    c: &mooring_core::Connection,
    used: &mut Vec<String>,
) -> IpcResult<Vec<HopPlan>> {
    mooring_core::validate_via(c.id, &c.via)?;
    let mut out = Vec::with_capacity(c.via.len());
    for (i, hop_id) in c.via.iter().enumerate() {
        let n = i + 1;
        let hop = store.get_connection(*hop_id).map_err(|e| match e {
            StoreError::NotFound { .. } => hop_failed(format!("jump host {n} does not exist")),
            other => other.into(),
        })?;
        if hop.protocol != Protocol::Ssh {
            return Err(hop_failed(format!("jump host {n} is not an SSH connection")));
        }
        let (username, secret) = match store.resolve_credential(hop.id, Role::Primary)? {
            None => (None, ConnectSecret::None),
            Some(r) if matches!(r.fields, CredentialFields::ExternalRef(_)) => {
                return Err(hop_failed(format!(
                    "jump host {n}: secret manager references are not supported for jump hosts in this version"
                )));
            }
            Some(r) => {
                used.push(r.id.to_string());
                ssh_secret(store, vault, &r)?
            }
        };
        let params = ConnectParams {
            host: hop.host.clone(),
            port: hop.effective_port().unwrap_or(22),
            username,
            secret,
            r#become: None,
            size: Size { width: 80, height: 24 },
        };
        out.push(HopPlan { connection: hop.id.to_string(), params });
    }
    Ok(out)
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
            let certificate = f.certificate.clone();
            (Some(f.username.clone()), ConnectSecret::PrivateKey { pem, passphrase, certificate })
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

/// Resolve everything for `session_open` (and each graphical reconnect). An `external_ref`
/// primary, `become` or `certificate` credential is resolved first, outside every lock
/// (ADR-0016 §3); dynamic leases belong to `session` (ADR-0026 §2).
pub(crate) async fn plan(ready: &Ready, connection_id: &str, size: Size, session: &str) -> IpcResult<Plan> {
    // Boxed: the resolve futures are large (clippy::large_futures).
    let ext = Box::pin(external::prefetch(ready, connection_id, session)).await?;
    plan_with(ready, connection_id, size, &ext)
}

fn plan_with(ready: &Ready, connection_id: &str, size: Size, ext: &external::External) -> IpcResult<Plan> {
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
                if let CredentialFields::ExternalRef(_) = &r.fields {
                    external::secret(ext.primary(r.id)?, protocol)?
                } else if protocol == Protocol::Ssh {
                    ssh_secret(store, vault, &r)?
                } else {
                    graphical_secret(store, vault, &r, protocol)?
                }
            }
        };
        let (username, mut secret) = (username, secret);
        if protocol == Protocol::Ssh {
            if let Some(r) = store.resolve_credential(id, Role::Certificate)? {
                used.push(r.id.to_string());
                let signed = ext.certificate(r.id)?;
                match &mut secret {
                    ConnectSecret::PrivateKey { certificate, .. } => *certificate = Some(signed),
                    _ => return Err(unsupported("An SSH certificate without an SSH key", protocol)),
                }
            }
        }
        let r#become = match store.resolve_credential(id, Role::Become)? {
            Some(r) if protocol == Protocol::Ssh => {
                used.push(r.id.to_string());
                if let CredentialFields::ExternalRef(_) = &r.fields {
                    Some(external::become_of(ext.r#become(r.id)?)?)
                } else {
                    Some(become_of(store, vault, &r)?)
                }
            }
            _ => None,
        };
        let hops = hops_of(store, vault, &c, &mut used)?;
        let params = ConnectParams { host: c.host, port, username, secret, r#become, size };
        Ok(Plan { params, used, protocol, options, hops })
    })
}

// --- ADR-0014 K4: Kubernetes ------------------------------------------------------------

/// What `kube_open` resolves before any network I/O.
pub(crate) struct KubePlan {
    /// Canonical connection id.
    pub(crate) connection_id: String,
    /// Server, trust anchor and user of the context (token / client key zeroized on drop).
    pub(crate) resolved: mooring_core::credential::kubeconfig::Resolved,
    /// The connection's validated options.
    pub(crate) options: mooring_core::options::KubeConnOptions,
    /// Credentials used (audit).
    pub(crate) used: Vec<String>,
    /// Unverified JWT `exp` of a bearer token (display only).
    pub(crate) token_expires_at: Option<time::OffsetDateTime>,
    /// ADR-0025: jump hosts to the API server (empty = direct).
    pub(crate) hops: Vec<HopPlan>,
}

impl std::fmt::Debug for KubePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubePlan").field("connection_id", &self.connection_id).finish_non_exhaustive()
    }
}

fn kube_resolve_error(e: &mooring_core::credential::kubeconfig::KubeResolveError) -> IpcError {
    let code = if e.code() == "kube.unsupported_auth" {
        "kube.unsupported_auth"
    } else {
        "credential.kubeconfig_rejected"
    };
    IpcError::new(code, e.to_string())
}

/// Resolve a Kubernetes connection: options, primary credential (`kubeconfig` or
/// `kube_token`), `check_credential(kind)` (ADR-0014 §3), the secret, and the JWT `exp` peek
/// (an already expired token fails with `kube.auth_failed`).
pub(crate) fn kube(ready: &Ready, connection_id: &str) -> IpcResult<KubePlan> {
    use mooring_core::credential::kubeconfig::{self, CaSource, KubeAuth};
    use secrecy::ExposeSecret as _;
    let id = dto::connection_id("connectionId", connection_id)?;
    ready.with_ready(|vault, store| {
        let c = store.get_connection(id)?;
        if c.protocol != Protocol::Kubernetes {
            return Err(IpcError::invalid("connectionId", "not a Kubernetes connection"));
        }
        let ProtocolOptions::Kube(options) = store.connection_options(id)? else {
            return Err(IpcError::invalid("options", "do not match the protocol"));
        };
        let Some(r) = store.resolve_credential(id, Role::Primary)? else {
            return Err(IpcError::new(
                "kube.unsupported_auth",
                "a Kubernetes connection needs a kubeconfig or kube_token credential",
            ));
        };
        options.check_credential(r.fields.kind())?;
        let mut resolved = match &r.fields {
            CredentialFields::Kubeconfig(f) => {
                let yaml = open(store, vault, r.id, SecretName::KubeconfigYaml)?;
                let context = options.context.as_deref().or(f.context.as_deref());
                kubeconfig::resolve(yaml.expose_secret().as_bytes(), context)
                    .map_err(|e| kube_resolve_error(&e))?
            }
            CredentialFields::KubeToken(_) => {
                let token = open(store, vault, r.id, SecretName::Token)?;
                let t = token.expose_secret();
                if t.is_empty() || t.len() > kubeconfig::MAX_TOKEN || !t.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(IpcError::new("kube.unsupported_auth", "the stored token is not a bearer token"));
                }
                let server = options.server_url().ok_or_else(|| IpcError::invalid("server", "required"))?;
                let ca = options.ca_pem.clone().ok_or_else(|| IpcError::invalid("caPem", "required"))?;
                kubeconfig::Resolved {
                    context_name: String::new(),
                    server,
                    ca: CaSource::Pem(ca.into_bytes()),
                    tls_server_name: None,
                    auth: KubeAuth::Token(token),
                    namespace: None,
                    insecure_skip: false,
                }
            }
            _ => return Err(unsupported("This credential", Protocol::Kubernetes)),
        };
        if let Some(name) = &options.tls_server_name {
            resolved.tls_server_name = Some(name.clone());
        }
        let token_expires_at = match &resolved.auth {
            KubeAuth::Token(t) => kubeconfig::peek_exp(t.expose_secret()),
            KubeAuth::ClientCert { .. } => None,
        };
        if token_expires_at.is_some_and(|t| t <= time::OffsetDateTime::now_utc()) {
            return Err(IpcError::new("kube.auth_failed", "the Kubernetes token has expired"));
        }
        let mut used = vec![r.id.to_string()];
        let hops = hops_of(store, vault, &c, &mut used)?;
        Ok(KubePlan { connection_id: id.to_string(), resolved, options, used, token_expires_at, hops })
    })
}
// --- end ADR-0014 K4 ----------------------------------------------------------------------

// --- ADR-0016 E2: external_ref resolution ----------------------------------------------------
#[path = "connect_plan_external.rs"]
mod external;
#[cfg(test)]
#[path = "connect_plan_dynamic_tests.rs"]
mod dynamic_tests;
pub(crate) use external::source_error;
