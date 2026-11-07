//! ssh-agent authentication (opt-in, ADR-0007 step 2). Plain keys and certificates of every
//! type; `sk-*` identities get the touch banner (ADR-0024 §2).
//!
//! Unix: `SSH_AUTH_SOCK`. Windows: Pageant, then the OpenSSH agent named pipe. Anything
//! else, or an unreachable agent, skips this step silently (logged at `debug`).

use mooring_core::session::SessionEvent;
use russh::client::{AuthResult, Handle};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;
use russh::MethodSet;

use crate::auth::{rsa_hash, AuthError};
use crate::handler::ClientHandler;
use crate::shared::Shared;

type DynAgent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

#[cfg(unix)]
async fn connect_agent() -> Option<DynAgent> {
    AgentClient::connect_env().await.ok().map(AgentClient::dynamic)
}

#[cfg(windows)]
async fn connect_agent() -> Option<DynAgent> {
    if let Ok(a) = AgentClient::connect_pageant().await {
        return Some(a.dynamic());
    }
    AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent")
        .await
        .ok()
        .map(AgentClient::dynamic)
}

#[cfg(not(any(unix, windows)))]
async fn connect_agent() -> Option<DynAgent> {
    None
}

/// Wraps the agent for an `sk-*` identity (ADR-0024 §2): the touch banner around the
/// signature and the 30 s deadline, as for an `ssh_sk_key` credential.
struct Touch<'a> {
    agent: &'a mut DynAgent,
    shared: &'a Shared,
    fingerprint: String,
    timeout: std::time::Duration,
}

impl russh::Signer for Touch<'_> {
    type Error = russh::AgentAuthError;

    #[allow(clippy::manual_async_fn)] // the trait asks for `impl Future + Send`
    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            let (id, hop) = (self.shared.broker.next_id(), self.shared.hop);
            let secs = u32::try_from(self.timeout.as_secs()).unwrap_or(u32::MAX);
            let fingerprint = self.fingerprint.clone();
            let _ = self
                .shared
                .events
                .send(SessionEvent::TouchRequired { id, fingerprint, timeout_seconds: secs, hop })
                .await;
            let signed =
                tokio::time::timeout(self.timeout, self.agent.sign_request(key, hash_alg, to_sign))
                    .await;
            let event = if signed.is_ok() {
                SessionEvent::TouchCleared { id, hop }
            } else {
                SessionEvent::TouchTimeout { id, hop }
            };
            let _ = self.shared.events.send(event).await;
            match signed {
                Ok(r) => r.map_err(Into::into),
                Err(_) => Err(russh::keys::Error::AgentFailure.into()),
            }
        }
    }
}

fn is_sk(alg: &russh::keys::Algorithm) -> bool {
    matches!(alg, russh::keys::Algorithm::SkEd25519 | russh::keys::Algorithm::SkEcdsaSha2NistP256)
}

/// `Some(true)` on success, `Some(false)` when every agent key was refused, `None` when no
/// agent is reachable. Updates `allowed` from the server's refusals. Certificates are tried
/// with `authenticate_certificate_with` (pinned by the certified key's fingerprint).
pub(crate) async fn try_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    pin: Option<&str>,
    allowed: &mut Option<MethodSet>,
    shared: &Shared,
    touch_timeout: std::time::Duration,
) -> Result<Option<bool>, AuthError> {
    let Some(mut agent) = connect_agent().await else {
        tracing::debug!("no ssh-agent reachable; skipping agent authentication");
        return Ok(None);
    };
    let Ok(identities) = agent.request_identities().await else {
        tracing::debug!("ssh-agent did not list identities");
        return Ok(None);
    };
    for identity in identities.into_iter().take(crate::auth::MAX_AGENT_KEYS_PUB) {
        let (alg, fp) = match &identity {
            AgentIdentity::PublicKey { key, .. } => {
                (key.algorithm(), key.fingerprint(HashAlg::Sha256))
            }
            AgentIdentity::Certificate { certificate, .. } => (
                certificate.algorithm(),
                russh::keys::ssh_key::Fingerprint::new(HashAlg::Sha256, certificate.public_key()),
            ),
        };
        let fp = fp.to_string();
        if pin.is_some_and(|p| fp != p) {
            continue;
        }
        let hash = if alg.clone().is_rsa() {
            match rsa_hash(handle).await {
                Some(h) => h,
                None => continue,
            }
        } else {
            None
        };
        let result = if is_sk(&alg) {
            let mut touch =
                Touch { agent: &mut agent, shared, fingerprint: fp, timeout: touch_timeout };
            sign_in(handle, user, identity, hash, &mut touch).await
        } else {
            sign_in(handle, user, identity, hash, &mut agent).await
        };
        match result {
            Ok(AuthResult::Success) => return Ok(Some(true)),
            Ok(AuthResult::Failure { remaining_methods, .. }) => {
                *allowed = Some(remaining_methods);
                if !allowed.as_ref().is_none_or(|m| m.contains(&russh::MethodKind::PublicKey)) {
                    break;
                }
            }
            Err(_) => {
                tracing::debug!("ssh-agent could not sign; trying the next identity");
                if handle.is_closed() {
                    return Err(AuthError::Transport);
                }
            }
        }
    }
    Ok(Some(false))
}

async fn sign_in<S: russh::Signer>(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    identity: AgentIdentity,
    hash: Option<HashAlg>,
    signer: &mut S,
) -> Result<AuthResult, S::Error> {
    match identity {
        AgentIdentity::PublicKey { key, .. } => {
            handle.authenticate_publickey_with(user.to_owned(), key, hash, signer).await
        }
        AgentIdentity::Certificate { certificate, .. } => {
            handle.authenticate_certificate_with(user.to_owned(), certificate, hash, signer).await
        }
    }
}
