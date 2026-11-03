//! ssh-agent authentication (opt-in, ADR-0007 step 2).
//!
//! Unix: `SSH_AUTH_SOCK`. Windows: Pageant, then the OpenSSH agent named pipe. Anything
//! else, or an unreachable agent, skips this step silently (logged at `debug`).

use russh::client::{AuthResult, Handle};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::AgentIdentity;
use russh::MethodSet;

use crate::auth::{rsa_hash, AuthError};
use crate::handler::ClientHandler;

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

/// `Some(true)` on success, `Some(false)` when every agent key was refused, `None` when no
/// agent is reachable. Updates `allowed` from the server's refusals.
pub(crate) async fn try_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    allowed: &mut Option<MethodSet>,
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
        let AgentIdentity::PublicKey { key, .. } = identity else {
            continue; // certificates: not in A1
        };
        let hash = if key.algorithm().is_rsa() {
            match rsa_hash(handle).await {
                Some(h) => h,
                None => continue,
            }
        } else {
            None
        };
        match handle.authenticate_publickey_with(user.to_owned(), key, hash, &mut agent).await {
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
