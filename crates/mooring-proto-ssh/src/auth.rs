//! Authentication (ADR-0007 §Authentication): publickey → agent → password →
//! keyboard-interactive, first success wins.
//!
//! Secrets live in [`Credentials`] (`SecretString`, zeroized on drop) and the decoded
//! private key (ssh-key zeroizes on drop); both are dropped when [`authenticate`] returns.
//! russh 0.65 limitation: `authenticate_password` and keyboard-interactive responses take a
//! plain `String` by value, so russh's internal copy cannot be zeroized by us; it is dropped
//! when russh finishes the request.

use std::sync::Arc;

use mooring_core::session::{CloseCode, ConnectSecret, PromptPurpose};
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{decode_secret_key, HashAlg, PrivateKeyWithHashAlg};
use russh::{MethodKind, MethodSet};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::audit::{AuthMethod, TrustEvent};
use crate::handler::ClientHandler;
use crate::shared::{sanitize, Shared};

/// Most keyboard-interactive rounds before giving up.
const MAX_KBD_ROUNDS: usize = 8;
/// Most prompts accepted in one keyboard-interactive round.
const MAX_KBD_PROMPTS: usize = 16;
/// Most agent identities tried.
pub(crate) const MAX_AGENT_KEYS_PUB: usize = 16;

/// What the user and the vault supplied for one login. Dropped after the auth round.
pub(crate) struct Credentials {
    pub(crate) user: String,
    pub(crate) secret: ConnectSecret,
    pub(crate) allow_agent: bool,
    pub(crate) sk: crate::sk_auth::SkOptions,
}

impl Credentials {
    pub(crate) fn new(user: String, secret: ConnectSecret, options: &crate::SshOptions) -> Self {
        let sk = crate::sk_auth::SkOptions {
            agent_path: options.agent_path.clone(),
            touch_timeout: options.sk_touch_timeout,
            helper: options.sk_helper.clone(),
        };
        Self { user, secret, allow_agent: options.allow_agent, sk }
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("secret", &self.secret)
            .field("allow_agent", &self.allow_agent)
            .field("sk", &self.sk)
            .finish()
    }
}

/// Why authentication stopped. Shown to the user only as a generic reason.
#[derive(Debug)]
pub(crate) enum AuthError {
    /// Every method was tried and refused.
    Failed,
    /// The user closed the session while a prompt was open.
    Cancelled,
    /// The connection broke.
    Transport,
    /// The user cancelled the connect-time sign-in form.
    PromptCancelled,
    /// `sk-*` material in an `ssh_key` credential (use the `ssh_sk_key` kind).
    Unsupported,
    /// An `ssh_sk_key` sign-in failed (ADR-0024); never followed by a password.
    SecurityKey(crate::sk_auth::SkFailure),
}

impl AuthError {
    pub(crate) fn code(&self) -> CloseCode {
        match self {
            Self::Failed | Self::SecurityKey(_) => CloseCode::AuthFailed,
            Self::Cancelled | Self::PromptCancelled => CloseCode::User,
            Self::Transport => CloseCode::Network,
            Self::Unsupported => CloseCode::ProtocolError,
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Failed => "authentication failed",
            Self::Cancelled => "closed by user",
            Self::Transport => "connection lost",
            Self::PromptCancelled => "authentication cancelled",
            Self::Unsupported => {
                "this is a FIDO2 security key: use an \"SSH security key (FIDO2)\" credential"
            }
            Self::SecurityKey(f) => f.reason(),
        }
    }
}

type H = Handle<ClientHandler>;

/// Methods the server still accepts; `None` until the first refusal tells us.
struct Allowed(Option<MethodSet>);

impl Allowed {
    fn permits(&self, kind: MethodKind) -> bool {
        self.0.as_ref().is_none_or(|set| set.contains(&kind))
    }

    /// `true` on success; otherwise remembers what the server still offers.
    fn record(&mut self, result: AuthResult) -> bool {
        match result {
            AuthResult::Success => true,
            AuthResult::Failure { remaining_methods, .. } => {
                // Empty means nothing is left (RFC 4252 §5.1); russh also ends the session then.
                self.0 = Some(remaining_methods);
                false
            }
        }
    }
}

/// Run the auth round. Consumes (and so drops) the credentials.
pub(crate) async fn authenticate(
    handle: &mut H,
    creds: Credentials,
    shared: &Shared,
) -> Result<AuthMethod, AuthError> {
    let Credentials { user, secret, allow_agent, sk } = creds;
    let (user, secret) = resolve(user, secret, shared).await?;
    // ADR-0024 decision 30: a security key is the only method tried, never a password.
    if let ConnectSecret::SecurityKey(login) = &secret {
        return crate::sk_auth::authenticate(handle, &user, login, shared, &sk).await;
    }
    let mut allowed = Allowed(None);
    let mut key_failed = false;

    if let ConnectSecret::PrivateKey { pem, passphrase, certificate } = &secret {
        if allowed.permits(MethodKind::PublicKey) {
            if let Some(cert) = certificate {
                let r = try_certificate(handle, &user, pem, passphrase.as_ref(), cert).await?;
                if r.is_some_and(|r| allowed.record(r)) {
                    return ok(shared, AuthMethod::PublicKey);
                }
            }
        }
        if allowed.permits(MethodKind::PublicKey) {
            let result = try_private_key(handle, &user, pem, passphrase.as_ref()).await?;
            if result.is_some_and(|r| allowed.record(r)) {
                return ok(shared, AuthMethod::PublicKey);
            }
            key_failed = true;
        }
    }

    // An explicit `ssh_agent` credential uses the agent even when the app setting is off for
    // implicit fallback; `pin` restricts it to one key.
    let (agent_wanted, pin) = match &secret {
        ConnectSecret::Agent { fingerprint } => (true, fingerprint.as_deref()),
        ConnectSecret::None => (allow_agent, None),
        _ => (allow_agent && key_failed, None),
    };
    if agent_wanted && allowed.permits(MethodKind::PublicKey) {
        if let Some(true) =
            crate::agent::try_agent(handle, &user, pin, &mut allowed.0, shared, sk.touch_timeout)
                .await?
        {
            return ok(shared, AuthMethod::Agent);
        }
    }

    let password = match &secret {
        ConnectSecret::Password(p) => Some(p),
        _ => None,
    };
    if let Some(pw) = password {
        if allowed.permits(MethodKind::Password) {
            let result = handle
                .authenticate_password(user.clone(), pw.expose_secret().to_owned())
                .await
                .map_err(transport)?;
            if allowed.record(result) {
                return ok(shared, AuthMethod::Password);
            }
        }
    }

    if allowed.permits(MethodKind::KeyboardInteractive)
        && keyboard_interactive(handle, &user, password, shared).await?
    {
        return ok(shared, AuthMethod::KeyboardInteractive);
    }

    shared.audit.push(TrustEvent::AuthFailed);
    Err(AuthError::Failed)
}

/// Turn the connect-time forms into plain secrets: a `prompt` credential asks the user once
/// (one form: username, domain, password); `DomainPassword` logs in as `user@domain` (`NetBIOS`)
/// or the UPN as given (ADR-0009 §2 footnote 2). FIDO2 keys are refused up front.
async fn resolve(
    user: String,
    secret: ConnectSecret,
    shared: &Shared,
) -> Result<(String, ConnectSecret), AuthError> {
    match secret {
        ConnectSecret::Prompt(account) => {
            let form = shared
                .broker
                .ask_credential(&shared.events, account, shared.hop)
                .await
                .ok_or(AuthError::Cancelled)?;
            let typed = form.username.trim().to_owned();
            if typed.is_empty() && form.password.expose_secret().is_empty() {
                return Err(AuthError::PromptCancelled);
            }
            let login = if typed.is_empty() { user } else { typed };
            let login = match form.domain.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
                Some(d) if !login.contains(['@', '\\']) => format!("{login}@{d}"),
                _ => login,
            };
            if login.is_empty() || login.chars().any(char::is_control) {
                return Err(AuthError::Failed);
            }
            Ok((login, ConnectSecret::Password(form.password)))
        }
        ConnectSecret::DomainPassword { user: u, domain, password } => {
            let login = if domain.is_empty() { u } else { format!("{u}@{domain}") };
            Ok((login, ConnectSecret::Password(password)))
        }
        ConnectSecret::PrivateKey { pem, .. } if is_security_key(&pem) => {
            Err(AuthError::Unsupported)
        }
        other => Ok((user, other)),
    }
}

/// FIDO2 `sk-*` key handles need the authenticator round trip (not in this version).
fn is_security_key(pem: &SecretString) -> bool {
    russh::keys::PrivateKey::from_openssh(pem.expose_secret().trim()).is_ok_and(|k| {
        matches!(
            k.algorithm(),
            russh::keys::Algorithm::SkEd25519 | russh::keys::Algorithm::SkEcdsaSha2NistP256
        )
    })
}

#[allow(clippy::unnecessary_wraps)] // reads as the success arm of `authenticate`
fn ok(shared: &Shared, method: AuthMethod) -> Result<AuthMethod, AuthError> {
    tracing::debug!(method = method.as_str(), "ssh authentication succeeded");
    shared.audit.push(TrustEvent::AuthSucceeded { method });
    Ok(method)
}

#[allow(clippy::needless_pass_by_value)] // used as `map_err(transport)`
fn transport(e: russh::Error) -> AuthError {
    tracing::debug!(error = %e, "ssh transport error during authentication");
    AuthError::Transport
}

/// RSA signature hash to use, never SHA-1. `None` when the server only allows `ssh-rsa`.
pub(crate) async fn rsa_hash(handle: &H) -> Option<Option<HashAlg>> {
    match handle.best_supported_rsa_hash().await {
        Ok(Some(None)) => None,
        Ok(Some(Some(h))) => Some(Some(h)),
        _ => Some(Some(HashAlg::Sha256)),
    }
}

async fn try_private_key(
    handle: &mut H,
    user: &str,
    pem: &SecretString,
    passphrase: Option<&SecretString>,
) -> Result<Option<AuthResult>, AuthError> {
    let Ok(key) =
        decode_secret_key(pem.expose_secret(), passphrase.map(ExposeSecret::expose_secret))
    else {
        tracing::debug!("vault private key could not be decoded");
        return Ok(None);
    };
    let key = Arc::new(key);
    let hash = if key.algorithm().is_rsa() {
        let Some(h) = rsa_hash(handle).await else {
            tracing::debug!("server only accepts ssh-rsa (SHA-1) signatures; key skipped");
            return Ok(None);
        };
        h
    } else {
        None
    };
    let result = handle
        .authenticate_publickey(user.to_owned(), PrivateKeyWithHashAlg::new(key, hash))
        .await
        .map_err(transport)?;
    Ok(Some(result))
}

/// ADR-0026 §1: the key with its OpenSSH user certificate (`publickey` with a
/// `*-cert-v01@openssh.com` blob). A certificate that does not parse is skipped (the plain
/// key follows); the server decides whether it trusts the CA.
async fn try_certificate(
    handle: &mut H,
    user: &str,
    pem: &SecretString,
    passphrase: Option<&SecretString>,
    cert: &str,
) -> Result<Option<AuthResult>, AuthError> {
    let Ok(cert) = russh::keys::Certificate::from_openssh(cert.trim()) else {
        tracing::debug!("ssh certificate could not be parsed; plain key next");
        return Ok(None);
    };
    let Ok(key) =
        decode_secret_key(pem.expose_secret(), passphrase.map(ExposeSecret::expose_secret))
    else {
        return Ok(None);
    };
    if cert.public_key() != key.public_key().key_data() {
        tracing::debug!("ssh certificate is for another key; skipped");
        return Ok(None);
    }
    let result = handle
        .authenticate_openssh_cert(user.to_owned(), Arc::new(key), cert)
        .await
        .map_err(transport)?;
    Ok(Some(result))
}

async fn keyboard_interactive(
    handle: &mut H,
    user: &str,
    password: Option<&SecretString>,
    shared: &Shared,
) -> Result<bool, AuthError> {
    let mut autofill = password;
    let mut reply = handle
        .authenticate_keyboard_interactive_start(user.to_owned(), None)
        .await
        .map_err(transport)?;
    for _ in 0..MAX_KBD_ROUNDS {
        let (name, instructions, prompts) = match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                (name, instructions, prompts)
            }
        };
        if prompts.len() > MAX_KBD_PROMPTS {
            tracing::debug!(count = prompts.len(), "too many keyboard-interactive prompts");
            return Ok(false);
        }
        let header = [sanitize(&name), sanitize(&instructions)]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" — ");
        let mut answers: Vec<String> = Vec::with_capacity(prompts.len());
        for prompt in &prompts {
            if let Some(pw) = autofill.filter(|_| prompt.prompt.to_lowercase().contains("password"))
            {
                autofill = None;
                answers.push(pw.expose_secret().to_owned());
                continue;
            }
            let text = sanitize(&prompt.prompt);
            let message = if header.is_empty() { text } else { format!("{header}: {text}") };
            let answer = shared
                .broker
                .ask(
                    &shared.events,
                    message,
                    !prompt.echo,
                    PromptPurpose::KeyboardInteractive,
                    shared.hop,
                )
                .await
                .ok_or(AuthError::Cancelled)?;
            answers.push(answer.expose_secret().to_owned());
        }
        // Our copies are wiped once russh has taken its own (see module docs).
        let responses = Zeroizing::new(answers);
        reply = handle
            .authenticate_keyboard_interactive_respond(responses.to_vec())
            .await
            .map_err(transport)?;
    }
    Ok(false)
}
