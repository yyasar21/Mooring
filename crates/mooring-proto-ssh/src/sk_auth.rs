//! FIDO2 `ssh_sk_key` sign-in (ADR-0024 §2, §3): pin the key by its blob, wrap every signature
//! in the touch banner (`TouchRequired` → `TouchCleared` / `TouchTimeout`), check what the
//! signer returned (algorithm, user-presence flag, signature over the request) before it is
//! sent, and never fall back to a password (decision 30).

use std::path::PathBuf;
use std::time::Duration;

use mooring_core::credential::sk_key::{
    parse_sk_certificate_line, parse_sk_public_line, SkAlgorithm,
};
use mooring_core::credential::SkBackend;
use mooring_core::session::{SessionEvent, SkLogin};
use russh::client::{AuthResult, Handle};
use russh::keys::agent::AgentIdentity;
use russh::keys::signature::Verifier;
use russh::keys::{Certificate, HashAlg, PublicKey};

use crate::agent_wire::{check_sk_signature, put_string, WireError};
use crate::audit::{AuthMethod, TrustEvent};
use crate::auth::AuthError;
use crate::handler::ClientHandler;
use crate::shared::Shared;
use crate::sk_agent::{find, Held, SkAgent};

/// ADR-0024: how long the authenticator is waited for.
pub const SK_TOUCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-connection FIDO2 settings (from `SshOptions`).
#[derive(Debug, Clone)]
pub(crate) struct SkOptions {
    pub(crate) agent_path: Option<PathBuf>,
    pub(crate) touch_timeout: Duration,
    pub(crate) helper: Option<PathBuf>,
    /// ADR-0027: PKCS#11 provider override (tests); `None` = the fixed per-OS list.
    pub(crate) pkcs11_module: Option<PathBuf>,
}

/// Why a security-key sign-in failed; each reason is safe to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkFailure {
    BadKey,
    NoAgent,
    NotInAgent,
    TouchTimeout,
    NoPresence,
    BadSignature,
    Refused,
    HelperDisabled,
    HelperMissing,
    HelperVersion,
    HelperFailed,
}

impl SkFailure {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::BadKey => "the security key credential is malformed",
            Self::NoAgent => "no ssh-agent is reachable for the security key; start ssh-agent and add the key with ssh-add",
            Self::NotInAgent => "security key not in ssh-agent; run `ssh-add -K` for a resident key or `ssh-add ~/.ssh/id_ed25519_sk`",
            Self::TouchTimeout => "the security key was not touched in time",
            Self::NoPresence => "the security key did not confirm user presence (no touch)",
            Self::BadSignature => "the signer returned a signature that does not match the security key",
            Self::Refused => "authentication failed",
            Self::HelperDisabled => "ssh-sk-helper is turned off (setting sshSkHelper)",
            Self::HelperMissing => "ssh-sk-helper was not found at its fixed path",
            Self::HelperVersion => "this ssh-sk-helper speaks an unsupported protocol version",
            Self::HelperFailed => "ssh-sk-helper could not sign with the security key",
        }
    }

    /// Audit `outcome`.
    pub(crate) const fn outcome(self) -> &'static str {
        match self {
            Self::BadKey => "bad_key",
            Self::NoAgent => "no_agent",
            Self::NotInAgent => "not_in_agent",
            Self::TouchTimeout => "touch_timeout",
            Self::NoPresence => "no_presence",
            Self::BadSignature => "bad_signature",
            Self::Refused => "refused",
            Self::HelperDisabled => "helper_disabled",
            Self::HelperMissing => "helper_missing",
            Self::HelperVersion => "helper_version",
            Self::HelperFailed => "helper_failed",
        }
    }
}

/// The signer's error (russh needs `From<SendError>`); the reason is kept on the signer.
#[derive(Debug)]
pub(crate) struct SignFailed;

impl From<russh::SendError> for SignFailed {
    fn from(_: russh::SendError) -> Self {
        Self
    }
}

/// Who produces the raw `sk-*` signature blob.
pub(crate) enum Backend<'a> {
    Agent { agent: SkAgent, blob: Vec<u8> },
    Helper(crate::sk_helper::HelperSigner<'a>),
}

/// russh `Signer` that raises the touch banner around each signature and checks the result.
pub(crate) struct SkSigner<'a> {
    pub(crate) backend: Backend<'a>,
    pub(crate) algorithm: SkAlgorithm,
    pub(crate) key: PublicKey,
    pub(crate) shared: &'a Shared,
    pub(crate) fingerprint: String,
    pub(crate) timeout: Duration,
    pub(crate) failure: Option<SkFailure>,
}

impl SkSigner<'_> {
    async fn emit(&self, event: SessionEvent) {
        let _ = self.shared.events.send(event).await;
    }

    async fn raw_sign(&mut self, data: &[u8]) -> Result<Vec<u8>, SkFailure> {
        match &mut self.backend {
            Backend::Agent { agent, blob } => {
                agent.sign(blob, data).await.map_err(|_| SkFailure::Refused)
            }
            Backend::Helper(h) => h.sign(data).await,
        }
    }

    async fn sign(&mut self, to_sign: Vec<u8>) -> Result<Vec<u8>, SkFailure> {
        let id = self.shared.broker.next_id();
        let hop = self.shared.hop;
        let secs = u32::try_from(self.timeout.as_secs()).unwrap_or(u32::MAX);
        self.emit(SessionEvent::TouchRequired {
            id,
            fingerprint: self.fingerprint.clone(),
            timeout_seconds: secs,
            hop,
        })
        .await;
        let timeout = self.timeout;
        let Ok(result) = tokio::time::timeout(timeout, self.raw_sign(&to_sign)).await else {
            self.emit(SessionEvent::TouchTimeout { id, hop }).await;
            return Err(SkFailure::TouchTimeout);
        };
        self.emit(SessionEvent::TouchCleared { id, hop }).await;
        let sig = result?;
        check_sk_signature(&sig, self.algorithm).map_err(|e| match e {
            WireError::NoPresence => SkFailure::NoPresence,
            _ => SkFailure::BadSignature,
        })?;
        let parsed = russh::keys::ssh_key::Signature::try_from(sig.as_slice())
            .map_err(|_| SkFailure::BadSignature)?;
        Verifier::verify(&self.key, &to_sign, &parsed).map_err(|_| SkFailure::BadSignature)?;
        let mut out = to_sign;
        put_string(&mut out, &sig);
        Ok(out)
    }
}

impl russh::Signer for SkSigner<'_> {
    type Error = SignFailed;

    #[allow(clippy::manual_async_fn)] // the trait asks for `impl Future + Send`
    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SignFailed>> + Send {
        async move {
            match self.sign(to_sign).await {
                Ok(v) => Ok(v),
                Err(f) => {
                    self.failure = Some(f);
                    Err(SignFailed)
                }
            }
        }
    }
}

type H = Handle<ClientHandler>;

fn fail(shared: &Shared, fingerprint: &str, backend: SkBackend, f: SkFailure) -> AuthError {
    shared.audit.push(TrustEvent::SecurityKeyAuth {
        fingerprint: fingerprint.to_owned(),
        backend: backend.name(),
        outcome: f.outcome(),
    });
    shared.audit.push(TrustEvent::AuthFailed);
    AuthError::SecurityKey(f)
}

/// The whole `ssh_sk_key` round: certificate first (stored or held by the agent), then the
/// plain key. Every failure ends the round; nothing else is tried.
pub(crate) async fn authenticate(
    handle: &mut H,
    user: &str,
    login: &SkLogin,
    shared: &Shared,
    options: &SkOptions,
) -> Result<AuthMethod, AuthError> {
    let backend = login.backend;
    let Ok(key) = parse_sk_public_line(&login.public_key) else {
        return Err(fail(shared, &login.fingerprint, backend, SkFailure::BadKey));
    };
    let fp = key.fingerprint.clone();
    let Ok(public) = PublicKey::from_bytes(&key.blob) else {
        return Err(fail(shared, &fp, backend, SkFailure::BadKey));
    };
    let stored_cert = login
        .certificate
        .as_deref()
        .filter(|c| parse_sk_certificate_line(c).is_ok_and(|k| k.blob == key.blob))
        .and_then(|c| Certificate::from_openssh(c.trim()).ok());
    let (backend_impl, cert, plain) = match backend {
        SkBackend::Agent => {
            let Some(mut agent) = SkAgent::connect(options.agent_path.as_deref()).await else {
                return Err(fail(shared, &fp, backend, SkFailure::NoAgent));
            };
            let Ok(ids) = agent.identities().await else {
                return Err(fail(shared, &fp, backend, SkFailure::NoAgent));
            };
            match find(&ids, &key.blob) {
                Held::Missing => return Err(fail(shared, &fp, backend, SkFailure::NotInAgent)),
                Held::Key { certificate } => {
                    let cert = stored_cert
                        .or_else(|| certificate.and_then(|c| Certificate::from_bytes(&c).ok()));
                    (Backend::Agent { agent, blob: key.blob.clone() }, cert, true)
                }
                Held::CertificateOnly(c) => {
                    let cert = Certificate::from_bytes(&c).ok();
                    (Backend::Agent { agent, blob: c }, cert, false)
                }
            }
        }
        SkBackend::Helper => match crate::sk_helper::HelperSigner::new(login, &key, options) {
            Ok(h) => (Backend::Helper(h), stored_cert, true),
            Err(f) => return Err(fail(shared, &fp, backend, f)),
        },
    };
    let mut signer = SkSigner {
        backend: backend_impl,
        algorithm: key.algorithm,
        key: public.clone(),
        shared,
        fingerprint: fp.clone(),
        timeout: options.touch_timeout,
        failure: None,
    };
    let mut attempts: Vec<Option<Certificate>> = Vec::new();
    if cert.is_some() {
        attempts.push(cert);
    }
    if plain {
        attempts.push(None);
    }
    for attempt in attempts {
        let result = match attempt {
            Some(c) => {
                handle.authenticate_certificate_with(user.to_owned(), c, None, &mut signer).await
            }
            None => {
                handle
                    .authenticate_publickey_with(user.to_owned(), public.clone(), None, &mut signer)
                    .await
            }
        };
        match result {
            Ok(AuthResult::Success) => {
                shared.audit.push(TrustEvent::SecurityKeyAuth {
                    fingerprint: fp,
                    backend: backend.name(),
                    outcome: "ok",
                });
                shared.audit.push(TrustEvent::AuthSucceeded { method: AuthMethod::SecurityKey });
                return Ok(AuthMethod::SecurityKey);
            }
            Ok(AuthResult::Failure { remaining_methods, .. }) => {
                if !remaining_methods.contains(&russh::MethodKind::PublicKey) {
                    break;
                }
            }
            Err(SignFailed) => {
                let f = signer.failure.unwrap_or(SkFailure::Refused);
                if handle.is_closed() {
                    return Err(AuthError::Transport);
                }
                return Err(fail(shared, &fp, backend, f));
            }
        }
    }
    Err(fail(shared, &fp, backend, SkFailure::Refused))
}
