//! Smart-card / PIV sign-in (`smart_card`, ADR-0027 §2, owner decision 40): the ssh-agent
//! holds the card's key (`ssh-add -s <module>`), Mooring pins it by its blob, and when the
//! agent lacks it and the credential names a PKCS#11 module, the PIN is asked through the
//! prompt channel (`purpose: smart_card_pin`, secret, never stored) and handed to the agent
//! with `SSH_AGENTC_ADD_SMARTCARD_KEY`. The module path comes from a fixed per-OS list, never
//! from input. No `cryptoki`, no FFI. Never followed by a password attempt.

use std::path::{Path, PathBuf};

use mooring_core::credential::Pkcs11Module;
use mooring_core::session::{PivLogin, PromptPurpose};
use russh::client::{AuthResult, Handle};
use russh::keys::agent::AgentIdentity;
use russh::keys::signature::Verifier;
use russh::keys::{HashAlg, PublicKey};
use secrecy::ExposeSecret;

use crate::agent_wire::put_string;
use crate::audit::{AuthMethod, TrustEvent};
use crate::auth::AuthError;
use crate::handler::ClientHandler;
use crate::shared::Shared;
use crate::sk_agent::{find, Held, SkAgent};

/// Longest PIN accepted from the dialog (PIV PINs are 6–8 characters; PUK-like codes longer).
pub const MAX_PIN: usize = 64;

/// Why a smart-card sign-in failed; each reason is safe to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PivFailure {
    BadKey,
    NoAgent,
    NotInAgent,
    PinCancelled,
    CardRefused,
    BadSignature,
    Refused,
}

impl PivFailure {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::BadKey => "the smart card credential has no usable public key",
            Self::NoAgent => "no ssh-agent is reachable for the smart card; start ssh-agent",
            Self::NotInAgent => {
                "smart card key not in ssh-agent; load the card with `ssh-add -s <PKCS#11 module>`"
            }
            Self::PinCancelled => "smart card PIN cancelled",
            Self::CardRefused => {
                "the ssh-agent could not load the smart card (wrong PIN, card or module)"
            }
            Self::BadSignature => {
                "the ssh-agent returned a signature that does not match the smart card key"
            }
            Self::Refused => "authentication failed",
        }
    }

    /// Audit `outcome` of `session.auth.sk` (backend `piv`).
    pub(crate) const fn outcome(self) -> &'static str {
        match self {
            Self::BadKey => "bad_key",
            Self::NoAgent => "no_agent",
            Self::NotInAgent => "not_in_agent",
            Self::PinCancelled => "pin_cancelled",
            Self::CardRefused => "card_refused",
            Self::BadSignature => "bad_signature",
            Self::Refused => "refused",
        }
    }
}

/// Fixed locations of each PKCS#11 provider on this OS (first existing file wins).
#[must_use]
pub fn module_candidates(m: Pkcs11Module) -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    let list: &[&str] = match m {
        Pkcs11Module::Opensc => &[
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib64/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
        ],
        Pkcs11Module::Ykcs11 => &[
            "/usr/lib/x86_64-linux-gnu/libykcs11.so",
            "/usr/lib/aarch64-linux-gnu/libykcs11.so",
            "/usr/lib64/libykcs11.so",
            "/usr/lib/libykcs11.so",
        ],
        Pkcs11Module::Cryptoapi => &[],
    };
    #[cfg(target_os = "macos")]
    let list: &[&str] = match m {
        Pkcs11Module::Opensc => &[
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
        ],
        Pkcs11Module::Ykcs11 => {
            &["/opt/homebrew/lib/libykcs11.dylib", "/usr/local/lib/libykcs11.dylib"]
        }
        Pkcs11Module::Cryptoapi => &[],
    };
    #[cfg(windows)]
    let list: &[&str] = match m {
        Pkcs11Module::Opensc => {
            &[r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"]
        }
        Pkcs11Module::Ykcs11 => &[r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"],
        Pkcs11Module::Cryptoapi => &[],
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let list: &[&str] = {
        let _ = m;
        &[]
    };
    list
}

/// The provider path the agent is asked to load: the test override, else the first existing
/// fixed location. `None` when the module is not installed (or is `cryptoapi`).
#[must_use]
pub fn module_path(m: Pkcs11Module, override_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        return Some(p.to_path_buf());
    }
    module_candidates(m).iter().map(PathBuf::from).find(|p| p.is_file())
}

/// Signs through the agent with the pinned key; checks the signature before it is sent.
struct PivSigner {
    agent: SkAgent,
    blob: Vec<u8>,
    key: PublicKey,
    failure: Option<PivFailure>,
}

impl russh::Signer for PivSigner {
    type Error = crate::sk_auth::SignFailed;

    #[allow(clippy::manual_async_fn)] // the trait asks for `impl Future + Send`
    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            let flags = match hash_alg {
                Some(HashAlg::Sha256) => 2,
                Some(HashAlg::Sha512) => 4,
                _ => 0,
            };
            let Ok(sig) = self.agent.sign_flags(&self.blob, &to_sign, flags).await else {
                self.failure = Some(PivFailure::Refused);
                return Err(crate::sk_auth::SignFailed);
            };
            let ok = russh::keys::ssh_key::Signature::try_from(sig.as_slice())
                .is_ok_and(|s| Verifier::verify(&self.key, &to_sign, &s).is_ok());
            if !ok {
                self.failure = Some(PivFailure::BadSignature);
                return Err(crate::sk_auth::SignFailed);
            }
            let mut out = to_sign;
            put_string(&mut out, &sig);
            Ok(out)
        }
    }
}

fn fail(shared: &Shared, fingerprint: &str, f: PivFailure) -> AuthError {
    shared.audit.push(TrustEvent::SecurityKeyAuth {
        fingerprint: fingerprint.to_owned(),
        backend: "piv",
        outcome: f.outcome(),
    });
    shared.audit.push(TrustEvent::AuthFailed);
    AuthError::SmartCard(f)
}

/// Ask the PIN and let the agent load the card. `Ok(())` = the agent accepted it.
async fn load_card(
    agent: &mut SkAgent,
    login: &PivLogin,
    module: &Path,
    shared: &Shared,
) -> Result<(), PivFailure> {
    let reader = login.reader_hint.as_deref().map_or_else(String::new, |r| format!(" ({r})"));
    let message = format!("Enter the PIN of the smart card{reader} for key {}", login.fingerprint);
    let pin = shared
        .broker
        .ask(&shared.events, message, true, PromptPurpose::SmartCardPin, shared.hop)
        .await;
    let entered = pin.as_ref().is_some_and(|p| {
        let p = p.expose_secret();
        !p.is_empty() && p.len() <= MAX_PIN && !p.chars().any(char::is_control)
    });
    shared.audit.push(TrustEvent::PinPrompted {
        fingerprint: login.fingerprint.clone(),
        outcome: if entered { "entered" } else { "cancelled" },
    });
    let Some(pin) = pin.filter(|_| entered) else {
        return Err(PivFailure::PinCancelled);
    };
    let provider = module.to_string_lossy();
    match agent.add_smartcard(&provider, pin.expose_secret().as_bytes()).await {
        Ok(true) => Ok(()),
        _ => Err(PivFailure::CardRefused),
    }
}

/// The whole `smart_card` round: find (or load) the key in the agent, sign, never fall back.
pub(crate) async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    login: &PivLogin,
    shared: &Shared,
    agent_path: Option<&Path>,
    module_override: Option<&Path>,
) -> Result<AuthMethod, AuthError> {
    let fp = login.fingerprint.as_str();
    let Ok(key) = PublicKey::from_openssh(login.public_key.trim()) else {
        return Err(fail(shared, fp, PivFailure::BadKey));
    };
    let Ok(blob) = key.to_bytes() else { return Err(fail(shared, fp, PivFailure::BadKey)) };
    let Some(mut agent) = SkAgent::connect(agent_path).await else {
        return Err(fail(shared, fp, PivFailure::NoAgent));
    };
    let Ok(ids) = agent.identities().await else {
        return Err(fail(shared, fp, PivFailure::NoAgent));
    };
    if find(&ids, &blob) == Held::Missing {
        let module = login.module.and_then(|m| module_path(m, module_override));
        let Some(module) = module else { return Err(fail(shared, fp, PivFailure::NotInAgent)) };
        if let Err(f) = load_card(&mut agent, login, &module, shared).await {
            return Err(fail(shared, fp, f));
        }
        let held = agent.identities().await.map(|ids| find(&ids, &blob) != Held::Missing);
        if held != Ok(true) {
            return Err(fail(shared, fp, PivFailure::NotInAgent));
        }
    }
    let hash =
        if key.algorithm().is_rsa() { crate::auth::rsa_hash(handle).await.flatten() } else { None };
    let mut signer = PivSigner { agent, blob, key: key.clone(), failure: None };
    match handle.authenticate_publickey_with(user.to_owned(), key, hash, &mut signer).await {
        Ok(AuthResult::Success) => {
            shared.audit.push(TrustEvent::SecurityKeyAuth {
                fingerprint: fp.to_owned(),
                backend: "piv",
                outcome: "ok",
            });
            shared.audit.push(TrustEvent::AuthSucceeded { method: AuthMethod::Agent });
            Ok(AuthMethod::Agent)
        }
        Ok(AuthResult::Failure { .. }) => Err(fail(shared, fp, PivFailure::Refused)),
        Err(_) if handle.is_closed() => Err(AuthError::Transport),
        Err(_) => Err(fail(shared, fp, signer.failure.unwrap_or(PivFailure::Refused))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_paths_come_from_the_fixed_list_or_the_override() {
        assert!(module_candidates(Pkcs11Module::Cryptoapi).is_empty());
        assert!(module_path(Pkcs11Module::Cryptoapi, None).is_none());
        for m in [Pkcs11Module::Opensc, Pkcs11Module::Ykcs11] {
            for p in module_candidates(m) {
                assert!(Path::new(p).is_absolute(), "{p}");
            }
        }
        let o = Path::new("override-module");
        assert_eq!(module_path(Pkcs11Module::Opensc, Some(o)).as_deref(), Some(o));
    }

    #[test]
    fn reasons_and_outcomes_are_distinct() {
        use PivFailure as F;
        let all = [
            F::BadKey,
            F::NoAgent,
            F::NotInAgent,
            F::PinCancelled,
            F::CardRefused,
            F::BadSignature,
            F::Refused,
        ];
        let outcomes: std::collections::HashSet<_> = all.iter().map(|f| f.outcome()).collect();
        assert_eq!(outcomes.len(), all.len());
        assert!(F::NotInAgent.reason().contains("ssh-add -s"));
    }
}
