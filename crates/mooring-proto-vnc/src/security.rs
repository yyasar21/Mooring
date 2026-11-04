//! Security type selection (ADR-0012 §Handshake) and VNC Authentication (RFC 6143 §7.2.2).
//!
//! Selection is a pure function of the offered list, the credential at hand, the policy and
//! whether a certificate pin exists (downgrade guard), so the whole matrix is unit-tested.

use des::cipher::{BlockCipherEncrypt, KeyInit};
use des::Des;
use mooring_core::options::VncSecurity;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::VncError;

/// RFB security type None.
pub const SEC_NONE: u8 = 1;
/// RFB security type VNC Authentication.
pub const SEC_VNC_AUTH: u8 = 2;
/// RFB security type `VeNCrypt`.
pub const SEC_VENCRYPT: u8 = 19;
/// Longest VNC password: DES uses 8 bytes (ADR-0009 §5 caps the secret there).
pub const MAX_VNC_PASSWORD: usize = 8;
/// Longest `X509Plain` username / password, in bytes.
pub const MAX_PLAIN_FIELD: usize = 1024;

/// The credential the handshake may use. Secrets are never printed.
pub enum Credential {
    /// No credential: None / `X509None` only.
    None,
    /// `vnc_password`: type 2 or `X509Vnc`.
    Password(SecretString),
    /// `vnc_user_password`: `X509Plain` only (the password never travels outside TLS).
    UserPassword {
        /// Username.
        user: String,
        /// Password.
        password: SecretString,
    },
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "Credential::None",
            Self::Password(_) => "Credential::Password(<redacted>)",
            Self::UserPassword { .. } => "Credential::UserPassword(<redacted>)",
        })
    }
}

impl Credential {
    /// Short kind for selection.
    pub const fn kind(&self) -> CredKind {
        match self {
            Self::None => CredKind::None,
            Self::Password(_) => CredKind::Password,
            Self::UserPassword { .. } => CredKind::UserPassword,
        }
    }
}

/// Credential shape, without the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredKind {
    /// No secret.
    None,
    /// Password only.
    Password,
    /// Username and password.
    UserPassword,
}

/// What the client answers to the security type list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecChoice {
    /// `VeNCrypt` (19); the subtype is chosen in the `VeNCrypt` step.
    VeNCrypt,
    /// VNC Authentication (2), plaintext.
    VncAuth,
    /// None (1), plaintext.
    None,
}

impl SecChoice {
    /// The wire byte.
    pub const fn byte(self) -> u8 {
        match self {
            Self::VeNCrypt => SEC_VENCRYPT,
            Self::VncAuth => SEC_VNC_AUTH,
            Self::None => SEC_NONE,
        }
    }
}

/// Inputs to the selection besides the offered list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecPolicy {
    /// `options.security`.
    pub security: VncSecurity,
    /// `known_vnc_certs` holds a pin or a "TLS seen" marker for this `host:port` (behaves as
    /// `require_tls`, and a missing `VeNCrypt` is a `trust_mismatch`).
    pub pinned: bool,
    /// `options.allowNoAuth`: a password credential may still take a None-only offer.
    pub allow_no_auth: bool,
    /// A previous attempt found no usable `VeNCrypt` subtype (anonymous TLS only); offered
    /// `VeNCrypt` is skipped on the fallback attempt. Never set when TLS is required.
    pub skip_vencrypt: bool,
}

impl SecPolicy {
    /// TLS is mandatory: `require_tls`, or a pin exists (HSTS-like downgrade guard).
    pub const fn tls_required(&self) -> bool {
        self.pinned || matches!(self.security, VncSecurity::RequireTls)
    }
}

/// Pick the security type (ADR-0012 preference order: `VeNCrypt`, VNC auth, None).
///
/// Errors: `TrustMismatch` when a pin exists and `VeNCrypt` is not offered (stripped by a
/// MITM, the caller audits `trust.cert.mismatch` with `presented = none`); `Unsupported`
/// when nothing acceptable is offered; `AuthFailed` when the server needs a password and
/// there is none.
pub fn select_security(
    offered: &[u8],
    cred: CredKind,
    policy: SecPolicy,
) -> Result<SecChoice, VncError> {
    let has = |t: u8| offered.contains(&t);
    if has(SEC_VENCRYPT) && (!policy.skip_vencrypt || policy.tls_required()) {
        return Ok(SecChoice::VeNCrypt);
    }
    if policy.pinned {
        return Err(VncError::TrustMismatch(
            "TLS EXPECTED: the server no longer offers VeNCrypt".into(),
        ));
    }
    if policy.tls_required() {
        return Err(VncError::Unsupported("the server offers no VeNCrypt (require_tls)".into()));
    }
    match cred {
        CredKind::UserPassword => Err(VncError::Unsupported(
            "a username and password need VeNCrypt X509Plain, which the server does not offer"
                .into(),
        )),
        CredKind::Password if has(SEC_VNC_AUTH) => Ok(SecChoice::VncAuth),
        CredKind::None if has(SEC_NONE) => Ok(SecChoice::None),
        // L-27: a MITM offering only None would get a silent session to its own desktop.
        CredKind::Password if has(SEC_NONE) && policy.allow_no_auth => Ok(SecChoice::None),
        CredKind::Password if has(SEC_NONE) => Err(VncError::Unsupported(
            "the server offers no authentication although a password is configured".into(),
        )),
        CredKind::None if has(SEC_VNC_AUTH) => {
            Err(VncError::AuthFailed("the server requires a VNC password".into()))
        }
        _ => Err(VncError::Unsupported("no supported security type offered".into())),
    }
}

fn reverse_bits(b: u8) -> u8 {
    b.reverse_bits()
}

/// The DES key RFB derives from a password: the first 8 bytes, zero-padded, each byte
/// bit-reversed (the historic VNC quirk).
pub fn vnc_des_key(password: &[u8]) -> Zeroizing<[u8; 8]> {
    let mut key = Zeroizing::new([0u8; 8]);
    for (k, p) in key.iter_mut().zip(password.iter()) {
        *k = reverse_bits(*p);
    }
    key
}

/// Encrypt the 16-byte challenge as two DES-ECB blocks with the RFB key. The key schedule
/// (`des/zeroize`) and the response are wiped on drop (N-29).
pub fn vnc_auth_response(password: &[u8], challenge: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    let key = vnc_des_key(password);
    let cipher = Des::new(&(*key).into());
    let mut out = Zeroizing::new(*challenge);
    for chunk in out.as_chunks_mut::<8>().0.iter_mut() {
        let mut block = des::cipher::Block::<Des>::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    out
}

/// The password bytes for VNC auth: at most 8 bytes are significant. Longer secrets are
/// refused rather than silently truncated (ADR-0009 §5 caps them at 8 bytes already).
pub fn vnc_password_bytes(secret: &SecretString) -> Result<Zeroizing<Vec<u8>>, VncError> {
    let bytes = secret.expose_secret().as_bytes();
    if bytes.len() > MAX_VNC_PASSWORD {
        return Err(VncError::AuthFailed("VNC passwords are at most 8 bytes".into()));
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// `X509Plain` credentials message: `u32 ulen, u32 plen, user, password`.
pub fn plain_auth_message(
    user: &str,
    password: &SecretString,
) -> Result<Zeroizing<Vec<u8>>, VncError> {
    let p = password.expose_secret().as_bytes();
    if user.len() > MAX_PLAIN_FIELD || p.len() > MAX_PLAIN_FIELD {
        return Err(VncError::AuthFailed("username or password too long".into()));
    }
    let mut m = Zeroizing::new(Vec::with_capacity(8 + user.len() + p.len()));
    // Both lengths are ≤ 1024, so the conversions cannot fail.
    m.extend_from_slice(&u32::try_from(user.len()).unwrap_or(0).to_be_bytes());
    m.extend_from_slice(&u32::try_from(p.len()).unwrap_or(0).to_be_bytes());
    m.extend_from_slice(user.as_bytes());
    m.extend_from_slice(p);
    Ok(m)
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
