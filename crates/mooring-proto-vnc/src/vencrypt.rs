//! `VeNCrypt` 0.2 negotiation (rfbproto "VeNCrypt"): version, subtype list, subtype ack.
//!
//! Only the X509 subtypes are accepted (ADR-0012): `TLSNone`/`TLSVnc`/`TLSPlain` (257–259)
//! need anonymous Diffie-Hellman, which rustls does not offer, and `Plain` (256) would send
//! the password in clear.

use crate::error::VncError;
use crate::security::CredKind;
use crate::wire::{take, PResult, Parsed, Rd};

/// `X509None`.
pub const X509_NONE: u32 = 260;
/// `X509Vnc`.
pub const X509_VNC: u32 = 261;
/// `X509Plain`.
pub const X509_PLAIN: u32 = 262;
/// Most subtypes read from a list (the count is a `u8` anyway).
pub const MAX_SUBTYPES: usize = 255;

/// Our version answer.
pub const CLIENT_VERSION: [u8; 2] = [0, 2];

/// The server's `VeNCrypt` version; only 0.2 is spoken.
pub fn parse_version(buf: &[u8]) -> PResult<()> {
    let mut r = Rd::new(buf);
    let v = take!(r.bytes(2));
    if v != [0, 2] {
        return Err(VncError::Unsupported(format!("VeNCrypt {}.{} (only 0.2)", v[0], v[1])));
    }
    Ok(Parsed::Done((), 2))
}

/// The server's answer to our version (0 = accepted).
pub fn parse_version_ack(buf: &[u8]) -> PResult<()> {
    let mut r = Rd::new(buf);
    match take!(r.u8()) {
        0 => Ok(Parsed::Done((), 1)),
        _ => Err(VncError::Unsupported("server refused VeNCrypt 0.2".into())),
    }
}

/// The subtype list.
pub fn parse_subtypes(buf: &[u8]) -> PResult<Vec<u32>> {
    let mut r = Rd::new(buf);
    let n = usize::from(take!(r.u8()));
    if n == 0 {
        return Err(VncError::Unsupported("VeNCrypt offers no subtype".into()));
    }
    let mut out = Vec::with_capacity(n.min(MAX_SUBTYPES));
    for _ in 0..n {
        out.push(take!(r.u32()));
    }
    Ok(Parsed::Done(out, r.pos()))
}

/// The server's ack of our subtype (1 = accepted).
pub fn parse_subtype_ack(buf: &[u8]) -> PResult<()> {
    let mut r = Rd::new(buf);
    match take!(r.u8()) {
        1 => Ok(Parsed::Done((), 1)),
        _ => Err(VncError::Unsupported("server refused the VeNCrypt subtype".into())),
    }
}

/// Pick an X509 subtype for the credential. [`SubtypeError::NoX509`] tells the caller that a
/// plaintext fallback may be attempted (when TLS is not required).
pub fn select_subtype(offered: &[u32], cred: CredKind) -> Result<u32, SubtypeError> {
    let has = |t: u32| offered.contains(&t);
    let any_x509 = [X509_NONE, X509_VNC, X509_PLAIN].iter().any(|t| has(*t));
    if !any_x509 {
        return Err(SubtypeError::NoX509);
    }
    let pick = match cred {
        CredKind::UserPassword => has(X509_PLAIN).then_some(X509_PLAIN),
        CredKind::Password => [X509_VNC, X509_NONE].into_iter().find(|t| has(*t)),
        CredKind::None => has(X509_NONE).then_some(X509_NONE),
    };
    pick.ok_or(SubtypeError::Credential(cred))
}

/// Why no subtype fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtypeError {
    /// Only anonymous-TLS or plain subtypes: a plaintext fallback may be attempted when TLS
    /// is not required.
    NoX509,
    /// X509 is offered, but not with the authentication this credential needs.
    Credential(CredKind),
}

impl SubtypeError {
    /// Close reason.
    pub fn into_error(self) -> VncError {
        match self {
            Self::NoX509 => VncError::Unsupported(
                "VeNCrypt offers only anonymous TLS or plain subtypes (X509 required)".into(),
            ),
            Self::Credential(CredKind::None) => {
                VncError::AuthFailed("the server requires a password inside VeNCrypt".into())
            }
            Self::Credential(CredKind::Password) => {
                VncError::AuthFailed("the server does not accept a VNC password inside TLS".into())
            }
            Self::Credential(CredKind::UserPassword) => VncError::AuthFailed(
                "the server does not offer X509Plain for a username and password".into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_parsers() {
        assert_eq!(parse_version(&[0, 2]).expect("v"), Parsed::Done((), 2));
        assert_eq!(parse_version(&[0]).expect("v"), Parsed::Need(2));
        assert!(parse_version(&[0, 1]).is_err());
        assert_eq!(parse_version_ack(&[0]).expect("a"), Parsed::Done((), 1));
        assert!(parse_version_ack(&[1]).is_err());
        let list = [2, 0, 0, 1, 4, 0, 0, 1, 5];
        assert_eq!(parse_subtypes(&list).expect("s"), Parsed::Done(vec![260, 261], 9));
        assert_eq!(parse_subtypes(&list[..6]).expect("s"), Parsed::Need(9));
        assert!(parse_subtypes(&[0]).is_err());
        assert_eq!(parse_subtype_ack(&[1]).expect("k"), Parsed::Done((), 1));
        assert!(parse_subtype_ack(&[0]).is_err());
    }

    #[test]
    fn subtype_matrix() {
        let all = [256, 257, 258, 259, 260, 261, 262];
        assert_eq!(select_subtype(&all, CredKind::None), Ok(X509_NONE));
        assert_eq!(select_subtype(&all, CredKind::Password), Ok(X509_VNC));
        assert_eq!(select_subtype(&all, CredKind::UserPassword), Ok(X509_PLAIN));
        assert_eq!(select_subtype(&[260], CredKind::Password), Ok(X509_NONE));
        assert_eq!(
            select_subtype(&[256, 257, 258, 259], CredKind::Password),
            Err(SubtypeError::NoX509)
        );
        assert_eq!(
            select_subtype(&[261], CredKind::None),
            Err(SubtypeError::Credential(CredKind::None))
        );
        assert_eq!(
            select_subtype(&[260, 261], CredKind::UserPassword),
            Err(SubtypeError::Credential(CredKind::UserPassword))
        );
        assert!(matches!(SubtypeError::NoX509.into_error(), VncError::Unsupported(_)));
        assert!(matches!(
            SubtypeError::Credential(CredKind::None).into_error(),
            VncError::AuthFailed(_)
        ));
    }
}
