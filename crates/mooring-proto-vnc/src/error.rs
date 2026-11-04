//! Errors of the RFB client and how they map onto `CloseCode`.
//!
//! Every reason is safe to show: it never contains secret material, and server-supplied text
//! (failure reasons) is sanitised and capped before it is put into one.

use mooring_core::known_certs::CertificateInfo;
use mooring_core::session::CloseCode;

/// Longest server-supplied text kept in a reason, in characters.
pub const MAX_REASON_CHARS: usize = 256;

/// Why the RFB client stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VncError {
    /// TCP / TLS I/O failed or the peer went away mid-message.
    Network(String),
    /// The peer violated RFB, or a parser / decoder refused its data (caps, bounds).
    Protocol(String),
    /// The server offers nothing our policy accepts (`session.unsupported_security`).
    Unsupported(String),
    /// Authentication was refused or impossible with the credential at hand.
    AuthFailed(String),
    /// A pinned certificate changed, or TLS was stripped after a pin: hard stop.
    TrustMismatch(String),
    /// The user declined the certificate.
    TrustRejected,
    /// Unknown certificate whose chain does not validate: prompt, then reconnect on `yes`.
    /// Internal to the connect loop; never reaches `Closed` as such.
    TrustUnknown {
        /// SHA-256 of the leaf.
        fp: [u8; 32],
        /// What the prompt shows.
        info: Box<CertificateInfo>,
    },
    /// The server ended the session.
    ServerEnded(String),
    /// Closed by the user.
    User,
}

impl VncError {
    pub(crate) fn protocol(reason: impl Into<String>) -> Self {
        Self::Protocol(reason.into())
    }

    /// The `CloseCode` the UI and the reconnect policy see.
    pub fn code(&self) -> CloseCode {
        match self {
            Self::Network(_) => CloseCode::Network,
            Self::Protocol(_) | Self::Unsupported(_) => CloseCode::ProtocolError,
            Self::AuthFailed(_) => CloseCode::AuthFailed,
            Self::TrustMismatch(_) => CloseCode::TrustMismatch,
            Self::TrustRejected | Self::TrustUnknown { .. } => CloseCode::TrustRejected,
            Self::ServerEnded(_) => CloseCode::ServerEnded,
            Self::User => CloseCode::User,
        }
    }

    /// Text for `Closed.reason`.
    pub fn reason(&self) -> String {
        match self {
            Self::Network(r) => format!("connection lost: {r}"),
            Self::Protocol(r) => format!("protocol error: {r}"),
            Self::Unsupported(r) => format!("unsupported security: {r}"),
            Self::AuthFailed(r) => format!("authentication failed: {r}"),
            Self::TrustMismatch(r) | Self::ServerEnded(r) => r.clone(),
            Self::TrustRejected | Self::TrustUnknown { .. } => "certificate not trusted".to_owned(),
            Self::User => "closed by user".to_owned(),
        }
    }
}

impl std::fmt::Display for VncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

impl std::error::Error for VncError {}

impl From<std::io::Error> for VncError {
    fn from(e: std::io::Error) -> Self {
        Self::Network(format!("{}", e.kind()))
    }
}

/// Strip control, bidi and invisible characters and cap the length of server text.
pub fn sanitize_server_text(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control() && !mooring_core::is_bidi_or_invisible(*c))
        .take(MAX_REASON_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_retry() {
        assert_eq!(VncError::Network("x".into()).code(), CloseCode::Network);
        assert!(VncError::Network("x".into()).code().is_retryable());
        assert!(VncError::ServerEnded("x".into()).code().is_retryable());
        for e in [
            VncError::protocol("x"),
            VncError::Unsupported("x".into()),
            VncError::AuthFailed("x".into()),
            VncError::TrustMismatch("x".into()),
            VncError::TrustRejected,
            VncError::User,
        ] {
            assert!(!e.code().is_retryable(), "{e:?}");
        }
    }

    #[test]
    fn server_text_is_sanitised() {
        let s = sanitize_server_text(b"bad\x1b[31m\xe2\x80\xaepass\x00word");
        assert_eq!(s, "bad[31mpassword");
        assert_eq!(sanitize_server_text(&[b'a'; 5000]).len(), MAX_REASON_CHARS);
    }
}
