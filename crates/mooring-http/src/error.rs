//! [`HttpError`]. No variant carries a header, a body byte or a secret; server-controlled
//! text appears only inside the sanitised [`CertificateInfo`](mooring_core::known_certs::CertificateInfo).

use http::StatusCode;

use crate::verify::TrustDecision;

/// Errors of the client.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The configuration was refused.
    #[error("invalid HTTP client configuration: {0}")]
    InvalidConfig(&'static str),
    /// A request argument was refused before anything was sent.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// `http://` without `allow_plaintext` + loopback, or to a host that has a pin / a
    /// "TLS seen" marker (downgrade guard).
    #[error("plaintext HTTP is not allowed for this endpoint")]
    PlaintextRefused,
    /// The `known_*_certs` file could not be read (fail closed).
    #[error("the certificate trust store could not be read")]
    TrustStore,
    /// Unknown certificate with an invalid chain: prompt, then retry with `trusted_once` or
    /// after the Gate wrote the pin. Never retried here.
    #[error("the server certificate is not trusted yet")]
    TrustPrompt(Box<TrustDecision>),
    /// The certificate differs from the pin: hard stop.
    #[error("the server certificate changed")]
    TrustMismatch(Box<TrustDecision>),
    /// Anchored mode and the chain failed against the explicit CA: not promptable.
    #[error("the server certificate does not validate against the configured CA")]
    TrustRejected(Box<TrustDecision>),
    /// The trust store holds conflicting pins for the host (review 6b L-35): hard stop until
    /// the user removes them in the known-certificates manager.
    #[error("the trust store holds conflicting pins for this host")]
    TrustConflict(Box<TrustDecision>),
    /// Any other TLS failure (protocol, bad handshake signature, …).
    #[error("TLS failed: {0}")]
    Tls(String),
    /// TCP connect / DNS failure.
    #[error("connection failed: {0}")]
    Connect(std::io::ErrorKind),
    /// A deadline passed.
    #[error("the request timed out")]
    Timeout,
    /// The HTTP exchange failed after connecting.
    #[error("HTTP protocol error")]
    Protocol,
    /// A non-success status (body discarded).
    #[error("HTTP status {}", .status.as_u16())]
    Status {
        /// The status.
        status: StatusCode,
    },
    /// A `3xx` that the redirect policy refused.
    #[error("redirect refused (HTTP {})", .status.as_u16())]
    Redirect {
        /// The status.
        status: StatusCode,
    },
    /// The body exceeds the cap (declared `Content-Length` or bytes read).
    #[error("response body exceeds {cap} bytes")]
    BodyTooLarge {
        /// The cap that was hit.
        cap: usize,
    },
    /// The body is not the expected JSON (position only, no content).
    #[error("response JSON invalid at line {line}, column {column}")]
    Decode {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// The WebSocket handshake or framing failed.
    #[error("websocket: {0}")]
    WebSocket(&'static str),
}

/// Coarse class of a status, for consumers' error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// 401.
    Unauthorized,
    /// 403.
    Forbidden,
    /// 404.
    NotFound,
    /// 409.
    Conflict,
    /// 412 (S3 conditional write lost the race).
    PreconditionFailed,
    /// 429.
    TooManyRequests,
    /// 5xx.
    Server,
    /// Any other non-success status.
    Other,
}

impl StatusClass {
    /// Classify `status`.
    pub fn of(status: StatusCode) -> Self {
        match status.as_u16() {
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            412 => Self::PreconditionFailed,
            429 => Self::TooManyRequests,
            500..=599 => Self::Server,
            _ => Self::Other,
        }
    }
}

impl HttpError {
    /// Stable machine code (`http.*`) for IPC mapping by the consumers.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) | Self::InvalidRequest(_) => "http.invalid",
            Self::PlaintextRefused => "http.plaintext_refused",
            Self::TrustStore => "http.trust_store",
            Self::TrustPrompt(_) => "http.trust_prompt",
            Self::TrustMismatch(_) => "http.trust_mismatch",
            Self::TrustRejected(_) => "http.trust_rejected",
            Self::TrustConflict(_) => "http.trust_conflict",
            Self::Tls(_) => "http.tls",
            Self::Connect(_) => "http.connect",
            Self::Timeout => "http.timeout",
            Self::Protocol => "http.protocol",
            Self::Status { .. } => "http.status",
            Self::Redirect { .. } => "http.redirect",
            Self::BodyTooLarge { .. } => "http.body_too_large",
            Self::Decode { .. } => "http.decode",
            Self::WebSocket(_) => "http.websocket",
        }
    }

    /// The status class of a [`HttpError::Status`].
    pub fn status_class(&self) -> Option<StatusClass> {
        match self {
            Self::Status { status } => Some(StatusClass::of(*status)),
            _ => None,
        }
    }

    /// The handshake decision of a `Trust*` error.
    pub fn trust_decision(&self) -> Option<&TrustDecision> {
        match self {
            Self::TrustPrompt(d)
            | Self::TrustMismatch(d)
            | Self::TrustRejected(d)
            | Self::TrustConflict(d) => Some(d),
            _ => None,
        }
    }
}

/// Connector failure, carried through hyper-util's error chain and unpacked by the client.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct ConnectFailure(pub(crate) HttpError);
