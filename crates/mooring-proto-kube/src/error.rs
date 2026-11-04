//! [`KubeError`]: static, value-free errors with stable IPC codes (ADR-0014 §6). API error
//! bodies are never read into an error (they may echo object content); only the status is.

use mooring_core::session::CloseCode;
use mooring_core::MooringError;
use mooring_http::{HttpError, StatusClass};
use tower::BoxError;

use crate::guard::Refused;

/// Errors of the Kubernetes client.
#[derive(Debug, thiserror::Error)]
pub enum KubeError {
    /// The read-only guard refused the request (`kube.refused`; ADR-0014 §6 calls it
    /// `kube.forbidden_request`, the UI (U1) and the coordinator use `kube.refused`).
    #[error(transparent)]
    Forbidden(#[from] Refused),
    /// The API server denied it (`403`, `kube.rbac_denied`).
    #[error("the Kubernetes API denied this request (RBAC)")]
    RbacDenied,
    /// `404` (`kube.not_found`).
    #[error("the Kubernetes object was not found")]
    NotFound,
    /// `401`: token invalid or expired, certificate refused (`kube.auth_failed`).
    #[error("the Kubernetes API rejected the credentials")]
    Unauthorized,
    /// The credential shape cannot be used (`kube.unsupported_auth`).
    #[error("unsupported Kubernetes authentication: {0}")]
    UnsupportedAuth(&'static str),
    /// An argument was refused before anything was sent (`kube.invalid`).
    #[error("invalid Kubernetes request: {0}")]
    Invalid(&'static str),
    /// Any other non-success status (`kube.status`).
    #[error("Kubernetes API returned HTTP {0}")]
    Status(u16),
    /// The response broke the expected shape (`kube.protocol`).
    #[error("Kubernetes protocol error: {0}")]
    Protocol(&'static str),
    /// Transport / TLS / trust / caps (`http.*`).
    #[error(transparent)]
    Http(#[from] HttpError),
    /// All 8 log streams of this cluster are open (`kube.stream_limit`).
    #[error("too many log streams are open for this cluster")]
    StreamLimit,
    /// The client or stream is gone.
    #[error("the Kubernetes connection is closed")]
    Closed,
}

impl KubeError {
    /// Stable IPC code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Forbidden(_) => "kube.refused",
            Self::StreamLimit => "kube.stream_limit",
            Self::RbacDenied => "kube.rbac_denied",
            Self::NotFound => "kube.not_found",
            Self::Unauthorized => "kube.auth_failed",
            Self::UnsupportedAuth(_) => "kube.unsupported_auth",
            Self::Invalid(_) => "kube.invalid",
            Self::Status(_) => "kube.status",
            Self::Protocol(_) => "kube.protocol",
            Self::Http(e) => e.code(),
            Self::Closed => "kube.closed",
        }
    }

    /// From a response status (non-success).
    pub(crate) fn from_status(status: http::StatusCode) -> Self {
        match StatusClass::of(status) {
            StatusClass::Unauthorized => Self::Unauthorized,
            StatusClass::Forbidden => Self::RbacDenied,
            StatusClass::NotFound => Self::NotFound,
            _ => Self::Status(status.as_u16()),
        }
    }

    /// From the boxed error chain of the tower stack (guard → bearer → `mooring-http`).
    pub(crate) fn from_box(e: BoxError) -> Self {
        let e = match e.downcast::<Refused>() {
            Ok(r) => return Self::Forbidden(*r),
            Err(e) => e,
        };
        let e = match e.downcast::<HttpError>() {
            Ok(h) => return Self::from_http(*h),
            Err(e) => e,
        };
        match e.downcast::<kube::Error>() {
            Ok(k) => Self::from_kube(*k),
            Err(_) => Self::Protocol("transport failed"),
        }
    }

    fn from_http(e: HttpError) -> Self {
        match e {
            HttpError::Status { status } => Self::from_status(status),
            other => Self::Http(other),
        }
    }

    /// From `kube::Client::send`.
    pub(crate) fn from_kube(e: kube::Error) -> Self {
        match e {
            kube::Error::Service(b) => Self::from_box(b),
            kube::Error::Api(s) => {
                http::StatusCode::from_u16(s.code).map_or(Self::Status(s.code), Self::from_status)
            }
            kube::Error::HyperError(_) => Self::Protocol("HTTP exchange failed"),
            _ => Self::Protocol("Kubernetes client error"),
        }
    }

    /// The session close code this error ends an exec / forward with.
    pub fn close_code(&self) -> CloseCode {
        match self {
            Self::Unauthorized => CloseCode::AuthFailed,
            Self::Http(HttpError::TrustPrompt(_) | HttpError::TrustRejected(_)) => {
                CloseCode::TrustRejected
            }
            Self::Http(HttpError::TrustMismatch(_)) => CloseCode::TrustMismatch,
            Self::Http(_) | Self::Closed => CloseCode::Network,
            Self::Protocol(_) => CloseCode::ProtocolError,
            _ => CloseCode::ServerEnded,
        }
    }
}

impl From<KubeError> for MooringError {
    fn from(e: KubeError) -> Self {
        match e {
            KubeError::Invalid(r) => Self::Invalid { field: "kube", reason: r.to_owned() },
            KubeError::Http(h) => Self::Transport(h.to_string()),
            other => Self::Protocol { protocol: "kubernetes", reason: other.to_string() },
        }
    }
}
