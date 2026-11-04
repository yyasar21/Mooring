//! [`VsphereError`] and its stable `vsphere.*` codes. No variant carries a credential, a
//! session token, a ticket or server-controlled text (vCenter error messages are dropped; only
//! the closed `error_type` enum is read).

use std::time::Duration;

use mooring_http::{HttpError, StatusClass};
use serde::Deserialize;

/// Errors of the vSphere client.
#[derive(Debug, thiserror::Error)]
pub enum VsphereError {
    /// Login refused, the session expired and re-login failed, or no credential is available
    /// (vault locked). Code `vsphere.auth_failed`.
    #[error("vCenter authentication failed")]
    Auth,
    /// The account lacks the privilege for this call (HTTP 403). Code `vsphere.forbidden`.
    #[error("vCenter refused the operation for this account")]
    Forbidden,
    /// HTTP 429 after mooring-http's bounded retries. Code `vsphere.rate_limited`.
    #[error("vCenter rate limit reached")]
    RateLimited {
        /// The server's `Retry-After` (delta seconds, ≤ 1 h), if it sent one.
        retry_after: Option<Duration>,
    },
    /// The object does not exist (any more). Code `vsphere.not_found`.
    #[error("vCenter object not found")]
    NotFound,
    /// A cap was hit (inventory size, list length, body size); nothing should be written.
    /// Code `vsphere.too_large`.
    #[error("vCenter {0} exceeds the configured limit")]
    TooLarge(&'static str),
    /// A guest operation needs running `VMware` Tools. Code `vsphere.tools_missing`.
    #[error("VMware Tools are not running in the guest")]
    ToolsMissing,
    /// The VM is not in a state that allows the action. Code `vsphere.wrong_state`.
    #[error("the VM is not in a state that allows this action")]
    WrongState,
    /// Power actions are off for this vCenter connection. Code `vsphere.power_disabled`.
    #[error("power actions are disabled for this vCenter")]
    PowerDisabled,
    /// The native confirmation was not given. Code `vsphere.not_confirmed`.
    #[error("the power action was not confirmed")]
    NotConfirmed,
    /// Another power action for the same VM is in flight. Code `vsphere.busy`.
    #[error("another action for this VM is in progress")]
    Busy,
    /// An argument was refused before anything was sent (id, name, URL). Code
    /// `vsphere.invalid`.
    #[error("invalid vSphere request: {0}")]
    Invalid(&'static str),
    /// The response did not match the expected model. Code `vsphere.failed`.
    #[error("unexpected vCenter response: {0}")]
    BadResponse(&'static str),
    /// Any other non-success status. Code `vsphere.failed`.
    #[error("vCenter call failed (HTTP {status})")]
    Failed {
        /// The HTTP status.
        status: u16,
    },
    /// Connect failure, timeout, 5xx after retries. Code `vsphere.unavailable`.
    #[error("vCenter is unavailable")]
    Unavailable,
    /// A trust / TLS / transport decision of mooring-http that the caller must act on
    /// (`http.trust_prompt`, `http.trust_mismatch`, …). Code = the http code.
    #[error(transparent)]
    Http(HttpError),
}

impl VsphereError {
    /// Stable machine code for IPC.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Auth => "vsphere.auth_failed",
            Self::Forbidden => "vsphere.forbidden",
            Self::RateLimited { .. } => "vsphere.rate_limited",
            Self::NotFound => "vsphere.not_found",
            Self::TooLarge(_) => "vsphere.too_large",
            Self::ToolsMissing => "vsphere.tools_missing",
            Self::WrongState => "vsphere.wrong_state",
            Self::PowerDisabled => "vsphere.power_disabled",
            Self::NotConfirmed => "vsphere.not_confirmed",
            Self::Busy => "vsphere.busy",
            Self::Invalid(_) => "vsphere.invalid",
            Self::BadResponse(_) | Self::Failed { .. } => "vsphere.failed",
            Self::Unavailable => "vsphere.unavailable",
            Self::Http(e) => e.code(),
        }
    }

    /// `Retry-After` of a [`VsphereError::RateLimited`].
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }
}

impl From<HttpError> for VsphereError {
    fn from(e: HttpError) -> Self {
        match e {
            HttpError::BodyTooLarge { .. } => Self::TooLarge("response body"),
            HttpError::Decode { .. } => Self::BadResponse("JSON does not match the model"),
            HttpError::Connect(_) | HttpError::Timeout | HttpError::Protocol => Self::Unavailable,
            HttpError::Status { status } => match StatusClass::of(status) {
                StatusClass::Unauthorized => Self::Auth,
                StatusClass::Forbidden => Self::Forbidden,
                StatusClass::NotFound => Self::NotFound,
                StatusClass::TooManyRequests => Self::RateLimited { retry_after: None },
                StatusClass::Server => Self::Unavailable,
                _ => Self::Failed { status: status.as_u16() },
            },
            other => Self::Http(other),
        }
    }
}

impl From<VsphereError> for mooring_core::MooringError {
    fn from(e: VsphereError) -> Self {
        match e {
            VsphereError::NotFound => Self::NotFound { kind: "vsphere object", id: String::new() },
            VsphereError::Invalid(r) => Self::Invalid { field: "vsphere", reason: r.to_owned() },
            VsphereError::Unavailable | VsphereError::Http(_) => Self::Transport(e.to_string()),
            other => Self::Protocol { protocol: "vsphere", reason: other.to_string() },
        }
    }
}

/// The closed `error_type` of a vSphere Automation API error document
/// (`{"error_type": "...", "messages": [...]}`). Messages are never read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiErrorType {
    AlreadyInDesiredState,
    NotAllowedInCurrentState,
    ServiceUnavailable,
    UnableToAllocateResource,
    Unauthenticated,
    Unauthorized,
    NotFound,
    Other,
}

#[derive(Deserialize)]
struct ErrorDoc<'a> {
    #[serde(borrow, default)]
    error_type: Option<&'a str>,
}

/// Read `error_type` from an error body (≤ 64 KiB considered; anything else → `Other`).
pub(crate) fn api_error_type(body: &[u8]) -> ApiErrorType {
    if body.len() > 64 * 1024 {
        return ApiErrorType::Other;
    }
    let Ok(doc) = serde_json::from_slice::<ErrorDoc<'_>>(body) else {
        return ApiErrorType::Other;
    };
    match doc.error_type.unwrap_or_default() {
        "ALREADY_IN_DESIRED_STATE" => ApiErrorType::AlreadyInDesiredState,
        "NOT_ALLOWED_IN_CURRENT_STATE" => ApiErrorType::NotAllowedInCurrentState,
        "SERVICE_UNAVAILABLE" => ApiErrorType::ServiceUnavailable,
        "UNABLE_TO_ALLOCATE_RESOURCE" => ApiErrorType::UnableToAllocateResource,
        "UNAUTHENTICATED" => ApiErrorType::Unauthenticated,
        "UNAUTHORIZED" => ApiErrorType::Unauthorized,
        "NOT_FOUND" => ApiErrorType::NotFound,
        _ => ApiErrorType::Other,
    }
}

/// Map a non-success status + error body to an error (generic calls).
pub(crate) fn status_error(
    status: u16,
    body: &[u8],
    retry_after: Option<Duration>,
) -> VsphereError {
    let t = api_error_type(body);
    match (status, t) {
        (401, _) | (_, ApiErrorType::Unauthenticated) => VsphereError::Auth,
        (403, _) | (_, ApiErrorType::Unauthorized) => VsphereError::Forbidden,
        (404, _) | (_, ApiErrorType::NotFound) => VsphereError::NotFound,
        (429, _) => VsphereError::RateLimited { retry_after },
        (_, ApiErrorType::UnableToAllocateResource) => VsphereError::TooLarge("result list"),
        (_, ApiErrorType::AlreadyInDesiredState | ApiErrorType::NotAllowedInCurrentState) => {
            VsphereError::WrongState
        }
        (500..=599, _) => VsphereError::Unavailable,
        _ => VsphereError::Failed { status },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_documents_map_to_codes() {
        let doc =
            |t: &str| format!(r#"{{"error_type":"{t}","messages":[{{"default_message":"x"}}]}}"#);
        let code = |s, t: &str| status_error(s, doc(t).as_bytes(), None).code();
        assert_eq!(code(401, "UNAUTHENTICATED"), "vsphere.auth_failed");
        assert_eq!(code(403, "UNAUTHORIZED"), "vsphere.forbidden");
        assert_eq!(code(404, "NOT_FOUND"), "vsphere.not_found");
        assert_eq!(code(400, "NOT_ALLOWED_IN_CURRENT_STATE"), "vsphere.wrong_state");
        assert_eq!(code(500, "UNABLE_TO_ALLOCATE_RESOURCE"), "vsphere.too_large");
        assert_eq!(code(503, "SERVICE_UNAVAILABLE"), "vsphere.unavailable");
        assert_eq!(code(400, "INVALID_ARGUMENT"), "vsphere.failed");
        let rl = status_error(429, b"", Some(Duration::from_secs(7)));
        assert_eq!(
            (rl.code(), rl.retry_after()),
            ("vsphere.rate_limited", Some(Duration::from_secs(7)))
        );
        assert_eq!(api_error_type(b"\xff not json"), ApiErrorType::Other);
        assert_eq!(api_error_type(br#"{"error_type": 5}"#), ApiErrorType::Other);
    }

    #[test]
    fn display_never_carries_server_text() {
        let e = status_error(
            400,
            br#"{"error_type":"X","messages":[{"default_message":"SECRET"}]}"#,
            None,
        );
        assert!(!e.to_string().contains("SECRET"));
        let m: mooring_core::MooringError = e.into();
        assert!(!m.to_string().contains("SECRET"));
    }
}
