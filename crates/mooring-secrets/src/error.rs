//! [`SecretsError`]: the ADR-0016 error codes and failure categories. No variant carries a
//! token, a secret value or server-controlled text; shape errors name fields only.

use mooring_http::{HttpError, StatusCode, TrustDecision, TrustVerdict};

/// `credential.external_unavailable` category (ADR-0016 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// DNS / TCP / timeout / 5xx (sealed, standby, overloaded).
    Network,
    /// TLS failure, pin mismatch or a certificate prompt.
    Tls,
    /// Login refused (bad token, bad `AppRole`, OIDC failed or required).
    AuthFailed,
    /// The token may not read the path.
    Forbidden,
    /// The secret or version does not exist (or was deleted / destroyed).
    NotFound,
    /// The response or the KV secret does not have the expected shape.
    Shape,
    /// The Mooring vault is locked, so the login material cannot be opened.
    Locked,
}

impl Category {
    /// Wire name (`network`, `tls`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Tls => "tls",
            Self::AuthFailed => "auth_failed",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Shape => "shape",
            Self::Locked => "locked",
        }
    }
}

/// Errors of secret resolution. Every failure closes; nothing falls back to a cached value.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// The source cannot serve the request (`credential.external_unavailable`).
    #[error("the secret source is unavailable ({}): {detail}", .category.as_str())]
    Unavailable {
        /// Category.
        category: Category,
        /// Static, value-free detail.
        detail: &'static str,
    },
    /// The server certificate needs a decision or changed (`credential.external_unavailable`,
    /// category `tls`); the decision drives the trust prompt.
    #[error("the secret source certificate is not trusted")]
    Trust(Box<TrustDecision>),
    /// The token has the `root` policy (`credential.external_root_token`).
    #[error("root tokens are refused; use a token with a narrow policy")]
    RootToken,
    /// The secret, version or path does not exist (`credential.external_not_found`).
    #[error("the referenced secret does not exist or was deleted")]
    NotFound,
    /// The KV secret does not fit the target kind (`credential.external_shape`). Names only.
    #[error("the secret does not fit the target kind: {}", describe(.missing, .extra, .invalid.as_ref()))]
    Shape {
        /// Required names absent from the KV secret.
        missing: Vec<String>,
        /// KV keys the target kind does not use.
        extra: Vec<String>,
        /// `field: reason` from the target kind's validators (value-free).
        invalid: Option<String>,
    },
    /// The request was refused before anything was sent (`input.invalid`).
    #[error("invalid {0}")]
    Invalid(&'static str),
}

fn describe(missing: &[String], extra: &[String], invalid: Option<&String>) -> String {
    let mut parts = Vec::new();
    if !missing.is_empty() {
        parts.push(format!("missing {}", missing.join(", ")));
    }
    if !extra.is_empty() {
        parts.push(format!("unexpected {}", extra.join(", ")));
    }
    if let Some(i) = invalid {
        parts.push(i.clone());
    }
    if parts.is_empty() {
        "malformed response".to_owned()
    } else {
        parts.join("; ")
    }
}

impl SecretsError {
    pub(crate) const fn unavailable(category: Category, detail: &'static str) -> Self {
        Self::Unavailable { category, detail }
    }

    pub(crate) fn shape(invalid: impl Into<String>) -> Self {
        Self::Shape { missing: Vec::new(), extra: Vec::new(), invalid: Some(invalid.into()) }
    }

    /// The IPC code (ADR-0016 §7).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } | Self::Trust(_) => "credential.external_unavailable",
            Self::RootToken => "credential.external_root_token",
            Self::NotFound => "credential.external_not_found",
            Self::Shape { .. } => "credential.external_shape",
            Self::Invalid(_) => "input.invalid",
        }
    }

    /// The category of `secret.failed` / `credential.external_unavailable`.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::Unavailable { category, .. } => *category,
            Self::Trust(_) => Category::Tls,
            Self::RootToken => Category::AuthFailed,
            Self::NotFound => Category::NotFound,
            Self::Shape { .. } | Self::Invalid(_) => Category::Shape,
        }
    }

    /// The certificate decision behind a [`Self::Trust`] error, whatever its verdict (for
    /// audit rows and messages). Never the input of a dialog: use [`Self::prompt_decision`].
    #[must_use]
    pub fn trust_decision(&self) -> Option<&TrustDecision> {
        match self {
            Self::Trust(d) => Some(d),
            _ => None,
        }
    }

    /// The decision a trust **prompt** may be opened for (review 6c N-50): only
    /// [`TrustVerdict::Prompt`], i.e. no pin and an invalid chain. A pinned mismatch, a
    /// conflicting pin store (review 6b L-35) and an anchored rejection are hard stops and
    /// never reach a dialog, so they answer `None` here.
    #[must_use]
    pub fn prompt_decision(&self) -> Option<&TrustDecision> {
        self.trust_decision().filter(|d| d.verdict == TrustVerdict::Prompt)
    }

    /// Whether a fresh login could help (the cached token was refused).
    pub(crate) const fn token_refused(&self) -> bool {
        matches!(
            self,
            Self::Unavailable { category: Category::AuthFailed | Category::Forbidden, .. }
        )
    }
}

/// What the request was doing, to read a status the way Vault means it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ctx {
    /// Login / lookup / renew: 400, 401 and 403 mean "credentials refused".
    Login,
    /// KV read: 403 means "policy does not allow the path".
    Read,
}

/// Map a non-2xx status (bodies are never echoed).
pub(crate) fn from_status(status: StatusCode, ctx: Ctx) -> SecretsError {
    use Category as C;
    match (status.as_u16(), ctx) {
        (400 | 401 | 403, Ctx::Login) => SecretsError::unavailable(C::AuthFailed, "login refused"),
        (401, Ctx::Read) => SecretsError::unavailable(C::AuthFailed, "token refused"),
        (403, Ctx::Read) => SecretsError::unavailable(C::Forbidden, "permission denied"),
        (404, _) => SecretsError::NotFound,
        (429 | 500..=599, _) => {
            SecretsError::unavailable(C::Network, "server unavailable (sealed, standby or busy)")
        }
        _ => SecretsError::unavailable(C::Shape, "unexpected HTTP status"),
    }
}

impl From<HttpError> for SecretsError {
    fn from(e: HttpError) -> Self {
        use Category as C;
        match e {
            HttpError::TrustPrompt(d)
            | HttpError::TrustMismatch(d)
            | HttpError::TrustRejected(d)
            | HttpError::TrustConflict(d) => Self::Trust(d),
            HttpError::Tls(_) => Self::unavailable(C::Tls, "TLS failed"),
            HttpError::TrustStore => Self::unavailable(C::Tls, "trust store unreadable"),
            HttpError::PlaintextRefused => Self::unavailable(C::Tls, "plaintext refused"),
            HttpError::Connect(_) => Self::unavailable(C::Network, "connection failed"),
            HttpError::Timeout => Self::unavailable(C::Network, "timed out"),
            HttpError::Protocol | HttpError::WebSocket(_) => {
                Self::unavailable(C::Network, "HTTP protocol error")
            }
            HttpError::Status { status } => from_status(status, Ctx::Read),
            HttpError::Redirect { .. } => Self::unavailable(C::Shape, "redirect refused"),
            HttpError::BodyTooLarge { .. } => Self::shape("response too large"),
            HttpError::Decode { .. } => Self::shape("response is not the expected JSON"),
            HttpError::InvalidConfig(_) | HttpError::InvalidRequest(_) => {
                Self::Invalid("secret source configuration")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(verdict: TrustVerdict) -> TrustDecision {
        use mooring_http::{CertProtocol, CertTrust, CertificateInfo};
        TrustDecision {
            protocol: CertProtocol::Vault,
            host: "vault.example.test".into(),
            port: 8200,
            fingerprint: [7; 32],
            trust: CertTrust::Unknown,
            verdict,
            info: CertificateInfo {
                subject: "CN=vault.example.test".into(),
                issuer: "CN=vault.example.test".into(),
                not_before: time::OffsetDateTime::UNIX_EPOCH,
                not_after: time::OffsetDateTime::UNIX_EPOCH,
                sha256: "07".repeat(32),
                san: vec![],
                problems: vec![],
            },
        }
    }

    /// Review 6c N-50: every `http.trust_*` folds into `Trust`, but only the `Prompt` verdict
    /// may open a dialog; a conflicting store, a mismatch and an anchored rejection are hard
    /// stops with no prompt decision.
    #[test]
    fn only_the_prompt_verdict_offers_a_dialog() {
        let rows = [
            (HttpError::TrustPrompt(Box::new(decision(TrustVerdict::Prompt))), true),
            (HttpError::TrustConflict(Box::new(decision(TrustVerdict::Conflict))), false),
            (
                HttpError::TrustMismatch(Box::new(decision(TrustVerdict::Mismatch {
                    expected: [1; 32],
                }))),
                false,
            ),
            (HttpError::TrustRejected(Box::new(decision(TrustVerdict::Rejected))), false),
        ];
        for (e, promptable) in rows {
            let s = SecretsError::from(e);
            assert!(matches!(s, SecretsError::Trust(_)));
            assert_eq!(s.code(), "credential.external_unavailable");
            assert_eq!(s.category(), Category::Tls);
            assert!(s.trust_decision().is_some(), "the decision is kept for the audit row");
            assert_eq!(s.prompt_decision().is_some(), promptable, "{s}");
        }
        assert!(SecretsError::NotFound.prompt_decision().is_none());
    }

    #[test]
    fn statuses_map_to_categories() {
        let c = |s: u16, ctx| from_status(StatusCode::from_u16(s).expect("status"), ctx).category();
        assert_eq!(c(400, Ctx::Login), Category::AuthFailed);
        assert_eq!(c(403, Ctx::Login), Category::AuthFailed);
        assert_eq!(c(403, Ctx::Read), Category::Forbidden);
        assert_eq!(c(404, Ctx::Read), Category::NotFound);
        assert_eq!(c(503, Ctx::Read), Category::Network);
        assert_eq!(c(429, Ctx::Login), Category::Network);
        assert_eq!(c(418, Ctx::Read), Category::Shape);
        assert_eq!(SecretsError::RootToken.code(), "credential.external_root_token");
        assert_eq!(SecretsError::NotFound.code(), "credential.external_not_found");
        let s = SecretsError::Shape {
            missing: vec!["password".into()],
            extra: vec!["note".into()],
            invalid: None,
        };
        assert_eq!(s.code(), "credential.external_shape");
        assert_eq!(
            s.to_string(),
            "the secret does not fit the target kind: missing password; unexpected note"
        );
        for cat in [Category::Network, Category::Locked, Category::Tls] {
            let e = SecretsError::unavailable(cat, "x");
            assert_eq!(e.code(), "credential.external_unavailable");
            assert_eq!(e.category(), cat);
        }
    }
}
