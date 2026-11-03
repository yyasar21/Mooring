//! Credential validation errors. `Display` names fields and short static reasons; it never
//! echoes a field or secret value.

use thiserror::Error;

use super::SecretName;

/// Why a credential, a field or a secret was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialError {
    /// A field or secret failed validation (`input.invalid` over IPC).
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field or secret name.
        field: &'static str,
        /// Reason; never the value.
        reason: String,
    },
    /// The kubeconfig is not self-contained or not parseable (`credential.kubeconfig_rejected`).
    #[error("{0}")]
    KubeconfigRejected(String),
    /// The kind cannot fill this protocol / role (`credential.incompatible`). The message is
    /// shown verbatim in the UI.
    #[error("{0}")]
    Incompatible(String),
    /// Valid credential, but this build cannot use it yet (`credential.kind_unsupported`).
    #[error("{0}")]
    KindUnsupported(String),
    /// A secret the operation needs is not stored (`credential.secret_missing`).
    #[error("{0} is not stored")]
    SecretMissing(SecretName),
}

impl CredentialError {
    /// `Invalid` for `field` with a value-free `reason`.
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid { field, reason: reason.into() }
    }
}

impl From<CredentialError> for crate::MooringError {
    fn from(e: CredentialError) -> Self {
        match e {
            CredentialError::Invalid { field, reason } => Self::Invalid { field, reason },
            other => Self::Invalid { field: "credential", reason: other.to_string() },
        }
    }
}
