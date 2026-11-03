//! Vault errors. None of the variants carry key or plaintext material.

use thiserror::Error;

/// Errors from the vault.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    /// Wrong password, or the header/wrapped key was tampered with. Deliberately one variant:
    /// the two cases must be indistinguishable to a caller.
    #[error("wrong password or corrupted vault header")]
    Unlock,

    /// A sealed field failed authentication: wrong key, wrong record/field binding or tampering.
    #[error("sealed data failed authentication")]
    Tampered,

    /// The vault is locked; unlock it first.
    #[error("vault is locked")]
    Locked,

    /// Header could not be parsed or has an unsupported version.
    #[error("unsupported or malformed vault format: {0}")]
    Format(String),

    /// KDF parameters are outside the allowed range.
    #[error("invalid KDF parameters: {0}")]
    KdfParams(String),

    /// The password does not meet the minimum policy (length only; no composition rules).
    #[error("password too short (minimum {min} characters)")]
    WeakPassword {
        /// Minimum accepted length in characters.
        min: usize,
    },
}
