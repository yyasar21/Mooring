//! Store errors.
//!
//! Rule (CLAUDE.md): `Display` never contains secret material. Variants carry ids, field
//! names and short static reasons; plaintext and sealed bytes are never formatted.

use mooring_core::credential::CredentialError;
use mooring_core::MooringError;
use thiserror::Error;

/// Errors from the local store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `SQLite` failure (I/O, constraint, busy). Messages name tables/columns, never values.
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Sealing or opening a secret column failed (locked vault, wrong binding, tampering).
    #[error("vault: {0}")]
    Vault(#[from] mooring_vault::VaultError),

    /// Input rejected before it reached SQL.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field that failed validation.
        field: &'static str,
        /// Reason. Never echoes the offending value.
        reason: String,
    },

    /// A folder, connection or credential id does not exist.
    #[error("not found: {kind} {id}")]
    NotFound {
        /// `folder`, `connection`, `credential` or `secret`.
        kind: &'static str,
        /// The id that was looked up.
        id: String,
    },

    /// A folder operation would break the tree invariants (one root, no cycles).
    #[error("tree integrity: {0}")]
    Tree(String),

    /// The database was written by a newer schema than this build understands.
    #[error(
        "database schema v{found} is newer than supported v{supported}; refusing to downgrade"
    )]
    Downgrade {
        /// Version found in `setting.schema_version`.
        found: u32,
        /// Highest version this build knows.
        supported: u32,
    },

    /// `vault_id` is already set to a different vault (ADR-0005: one vault per app).
    #[error("store already belongs to another vault")]
    VaultIdMismatch,

    /// A credential rule refused the operation (kubeconfig rejected, incompatible kind, kind
    /// unsupported, secret missing). Messages are safe to show and never carry values.
    #[error("{0}")]
    Credential(CredentialError),

    /// An ordinary edit inside a vSphere-synced subtree (ADR-0015 §2): create, rename, move
    /// or delete. Only the overlays (credential, tags, overrides, options, a folder's default
    /// credential) may change there. IPC code `tree.synced_readonly`.
    #[error("this item is synced from vCenter and is read-only")]
    SyncedReadOnly,

    /// A stored value could not be decoded (bad UUID, timestamp, enum or sealed JSON).
    #[error("corrupt {what} in database")]
    Corrupt {
        /// Which kind of value was unreadable.
        what: &'static str,
    },
}

impl From<MooringError> for StoreError {
    fn from(e: MooringError) -> Self {
        match e {
            MooringError::Invalid { field, reason } => Self::Invalid { field, reason },
            MooringError::NotFound { kind, id } => Self::NotFound { kind, id },
            MooringError::Tree(r) => Self::Tree(r),
            other => Self::Invalid { field: "input", reason: other.to_string() },
        }
    }
}

impl From<CredentialError> for StoreError {
    fn from(e: CredentialError) -> Self {
        match e {
            CredentialError::Invalid { field, reason } => Self::Invalid { field, reason },
            other => Self::Credential(other),
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, StoreError>;

pub(crate) fn invalid(field: &'static str, reason: &str) -> StoreError {
    StoreError::Invalid { field, reason: reason.to_owned() }
}

pub(crate) fn not_found(kind: &'static str, id: &dyn std::fmt::Display) -> StoreError {
    StoreError::NotFound { kind, id: id.to_string() }
}
