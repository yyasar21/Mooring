//! [`SyncError`]: every failure of the sync crate, with a stable `sync.*` code for IPC.
//! Messages never carry secret material, object bodies or credentials.

use mooring_http::HttpError;
use mooring_store::StoreError;
use mooring_vault::VaultError;

/// Result alias of the crate.
pub type Result<T, E = SyncError> = std::result::Result<T, E>;

/// Sync failure.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A blob, snapshot or remote object is malformed.
    #[error("malformed sync data: {0}")]
    Format(&'static str),
    /// Over a size cap (blob, snapshot, trust file, object).
    #[error("sync data exceeds the size cap")]
    TooLarge,
    /// AEAD authentication failed: wrong key or modified bytes.
    #[error("sync blob failed authentication")]
    Tampered,
    /// The blob belongs to another vault.
    #[error("sync blob belongs to another vault")]
    WrongVault,
    /// The remote vault header does not match the blob or this device's header.
    #[error("remote vault header does not match: {0}")]
    HeaderMismatch(&'static str),
    /// The remote generation went backwards: hard stop, never applied.
    #[error("SYNC ROLLBACK: remote generation {remote} is older than the last seen {last}")]
    Rollback {
        /// Remote counter (0 = the remote object disappeared).
        remote: u64,
        /// Last counter this device saw.
        last: u64,
    },
    /// Two devices published diverging histories: hard stop until the user resolves it.
    #[error("sync fork at remote generation {remote}: resolve by keeping local or remote")]
    Fork {
        /// Remote counter.
        remote: u64,
    },
    /// Conditional writes kept failing (someone pushes concurrently); try again later.
    #[error("sync conflict: the remote changed during every attempt")]
    Conflict,
    /// The backend ignores conditional writes.
    #[error("the storage backend does not honour conditional writes")]
    UnsupportedBackend,
    /// The backend returned an unexpected status.
    #[error("storage backend returned status {status}")]
    Backend {
        /// HTTP status.
        status: u16,
    },
    /// Sync cannot run with the keyring wrap enabled (the header object must not carry it).
    #[error("disable the OS keyring unlock before enabling sync")]
    KeyringHeader,
    /// Invalid configuration or call.
    #[error("invalid sync request: {0}")]
    Invalid(&'static str),
    /// Transport.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// Local store.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Vault (locked, sealing).
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// Trust-store file I/O.
    #[error("sync file I/O: {0:?}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

impl SyncError {
    /// Stable machine code (ADR-0017 §5 plus the transport's `http.*`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Format(_) => "sync.format",
            Self::TooLarge | Self::Http(HttpError::BodyTooLarge { .. }) => "sync.too_large",
            Self::Tampered => "sync.tampered",
            Self::WrongVault => "sync.wrong_vault",
            Self::HeaderMismatch(_) => "sync.header_mismatch",
            Self::Rollback { .. } => "sync.rollback",
            Self::Fork { .. } => "sync.fork",
            Self::Conflict => "sync.conflict",
            Self::UnsupportedBackend => "sync.unsupported_backend",
            Self::Backend { .. } => "sync.backend",
            Self::KeyringHeader => "sync.keyring_header",
            Self::Invalid(_) => "sync.invalid",
            Self::Http(e) => e.code(),
            Self::Store(_) => "sync.store",
            Self::Vault(VaultError::Locked) => "vault.locked",
            Self::Vault(_) => "sync.vault",
            Self::Io(_) => "sync.io",
        }
    }

    /// `true` for the hard stops that need [`crate::SyncEngine::resolve_fork`].
    pub fn is_alarm(&self) -> bool {
        matches!(self, Self::Rollback { .. } | Self::Fork { .. })
    }
}
