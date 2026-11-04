//! Audit hooks (ADR-0016 §7). Events carry ids, names, counts and categories, never a token
//! or a secret value; src-tauri maps them onto `mooring-audit` (adding the connection id).

use std::sync::{Mutex, PoisonError};

use mooring_core::secret_source::SourceAuthMethod;
use mooring_core::{CredentialId, CredentialKind, SecretSourceId};

use crate::error::Category;

/// One security event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretEvent {
    /// `secret.login { source, method, ttl }`.
    Login {
        /// Source.
        source: SecretSourceId,
        /// Method.
        method: SourceAuthMethod,
        /// Cached lifetime in seconds.
        ttl: u64,
    },
    /// Token renewed by the cache (`secret.login` with method `renew` in the log).
    Renewed {
        /// Source.
        source: SecretSourceId,
        /// New lifetime in seconds.
        ttl: u64,
    },
    /// `secret.resolved { credential, source, reference, version, target_kind, fields }`.
    Resolved {
        /// The `external_ref` credential.
        credential: CredentialId,
        /// Source.
        source: SecretSourceId,
        /// `<mount>/<path>` (inventory class, R-INV-CRED).
        reference: String,
        /// Version read.
        version: u64,
        /// Target kind.
        target_kind: CredentialKind,
        /// Names of the fields and secrets that were filled (never values).
        fields: Vec<&'static str>,
    },
    /// `secret.failed { source, category }`.
    Failed {
        /// Source.
        source: SecretSourceId,
        /// Category.
        category: Category,
    },
    /// `secret.revoked { source }` (token dropped; revoked server-side when ours).
    Revoked {
        /// Source.
        source: SecretSourceId,
    },
}

impl SecretEvent {
    /// Audit event name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Login { .. } | Self::Renewed { .. } => "secret.login",
            Self::Resolved { .. } => "secret.resolved",
            Self::Failed { .. } => "secret.failed",
            Self::Revoked { .. } => "secret.revoked",
        }
    }
}

/// Sink for [`SecretEvent`]s. Must not block.
pub trait SecretsAudit: Send + Sync {
    /// Record one event.
    fn record(&self, event: SecretEvent);
}

/// Discards events.
#[derive(Debug, Default)]
pub struct NoAudit;

impl SecretsAudit for NoAudit {
    fn record(&self, _event: SecretEvent) {}
}

/// Keeps events in memory (tests, the Tauri layer drains it).
#[derive(Debug, Default)]
pub struct MemoryAudit(Mutex<Vec<SecretEvent>>);

impl MemoryAudit {
    /// Take every recorded event.
    pub fn take(&self) -> Vec<SecretEvent> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl SecretsAudit for MemoryAudit {
    fn record(&self, event: SecretEvent) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(event);
    }
}
