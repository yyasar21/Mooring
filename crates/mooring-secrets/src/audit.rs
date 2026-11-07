//! Audit hooks (ADR-0016 §7). Events carry ids, names, counts and categories, never a token
//! or a secret value; src-tauri maps them onto `mooring-audit` (adding the connection id).

use std::sync::{Mutex, PoisonError};

use mooring_core::credential::VaultEngine;
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
        /// `vault` | `onepassword` | `bitwarden` (ADR-0026 §5).
        provider: &'static str,
        /// Vault engine (`kv2` for the other providers).
        engine: VaultEngine,
    },
    /// `secret.lease_issued { session, source, engine, ttl, renewable }`.
    LeaseIssued {
        /// Owner (session id), `None` for a test resolve (revoked at once).
        owner: Option<String>,
        /// Source.
        source: SecretSourceId,
        /// Engine.
        engine: VaultEngine,
        /// Lease duration in seconds.
        ttl: u64,
        /// Renewable.
        renewable: bool,
    },
    /// `secret.lease_renewed { session, source, ttl }`.
    LeaseRenewed {
        /// Owner.
        owner: String,
        /// Source.
        source: SecretSourceId,
        /// New duration in seconds.
        ttl: u64,
    },
    /// `secret.lease_renew_failed { session, source, category }` (the session keeps running).
    LeaseRenewFailed {
        /// Owner.
        owner: String,
        /// Source.
        source: SecretSourceId,
        /// Category.
        category: Category,
    },
    /// `secret.lease_revoked { session, source, reason, ok }` (best effort, 3 s).
    LeaseRevoked {
        /// Owner, `None` for a test resolve.
        owner: Option<String>,
        /// Source.
        source: SecretSourceId,
        /// `closed` | `locked` | `exit` | `reconnect` | `test` | `refused`.
        reason: &'static str,
        /// The server confirmed.
        ok: bool,
    },
    /// `secret.tool_spawned { provider, action, exit }` (ADR-0026 §5).
    ToolSpawned {
        /// `bitwarden`.
        provider: &'static str,
        /// `version` | `secret_get` | `secret_list` | `project_list`.
        action: &'static str,
        /// Exit code (`None`: killed at the deadline or the cap, or by a signal).
        exit: Option<i32>,
    },
    /// `secret.tool_changed { provider, sha256 }`: the pinned `bws` binary changed (warning).
    ToolChanged {
        /// `bitwarden`.
        provider: &'static str,
        /// Hex SHA-256 of the new binary.
        sha256: String,
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
            Self::LeaseIssued { .. } => "secret.lease_issued",
            Self::LeaseRenewed { .. } => "secret.lease_renewed",
            Self::LeaseRenewFailed { .. } => "secret.lease_renew_failed",
            Self::LeaseRevoked { .. } => "secret.lease_revoked",
            Self::ToolSpawned { .. } => "secret.tool_spawned",
            Self::ToolChanged { .. } => "secret.tool_changed",
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
