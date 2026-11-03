//! Security-relevant events for the Tauri layer to append to the audit log.
//!
//! This crate does not depend on `mooring-audit`; it records [`TrustEvent`]s that the caller
//! drains with `SshSession::take_audit_events`. Events never carry secret material.

use std::sync::{Arc, Mutex, PoisonError};

/// Authentication method that succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// `publickey` with the vault key.
    PublicKey,
    /// `publickey` through the ssh-agent.
    Agent,
    /// `password`.
    Password,
    /// `keyboard-interactive`.
    KeyboardInteractive,
}

impl AuthMethod {
    /// Stable name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicKey => "publickey",
            Self::Agent => "agent",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// One audit-worthy event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEvent {
    /// The user trusted a new host key (TOFU "yes"); it was stored.
    HostKeyAdded {
        /// Host as given.
        host: String,
        /// Port.
        port: u16,
        /// Key type, e.g. `ssh-ed25519`.
        key_type: String,
        /// `SHA256:<base64>`.
        fingerprint: String,
    },
    /// The user declined a new host key.
    HostKeyRejected {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// `SHA256:<base64>` of the declined key.
        fingerprint: String,
    },
    /// The stored key differs from the presented one; the connection was stopped.
    HostKeyMismatch {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// Stored fingerprint (or `revoked`).
        expected: String,
        /// Presented fingerprint.
        presented: String,
    },
    /// Authentication succeeded with this method.
    AuthSucceeded {
        /// Method.
        method: AuthMethod,
    },
    /// Every method failed.
    AuthFailed,
    /// A port forward started listening (ADR-0007 §Channels and flow).
    ForwardOpened {
        /// Session-local id, e.g. `fwd-1`.
        id: String,
        /// `local`, `remote` or `dynamic`.
        kind: &'static str,
        /// Address actually bound (local side for local/dynamic, server side for remote).
        bind: String,
        /// Where connections go (`host:port`, or `socks5` for dynamic).
        target: String,
    },
    /// A port forward stopped (by the user or because the session ended).
    ForwardClosed {
        /// Session-local id.
        id: String,
        /// `local`, `remote` or `dynamic`.
        kind: &'static str,
        /// Bound address.
        bind: String,
        /// Target.
        target: String,
    },
}

impl TrustEvent {
    /// Audit action name, e.g. `trust.host_key.added`.
    pub fn action(&self) -> &'static str {
        match self {
            Self::HostKeyAdded { .. } => "trust.host_key.added",
            Self::HostKeyRejected { .. } => "trust.host_key.rejected",
            Self::HostKeyMismatch { .. } => "trust.host_key.mismatch",
            Self::AuthSucceeded { .. } => "session.auth.succeeded",
            Self::AuthFailed => "session.auth.failed",
            Self::ForwardOpened { .. } => "session.forward.open",
            Self::ForwardClosed { .. } => "session.forward.close",
        }
    }
}

/// Shared, append-only event buffer.
#[derive(Debug, Clone, Default)]
pub(crate) struct AuditLog(Arc<Mutex<Vec<TrustEvent>>>);

impl AuditLog {
    pub(crate) fn push(&self, event: TrustEvent) {
        tracing::info!(action = event.action(), "ssh audit event");
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(event);
    }

    pub(crate) fn take(&self) -> Vec<TrustEvent> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_drains() {
        let log = AuditLog::default();
        log.push(TrustEvent::AuthFailed);
        log.push(TrustEvent::AuthSucceeded { method: AuthMethod::Password });
        let events = log.take();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action(), "session.auth.failed");
        assert!(log.take().is_empty());
        assert_eq!(AuthMethod::KeyboardInteractive.as_str(), "keyboard-interactive");
    }
}
