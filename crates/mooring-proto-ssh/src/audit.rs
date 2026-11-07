//! Security-relevant events for the Tauri layer to append to the audit log.
//!
//! This crate does not depend on `mooring-audit`; it records [`TrustEvent`]s (=
//! `mooring_core::SessionAudit`) that the caller drains with `take_audit_events`. Events
//! never carry secret material.

use std::sync::{Arc, Mutex, PoisonError};

/// The audit types live in `mooring-core` since ADR-0011 (shared with RDP and VNC);
/// `TrustEvent` stays as this crate's name for them.
pub use mooring_core::audit::{AuthMethod, SessionAudit as TrustEvent};

/// Shared, append-only event buffer.
#[derive(Debug, Clone, Default)]
pub struct AuditLog(Arc<Mutex<Vec<TrustEvent>>>);

impl AuditLog {
    /// Append one event.
    pub fn push(&self, event: TrustEvent) {
        tracing::info!(action = event.action(), "ssh audit event");
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(event);
    }

    /// Drain everything recorded so far.
    pub fn take(&self) -> Vec<TrustEvent> {
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
