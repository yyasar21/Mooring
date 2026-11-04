//! Single flight and cool-down for the Rust-native confirmations (review 6, M-16).
//!
//! A compromised `WebView` (T5) decides *when* a native dialog appears, so besides putting
//! "Cancel" first (Return refuses) the gate bounds how often one can be raised:
//!
//! - at most **one** native confirmation is open per process; a second request fails
//!   `confirm.busy` without a dialog;
//! - after a **cancelled destructive** confirmation (power off / reset, trust-and-remember,
//!   fork resolution) the same action on the same target is refused for [`COOLDOWN`]
//!   (`confirm.cooldown`), so a stray Enter cannot be fished for by re-asking at once.
//!
//! Both refusals are audited (`confirm_refused`). The gate lives in `AppState::confirm`; every
//! prompter (`vsphere_confirm::Prompt`, `sync_gate`) acquires a [`Slot`] before showing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mooring_audit::{AuditEvent, AuditLog};

use crate::error::{IpcError, IpcResult};
use crate::state::record_audit;

/// How long a cancelled destructive confirmation blocks the same action on the same target.
pub const COOLDOWN: Duration = Duration::from_secs(10);

/// What a confirmation is about (audit names only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope<'s> {
    /// Dialog kind (`vsphere_power`, `vsphere_trust`, `vmrc`, `sync_trust`, `sync_fork`).
    pub kind: &'static str,
    /// Target: connection id, `vm-42`, `host:port`. Never a secret.
    pub target: &'s str,
    /// Cancelling starts the cool-down for `kind:target`.
    pub destructive: bool,
}

#[derive(Debug, Default)]
struct Inner {
    open: bool,
    cooldowns: HashMap<String, Instant>,
}

/// The process-wide gate.
pub struct ConfirmGate {
    inner: Mutex<Inner>,
    audit: Arc<Mutex<AuditLog>>,
    cooldown: Duration,
}

impl std::fmt::Debug for ConfirmGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmGate").field("cooldown", &self.cooldown).finish_non_exhaustive()
    }
}

/// An open confirmation: dropping it frees the gate. Call [`Slot::done`] with the answer so a
/// cancelled destructive dialog starts its cool-down (a dropped slot counts as cancelled).
#[derive(Debug)]
pub struct Slot<'a> {
    gate: &'a ConfirmGate,
    key: Option<String>,
    confirmed: bool,
    now: Instant,
}

impl Slot<'_> {
    /// Record the answer and free the gate.
    pub fn done(mut self, confirmed: bool) {
        self.confirmed = confirmed;
        self.now = Instant::now();
    }

    /// [`done`](Self::done) at a simulated `now` (tests).
    pub fn done_at(mut self, confirmed: bool, now: Instant) {
        self.confirmed = confirmed;
        self.now = now;
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.gate.release(self.key.take().filter(|_| !self.confirmed), self.now);
    }
}

impl ConfirmGate {
    /// A gate with the production cool-down.
    pub fn new(audit: Arc<Mutex<AuditLog>>) -> Self {
        Self { inner: Mutex::new(Inner::default()), audit, cooldown: COOLDOWN }
    }

    /// Override the cool-down (tests).
    #[must_use]
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    /// Reserve the one dialog slot for `scope`, or refuse (`confirm.busy`, `confirm.cooldown`).
    pub fn acquire(&self, scope: Scope<'_>) -> IpcResult<Slot<'_>> {
        self.acquire_at(scope, Instant::now())
    }

    /// [`acquire`](Self::acquire) at a simulated `now` (tests).
    pub fn acquire_at(&self, scope: Scope<'_>, now: Instant) -> IpcResult<Slot<'_>> {
        let key = format!("{}:{}", scope.kind, scope.target);
        let refused = {
            let mut g = self.inner.lock().map_err(|_| IpcError::poisoned())?;
            g.cooldowns.retain(|_, until| *until > now);
            if g.open {
                Some("busy")
            } else if scope.destructive && g.cooldowns.contains_key(&key) {
                Some("cooldown")
            } else {
                g.open = true;
                None
            }
        };
        if let Some(reason) = refused {
            tracing::warn!(kind = scope.kind, reason, "native confirmation refused");
            record_audit(
                &self.audit,
                AuditEvent::ConfirmRefused {
                    kind: scope.kind.to_owned(),
                    target: scope.target.to_owned(),
                    reason: reason.to_owned(),
                },
            );
            return Err(match reason {
                "busy" => IpcError::new("confirm.busy", "another confirmation dialog is already open"),
                _ => IpcError::new(
                    "confirm.cooldown",
                    "this action was just cancelled; wait a few seconds before asking again",
                ),
            });
        }
        Ok(Slot { gate: self, key: scope.destructive.then_some(key), confirmed: false, now })
    }

    /// Forget every cool-down (tests that reject and then accept the same target).
    #[cfg(any(test, feature = "test-util"))]
    pub fn clear_cooldowns(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.cooldowns.clear();
        }
    }

    /// Whether a dialog is open right now.
    pub fn is_open(&self) -> bool {
        self.inner.lock().is_ok_and(|g| g.open)
    }

    fn release(&self, cancelled_key: Option<String>, now: Instant) {
        if let Ok(mut g) = self.inner.lock() {
            g.open = false;
            if let Some(k) = cancelled_key {
                g.cooldowns.insert(k, now + self.cooldown);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> (tempfile::TempDir, ConfirmGate) {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::open(dir.path().join("audit.jsonl")).expect("audit");
        (dir, ConfirmGate::new(Arc::new(Mutex::new(log))))
    }

    fn events(dir: &tempfile::TempDir) -> Vec<String> {
        std::fs::read_to_string(dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("confirm_refused"))
            .map(str::to_owned)
            .collect()
    }

    const POWER: Scope<'static> = Scope { kind: "vsphere_power", target: "c/vm-1", destructive: true };
    const VMRC: Scope<'static> = Scope { kind: "vmrc", target: "c/vm-1", destructive: false };

    #[test]
    fn one_dialog_at_a_time() {
        let (dir, g) = gate();
        let slot = g.acquire(VMRC).expect("first");
        assert!(g.is_open());
        assert_eq!(g.acquire(POWER).expect_err("second").code, "confirm.busy");
        let rows = events(&dir);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("\"reason\":\"busy\"") && rows[0].contains("\"target\":\"c/vm-1\""), "{rows:?}");
        slot.done(true);
        assert!(!g.is_open());
        g.acquire(POWER).expect("free again").done(true);
    }

    #[test]
    fn cancelled_destructive_cools_down_per_target() {
        let (dir, g) = gate();
        let t0 = Instant::now();
        g.acquire_at(POWER, t0).expect("ask").done_at(false, t0);
        assert_eq!(g.acquire_at(POWER, t0).expect_err("retry").code, "confirm.cooldown");
        assert!(events(&dir)[0].contains("\"reason\":\"cooldown\""));
        // Another target or kind is unaffected.
        let other = Scope { target: "c/vm-2", ..POWER };
        g.acquire_at(other, t0).expect("other vm").done(true);
        g.acquire_at(Scope { kind: "vmrc", ..POWER }, t0).expect("other kind").done(true);
        // Non-destructive prompts never cool down.
        g.acquire_at(VMRC, t0).expect("vmrc").done(false);
        g.acquire_at(VMRC, t0).expect("vmrc again").done(false);
        // The cool-down expires.
        assert_eq!(g.acquire_at(POWER, t0 + Duration::from_millis(9_999)).expect_err("still").code, "confirm.cooldown");
        g.acquire_at(POWER, t0 + COOLDOWN).expect("expired").done(true);
    }

    #[test]
    fn confirmed_and_dropped_slots() {
        let (_dir, g) = gate();
        g.acquire(POWER).expect("ask").done(true);
        g.acquire(POWER).expect("confirmed: no cool-down").done(true);
        drop(g.acquire(POWER).expect("ask"));
        assert_eq!(g.acquire(POWER).expect_err("dropped counts as cancelled").code, "confirm.cooldown");
    }
}
