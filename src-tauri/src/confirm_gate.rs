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
//! Both refusals are audited (`confirm_refused`), bounded (6b N-47): the first [`AUDITED`]
//! refusals of each hour of process uptime get a row each, the rest are counted and written
//! as one `confirm_refused_suppressed { count }` row when the next hour starts, so a T5 that
//! loops a command behind an open dialog cannot grow the hash chain without bound. The gate
//! lives in `AppState::confirm`; every prompter (`vsphere_confirm::Prompt`, `sync_gate`)
//! acquires a [`Slot`] before showing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mooring_audit::{AuditEvent, AuditLog};

use crate::error::{IpcError, IpcResult};
use crate::state::record_audit;

/// How long a cancelled destructive confirmation blocks the same action on the same target.
pub const COOLDOWN: Duration = Duration::from_secs(10);
/// Refusals audited one by one per [`AUDIT_WINDOW`] (N-47).
pub const AUDITED: u32 = 16;
/// The process-uptime window of the refusal budget.
pub const AUDIT_WINDOW: Duration = Duration::from_secs(3600);

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

#[derive(Debug)]
struct Inner {
    open: bool,
    cooldowns: HashMap<String, Instant>,
    /// Start of the current refusal-budget window.
    window: Instant,
    /// Refusals audited in this window.
    audited: u32,
    /// Refusals counted only in this window.
    suppressed: u64,
}

impl Inner {
    fn new(now: Instant) -> Self {
        Self { open: false, cooldowns: HashMap::new(), window: now, audited: 0, suppressed: 0 }
    }

    /// Account one refusal at `now`: `(write its own row, summary of the closed window)`.
    fn refusal(&mut self, now: Instant) -> (bool, Option<u64>) {
        let mut summary = None;
        if now.saturating_duration_since(self.window) >= AUDIT_WINDOW {
            summary = (self.suppressed > 0).then_some(self.suppressed);
            self.window = now;
            self.audited = 0;
            self.suppressed = 0;
        }
        if self.audited < AUDITED {
            self.audited += 1;
            (true, summary)
        } else {
            self.suppressed += 1;
            (false, summary)
        }
    }
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
        Self { inner: Mutex::new(Inner::new(Instant::now())), audit, cooldown: COOLDOWN }
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
                Some(("busy", g.refusal(now)))
            } else if scope.destructive && g.cooldowns.contains_key(&key) {
                Some(("cooldown", g.refusal(now)))
            } else {
                g.open = true;
                None
            }
        };
        if let Some((reason, (own_row, summary))) = refused {
            tracing::warn!(kind = scope.kind, reason, "native confirmation refused");
            if let Some(count) = summary {
                record_audit(&self.audit, AuditEvent::ConfirmRefusedSuppressed { count });
            }
            if own_row {
                record_audit(
                    &self.audit,
                    AuditEvent::ConfirmRefused {
                        kind: scope.kind.to_owned(),
                        target: scope.target.to_owned(),
                        reason: reason.to_owned(),
                    },
                );
            }
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

    /// 6b N-47: the first 16 refusals of an hour get a row each; the rest are counted and
    /// written once as `confirm_refused_suppressed { count }` when the next hour starts.
    #[test]
    fn refusal_rows_are_bounded_per_hour_of_uptime() {
        let (dir, g) = gate();
        let t0 = Instant::now();
        let slot = g.acquire_at(VMRC, t0).expect("open dialog");
        for _ in 0..100 {
            assert_eq!(g.acquire_at(POWER, t0 + Duration::from_secs(1)).expect_err("busy").code, "confirm.busy");
        }
        let rows = events(&dir);
        assert_eq!(rows.len(), 16, "{rows:?}");
        assert!(rows.iter().all(|r| r.contains("\"event\":\"confirm_refused\"")));
        // Still the same hour: counted only.
        assert_eq!(g.acquire_at(POWER, t0 + Duration::from_secs(3599)).expect_err("busy").code, "confirm.busy");
        assert_eq!(events(&dir).len(), 16);
        // The next hour: one summary for the 85 counted refusals, then a fresh budget.
        assert_eq!(g.acquire_at(POWER, t0 + AUDIT_WINDOW).expect_err("busy").code, "confirm.busy");
        let rows = events(&dir);
        assert_eq!(rows.len(), 18);
        assert!(rows[16].contains("\"event\":\"confirm_refused_suppressed\"") && rows[16].contains("\"count\":85"), "{}", rows[16]);
        assert!(rows[17].contains("\"event\":\"confirm_refused\""));
        slot.done(true);
        // A window without suppressed refusals writes no summary.
        g.acquire_at(VMRC, t0 + 3 * AUDIT_WINDOW).expect("free").done(true);
        let held = g.acquire_at(VMRC, t0 + 3 * AUDIT_WINDOW).expect("open");
        assert_eq!(g.acquire_at(POWER, t0 + 3 * AUDIT_WINDOW).expect_err("busy").code, "confirm.busy");
        assert_eq!(events(&dir).len(), 19);
        assert!(!events(&dir).iter().skip(18).any(|r| r.contains("suppressed")));
        drop(held);
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
