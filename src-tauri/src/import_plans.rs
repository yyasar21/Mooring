//! Import plans held between `import_preview` and `import_apply` (ADR-0019 §3). A plan may
//! carry plaintext secrets (opt-in), so it never crosses IPC: the `WebView` sees a random
//! 128-bit `planId` and names only. A plan is
//! * single-use: `import_apply` and `import_discard` take it;
//! * valid for [`PLAN_TTL`];
//! * capped at [`MAX_PLANS`] (oldest dropped first);
//! * swept on **every** store access and by a [`SWEEP_TICK`] task (review 7 N-53), so an
//!   expired plan does not sit in memory until the next preview;
//! * dropped on every vault lock ([`ImportPlans::clear`]), which zeroizes its secrets.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mooring_import::{ImportFormat, ImportPlan};
use rand_core::{OsRng, RngCore};

use crate::error::{IpcError, IpcResult};

/// How long a plan stays applicable.
pub const PLAN_TTL: Duration = Duration::from_secs(10 * 60);
/// Most plans held at once.
pub const MAX_PLANS: usize = 8;
/// Length of a `planId`: 128 bits as lower-case hex.
pub const PLAN_ID_LEN: usize = 32;
/// How often the background sweep drops expired plans (N-53).
pub const SWEEP_TICK: Duration = Duration::from_secs(60);

/// A previewed plan with what the apply needs besides it.
#[derive(Debug)]
pub struct HeldPlan {
    /// The plan (secrets inside, zeroized on drop).
    pub plan: ImportPlan,
    /// Source format.
    pub format: ImportFormat,
    /// Plan connection key → existing connection id it duplicates.
    pub duplicates: HashMap<String, String>,
    created: Instant,
}

/// The plan store held in `AppState`.
#[derive(Debug, Default)]
pub struct ImportPlans {
    inner: Mutex<HashMap<String, HeldPlan>>,
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// `import.plan_expired`: unknown, used, expired or dropped by a lock; one answer for all.
pub fn expired() -> IpcError {
    IpcError::new("import.plan_expired", "the import preview has expired; run it again")
}

impl HeldPlan {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) >= PLAN_TTL
    }
}

impl ImportPlans {
    /// Lock the map, drop every expired plan (its secrets zeroize on drop), then run `f`.
    fn with<T>(&self, now: Instant, f: impl FnOnce(&mut HashMap<String, HeldPlan>) -> T) -> T {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.retain(|_, p| !p.expired(now));
        f(&mut g)
    }

    /// Drop expired plans (the [`SWEEP_TICK`] task and every access call this).
    pub fn sweep(&self, now: Instant) {
        self.with(now, |_| ());
    }

    /// Store a plan and return its `planId`.
    pub fn insert(
        &self,
        plan: ImportPlan,
        format: ImportFormat,
        duplicates: HashMap<String, String>,
        now: Instant,
    ) -> String {
        self.with(now, |m| {
            while m.len() >= MAX_PLANS {
                let oldest = m.iter().min_by_key(|(_, p)| p.created).map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => m.remove(&k),
                    None => break,
                };
            }
            let id = new_id();
            m.insert(id.clone(), HeldPlan { plan, format, duplicates, created: now });
            id
        })
    }

    /// Take (consume) a plan; expired or unknown ids are refused alike.
    pub fn take(&self, plan_id: &str, now: Instant) -> IpcResult<HeldPlan> {
        if plan_id.len() != PLAN_ID_LEN
            || !plan_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(expired());
        }
        self.with(now, |m| m.remove(plan_id).ok_or_else(expired))
    }

    /// Drop every plan (vault lock); secrets are zeroized by the plan's drop.
    pub fn clear(&self) {
        self.with(Instant::now(), HashMap::clear);
    }

    /// Plans held right now (expired ones are swept first).
    pub fn len(&self) -> usize {
        self.with(Instant::now(), |m| m.len())
    }

    /// Plans held at a simulated `now` (tests).
    pub fn len_at(&self, now: Instant) -> usize {
        self.with(now, |m| m.len())
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Start the [`SWEEP_TICK`] task (N-53): expired plans go even when nothing touches the
/// store and the vault stays unlocked.
pub fn install<R: tauri::Runtime>(app: &tauri::App<R>) {
    use tauri::Manager;
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let mut every = tokio::time::interval(SWEEP_TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            if let Some(state) = handle.try_state::<crate::state::AppState>() {
                state.import_plans.sweep(Instant::now());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ImportPlan {
        ImportPlan::default()
    }

    #[test]
    fn single_use_ttl_cap_and_clear() {
        let store = ImportPlans::default();
        let t0 = Instant::now();
        let id = store.insert(plan(), ImportFormat::Termius, HashMap::new(), t0);
        assert_eq!(id.len(), PLAN_ID_LEN);
        assert!(store.take("zz", t0).is_err());
        assert!(store.take(&"0".repeat(32), t0).is_err());
        let held = store.take(&id, t0 + Duration::from_secs(1)).expect("once");
        assert_eq!(held.format, ImportFormat::Termius);
        assert_eq!(store.take(&id, t0).expect_err("used").code, "import.plan_expired");
        let id = store.insert(plan(), ImportFormat::Putty, HashMap::new(), t0);
        assert!(store.take(&id, t0 + PLAN_TTL).is_err());
        for _ in 0..MAX_PLANS + 2 {
            store.insert(plan(), ImportFormat::Putty, HashMap::new(), t0);
        }
        assert_eq!(store.len(), MAX_PLANS);
        store.clear();
        assert!(store.is_empty());
    }

    /// Review 7 N-53: an expired plan is dropped by any access (a `len`, a `take` of another
    /// id, a sweep), not only by the next insert.
    #[test]
    fn expired_plans_are_swept_on_every_access() {
        let store = ImportPlans::default();
        let t0 = Instant::now();
        let old = store.insert(plan(), ImportFormat::Termius, HashMap::new(), t0);
        let fresh = store.insert(plan(), ImportFormat::Putty, HashMap::new(), t0 + PLAN_TTL / 2);
        assert_eq!(store.len_at(t0 + PLAN_TTL / 2), 2);
        // A take of the fresh plan's id at a later time sweeps the old one first.
        assert_eq!(store.len_at(t0 + PLAN_TTL), 1, "the old plan expired");
        assert_eq!(store.take(&old, t0 + PLAN_TTL).expect_err("gone").code, "import.plan_expired");
        store.sweep(t0 + PLAN_TTL + PLAN_TTL / 2);
        assert_eq!(store.len_at(t0 + PLAN_TTL + PLAN_TTL / 2), 0, "the sweep dropped the fresh one too");
        assert_eq!(store.take(&fresh, t0 + PLAN_TTL + PLAN_TTL / 2).expect_err("swept").code, "import.plan_expired");
        assert_eq!(SWEEP_TICK, Duration::from_secs(60));
    }
}
