//! Import plans held between `import_preview` and `import_apply` (ADR-0019 §3). A plan may
//! carry plaintext secrets (opt-in), so it never crosses IPC: the `WebView` sees a random
//! 128-bit `planId` and names only. A plan is
//! * single-use: `import_apply` and `import_discard` take it;
//! * valid for [`PLAN_TTL`];
//! * capped at [`MAX_PLANS`] (oldest dropped first);
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

impl ImportPlans {
    fn with<T>(&self, f: impl FnOnce(&mut HashMap<String, HeldPlan>) -> T) -> T {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Store a plan and return its `planId`.
    pub fn insert(
        &self,
        plan: ImportPlan,
        format: ImportFormat,
        duplicates: HashMap<String, String>,
        now: Instant,
    ) -> String {
        self.with(|m| {
            m.retain(|_, p| now.saturating_duration_since(p.created) < PLAN_TTL);
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
        self.with(|m| {
            let p = m.remove(plan_id).ok_or_else(expired)?;
            if now.saturating_duration_since(p.created) >= PLAN_TTL {
                return Err(expired());
            }
            Ok(p)
        })
    }

    /// Drop every plan (vault lock); secrets are zeroized by the plan's drop.
    pub fn clear(&self) {
        self.with(HashMap::clear);
    }

    /// Plans held (tests).
    pub fn len(&self) -> usize {
        self.with(|m| m.len())
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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
}
