//! Per-window budget of audited navigation refusals (review 6 N-43).
//!
//! A hostile page looping `location = …` would otherwise write one hash-chained audit row
//! per refusal without bound. Each web / OIDC window audits its first [`AUDITED`] refusals
//! one by one, then counts; the window's close writes one `…_suppressed { count }` row. An
//! OIDC window is closed outright at [`OIDC_FLOOD`] refusals (`failed: navigation_flood`).

use std::sync::atomic::{AtomicU32, Ordering};

/// Refusals that get a row of their own per window.
pub const AUDITED: u32 = 16;
/// Refusals after which an OIDC window is closed.
pub const OIDC_FLOOD: u32 = 64;

/// The counter of one window.
#[derive(Debug, Default)]
pub struct RefusalBudget(AtomicU32);

impl RefusalBudget {
    /// Count one refusal; `true` when it still gets its own audit row.
    pub fn refused(&self) -> bool {
        let n = self.0.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        n <= AUDITED
    }

    /// Refusals so far.
    pub fn total(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }

    /// Refusals that got no row of their own (the close-time summary).
    pub fn suppressed(&self) -> u32 {
        self.total().saturating_sub(AUDITED)
    }

    /// Whether the OIDC flood limit is reached.
    pub fn flooded(&self) -> bool {
        self.total() >= OIDC_FLOOD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sixteen_are_audited_then_counted() {
        let b = RefusalBudget::default();
        assert_eq!(b.suppressed(), 0);
        for i in 1..=AUDITED {
            assert!(b.refused(), "refusal {i} is audited");
        }
        for _ in 0..10 {
            assert!(!b.refused(), "beyond the budget: counted only");
        }
        assert_eq!((b.total(), b.suppressed(), b.flooded()), (26, 10, false));
        while !b.flooded() {
            b.refused();
        }
        assert_eq!(b.total(), OIDC_FLOOD);
    }
}
