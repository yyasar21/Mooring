//! A per-process budget of audit rows for one noisy source (review 6b N-47, review 7 N-52):
//! the first [`AuditBudget::limit`] events of each window of process uptime get a row each;
//! the rest are counted and written as one `…_suppressed { count }` row when the next window
//! starts, so a T5 that loops a command cannot grow the hash chain without bound. The
//! confirm gate carries the same arithmetic inline; this is the reusable form for the `net_*`
//! commands.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many events of a window get their own row (`net_*`, N-52).
pub const NET_AUDITED: u32 = 32;
/// The budget window (process uptime).
pub const WINDOW: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct Inner {
    window: Instant,
    audited: u32,
    suppressed: u64,
}

/// The budget. `account` says whether an event gets its own row and whether a summary row
/// for the window that just closed is due.
#[derive(Debug)]
pub struct AuditBudget {
    inner: Mutex<Inner>,
    limit: u32,
    window: Duration,
}

/// What [`AuditBudget::account`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accounted {
    /// Write the event's own row.
    pub own_row: bool,
    /// Write a `…_suppressed { count }` row first (the previous window had `count` events
    /// without a row).
    pub summary: Option<u64>,
}

impl AuditBudget {
    /// A budget of `limit` rows per `window`, starting now.
    pub fn new(limit: u32, window: Duration) -> Self {
        Self::starting(limit, window, Instant::now())
    }

    /// [`new`](Self::new) at a simulated start (tests).
    pub fn starting(limit: u32, window: Duration, now: Instant) -> Self {
        Self { inner: Mutex::new(Inner { window: now, audited: 0, suppressed: 0 }), limit, window }
    }

    /// Account one event at `now`.
    pub fn account(&self, now: Instant) -> Accounted {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut summary = None;
        if now.saturating_duration_since(g.window) >= self.window {
            summary = (g.suppressed > 0).then_some(g.suppressed);
            g.window = now;
            g.audited = 0;
            g.suppressed = 0;
        }
        let own_row = if g.audited < self.limit {
            g.audited += 1;
            true
        } else {
            g.suppressed += 1;
            false
        };
        Accounted { own_row, summary }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_n_get_rows_then_one_summary_per_window() {
        let t0 = Instant::now();
        let b = AuditBudget::starting(3, Duration::from_secs(10), t0);
        for _ in 0..3 {
            assert_eq!(b.account(t0), Accounted { own_row: true, summary: None });
        }
        for _ in 0..5 {
            assert_eq!(b.account(t0 + Duration::from_secs(9)), Accounted { own_row: false, summary: None });
        }
        // The next window: summary of the five counted events, then a fresh budget.
        assert_eq!(b.account(t0 + Duration::from_secs(10)), Accounted { own_row: true, summary: Some(5) });
        assert_eq!(b.account(t0 + Duration::from_secs(10)), Accounted { own_row: true, summary: None });
        // A window with nothing suppressed writes no summary.
        assert_eq!(b.account(t0 + Duration::from_secs(25)), Accounted { own_row: true, summary: None });
        assert_eq!((NET_AUDITED, WINDOW), (32, Duration::from_secs(3600)));
    }
}
