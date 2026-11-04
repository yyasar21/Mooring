//! Token-bucket rate limit and jittered retry backoff.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::time::Instant;

use crate::config::{RateLimit, RetryPolicy};

/// A token bucket: `burst` tokens, refilled at `rps` per second. `acquire` waits outside the
/// lock, so callers queue fairly enough for a handful of concurrent requests.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    rps: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    pub(crate) fn new(rate: RateLimit) -> Self {
        let burst = f64::from(rate.burst);
        Self { rps: rate.rps, burst, state: Mutex::new((burst, Instant::now())) }
    }

    /// Take a token now, or say how long to wait for one.
    pub(crate) fn try_take(&self, now: Instant) -> Result<(), Duration> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = now.saturating_duration_since(st.1).as_secs_f64();
        st.0 = (st.0 + elapsed * self.rps).min(self.burst);
        st.1 = now;
        if st.0 >= 1.0 {
            st.0 -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - st.0) / self.rps))
        }
    }

    pub(crate) async fn acquire(&self) {
        loop {
            match self.try_take(Instant::now()) {
                Ok(()) => return,
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }
}

/// Backoff before attempt `attempt + 1` (`attempt` ≥ 1): uniform in `0..=min(max, base·2ⁿ⁻¹)`.
pub(crate) fn backoff(policy: &RetryPolicy, attempt: u32) -> Duration {
    let exp = policy.base_delay.saturating_mul(1u32 << attempt.saturating_sub(1).min(16));
    let ceiling = exp.min(policy.max_delay);
    let nanos = u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX);
    if nanos == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(OsRng.next_u64() % (nanos + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_paces() {
        let b = TokenBucket::new(RateLimit { rps: 2.0, burst: 3 });
        let t0 = Instant::now();
        for _ in 0..3 {
            b.try_take(t0).expect("burst");
        }
        let wait = b.try_take(t0).expect_err("empty");
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "{wait:?}");
        b.try_take(t0 + Duration::from_millis(500)).expect("refilled one");
        assert!(b.try_take(t0 + Duration::from_millis(500)).is_err());
        // Refill never exceeds the burst.
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            b.try_take(later).expect("full again");
        }
        assert!(b.try_take(later).is_err());
    }

    #[test]
    fn backoff_is_bounded() {
        let p = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(300),
        };
        for attempt in 1..40 {
            let d = backoff(&p, attempt);
            assert!(d <= Duration::from_millis(300), "{attempt}: {d:?}");
            if attempt == 1 {
                assert!(d <= Duration::from_millis(100));
            }
        }
        let zero = RetryPolicy { base_delay: Duration::ZERO, ..p };
        assert_eq!(backoff(&zero, 3), Duration::ZERO);
    }
}
