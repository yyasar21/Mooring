//! Reconnect policy of graphical sessions (ADR-0011 §Session behaviour, shared with VNC):
//! retry only `network` / `server_ended` after a `Connected`, never after a user close; the
//! backoff is 1, 2, 4, 8, 16, 30 units with ±20 % jitter, at most 6 attempts.

use std::time::Duration;

use mooring_core::CloseCode;
use rand_core::{OsRng, RngCore};

/// Backoff multipliers of the unit (1 s in production), one per attempt.
pub const STEPS: [u32; 6] = [1, 2, 4, 8, 16, 30];
/// Most attempts after one drop.
pub const MAX_ATTEMPTS: u32 = 6;
/// Jitter, in per mille of the step (±20 %).
pub const JITTER_PERMILLE: u64 = 200;

/// Whether to schedule attempt `attempt + 1` after a close with `code`.
pub const fn should_retry(code: CloseCode, connected: bool, by_user: bool, attempt: u32) -> bool {
    code.is_retryable() && connected && !by_user && attempt < MAX_ATTEMPTS
}

/// Delay before `attempt` (1-based) with jitter from `roll` (any `u32`; uniform in
/// −20 %..=+20 %). `None` past [`MAX_ATTEMPTS`]. Capped at 30 units + 20 %.
pub fn delay(unit: Duration, attempt: u32, roll: u32) -> Option<Duration> {
    let idx = usize::try_from(attempt.checked_sub(1)?).ok()?;
    let step = u64::from(*STEPS.get(idx)?);
    let base = u64::try_from(unit.as_micros()).unwrap_or(u64::MAX).saturating_mul(step);
    let permille = 1000 - JITTER_PERMILLE + u64::from(roll) % (2 * JITTER_PERMILLE + 1);
    Some(Duration::from_micros(base.saturating_mul(permille) / 1000))
}

/// [`delay`] with an OS-random roll.
pub fn jittered(unit: Duration, attempt: u32) -> Option<Duration> {
    delay(unit, attempt, OsRng.next_u32())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_attempts_matches_the_steps() {
        assert_eq!(usize::try_from(MAX_ATTEMPTS).expect("small"), STEPS.len());
    }

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn schedule_is_1_2_4_8_16_30_without_jitter_and_stops_after_6() {
        let mid = u32::try_from(JITTER_PERMILLE).expect("small"); // roll % 401 == 200 → ±0
        let got: Vec<u64> =
            (1..=6).map(|a| delay(S, a, mid).expect("in range").as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 30]);
        assert_eq!(delay(S, 0, 0), None);
        assert_eq!(delay(S, 7, 0), None);
    }

    #[test]
    fn jitter_stays_within_20_percent_and_is_capped() {
        assert_eq!(delay(S, 1, 0), Some(Duration::from_millis(800)));
        assert_eq!(delay(S, 1, 400), Some(Duration::from_millis(1200)));
        assert_eq!(delay(S, 6, 400), Some(Duration::from_secs(36)), "cap: 30 s + 20 %");
        for _ in 0..200 {
            let d = jittered(S, 3).expect("attempt 3");
            assert!(d >= Duration::from_millis(3200) && d <= Duration::from_millis(4800), "{d:?}");
        }
        assert!(delay(Duration::MAX, 6, u32::MAX).is_some(), "no overflow panic");
    }

    #[test]
    fn only_network_and_server_ended_after_connected_are_retried() {
        use CloseCode as C;
        for code in [C::Network, C::ServerEnded] {
            assert!(should_retry(code, true, false, 0));
            assert!(should_retry(code, true, false, 5));
            assert!(!should_retry(code, true, false, 6), "at most 6 attempts");
            assert!(!should_retry(code, false, false, 0), "never before Connected");
            assert!(!should_retry(code, true, true, 0), "never after a user close");
        }
        for code in [
            C::User,
            C::AuthFailed,
            C::TrustRejected,
            C::TrustMismatch,
            C::ProtocolError,
            C::VaultLocked,
        ] {
            assert!(!should_retry(code, true, false, 0), "{code:?}");
        }
    }
}
