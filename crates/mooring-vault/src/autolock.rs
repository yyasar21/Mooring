//! Auto-lock policy and clock (ADR-0006). Pure: the caller supplies `now` and OS signals.

use std::time::{Duration, Instant};

/// Default idle timeout.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(15 * 60);

/// When the vault locks without user action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLockPolicy {
    /// Lock after this much inactivity; `None` disables the idle trigger.
    pub idle: Option<Duration>,
    /// Lock when the OS screen locks.
    pub on_screen_lock: bool,
    /// Lock when the OS goes to sleep.
    pub on_sleep: bool,
    /// Lock when the main window is hidden / minimised.
    pub on_window_hidden: bool,
}

impl Default for AutoLockPolicy {
    fn default() -> Self {
        Self {
            idle: Some(DEFAULT_IDLE),
            on_screen_lock: true,
            on_sleep: true,
            on_window_hidden: true,
        }
    }
}

/// Why the vault was locked. Logged by the caller as the audit `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockReason {
    /// The user asked.
    User,
    /// Idle timeout elapsed.
    Idle,
    /// The OS screen locked.
    ScreenLock,
    /// The OS went to sleep.
    Sleep,
    /// The main window was hidden.
    WindowHidden,
}

impl LockReason {
    /// Stable audit string: `user`, `idle`, `screen_lock`, `sleep`, `window_hidden`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Idle => "idle",
            Self::ScreenLock => "screen_lock",
            Self::Sleep => "sleep",
            Self::WindowHidden => "window_hidden",
        }
    }

    /// Parse the audit string; unknown input is `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "user" => Self::User,
            "idle" => Self::Idle,
            "screen_lock" => Self::ScreenLock,
            "sleep" => Self::Sleep,
            "window_hidden" => Self::WindowHidden,
            _ => return None,
        })
    }
}

impl std::fmt::Display for LockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OS / UI events fed into the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    /// User asked to lock.
    UserRequested,
    /// The OS screen locked.
    ScreenLocked,
    /// The OS is about to sleep.
    Sleeping,
    /// The main window was hidden or minimised.
    WindowHidden,
    /// The main window became visible / focused again (counts as activity).
    WindowShown,
}

/// Tracks the last activity and pending OS signals; answers whether to lock now.
#[derive(Debug, Clone)]
pub struct AutoLockClock {
    policy: AutoLockPolicy,
    last_activity: Instant,
    pending: Option<LockReason>,
}

impl AutoLockClock {
    /// Start the clock; `now` counts as activity.
    #[must_use]
    pub fn new(policy: AutoLockPolicy, now: Instant) -> Self {
        Self { policy, last_activity: now, pending: None }
    }

    /// The active policy.
    #[must_use]
    pub fn policy(&self) -> AutoLockPolicy {
        self.policy
    }

    /// Replace the policy; pending signals are kept.
    pub fn set_policy(&mut self, policy: AutoLockPolicy) {
        self.policy = policy;
    }

    /// Record user activity (any IPC command). Never moves the clock backwards.
    pub fn touch(&mut self, now: Instant) {
        if now > self.last_activity {
            self.last_activity = now;
        }
    }

    /// Feed an OS/UI event. Events whose trigger is disabled by the policy are ignored.
    pub fn signal(&mut self, event: LockEvent, now: Instant) {
        let reason = match event {
            LockEvent::UserRequested => Some(LockReason::User),
            LockEvent::ScreenLocked if self.policy.on_screen_lock => Some(LockReason::ScreenLock),
            LockEvent::Sleeping if self.policy.on_sleep => Some(LockReason::Sleep),
            LockEvent::WindowHidden if self.policy.on_window_hidden => {
                Some(LockReason::WindowHidden)
            }
            LockEvent::WindowShown => {
                self.touch(now);
                None
            }
            _ => None,
        };
        if reason.is_some() && self.pending.is_none() {
            self.pending = reason;
        }
    }

    /// Whether the vault should lock at `now`, and why. Pending OS signals win over idle.
    #[must_use]
    pub fn should_lock(&self, now: Instant) -> Option<LockReason> {
        if let Some(r) = self.pending {
            return Some(r);
        }
        let idle = self.policy.idle?;
        (now.saturating_duration_since(self.last_activity) >= idle).then_some(LockReason::Idle)
    }

    /// Call after the vault was locked (or unlocked): clears signals, restarts the idle timer.
    pub fn reset(&mut self, now: Instant) {
        self.pending = None;
        self.last_activity = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn defaults() {
        let p = AutoLockPolicy::default();
        assert_eq!(p.idle, Some(15 * MIN));
        assert!(p.on_screen_lock && p.on_sleep && p.on_window_hidden);
    }

    #[test]
    fn idle_table() {
        // (idle policy, activity offsets, query offset, expected)
        type Case<'a> = (Option<Duration>, &'a [Duration], Duration, Option<LockReason>);
        let cases: &[Case] = &[
            (Some(15 * MIN), &[], 14 * MIN, None),
            (Some(15 * MIN), &[], 15 * MIN, Some(LockReason::Idle)),
            (Some(15 * MIN), &[10 * MIN], 20 * MIN, None),
            (Some(15 * MIN), &[10 * MIN], 25 * MIN, Some(LockReason::Idle)),
            (Some(MIN), &[], Duration::ZERO, None),
            (None, &[], 1000 * MIN, None),
        ];
        let t0 = Instant::now();
        for (i, (idle, touches, at, want)) in cases.iter().enumerate() {
            let policy = AutoLockPolicy { idle: *idle, ..AutoLockPolicy::default() };
            let mut c = AutoLockClock::new(policy, t0);
            for d in *touches {
                c.touch(t0 + *d);
            }
            assert_eq!(c.should_lock(t0 + *at), *want, "case {i}");
        }
    }

    #[test]
    fn signal_table() {
        let all_off = AutoLockPolicy {
            idle: None,
            on_screen_lock: false,
            on_sleep: false,
            on_window_hidden: false,
        };
        let cases: &[(AutoLockPolicy, LockEvent, Option<LockReason>)] = &[
            (AutoLockPolicy::default(), LockEvent::UserRequested, Some(LockReason::User)),
            (AutoLockPolicy::default(), LockEvent::ScreenLocked, Some(LockReason::ScreenLock)),
            (AutoLockPolicy::default(), LockEvent::Sleeping, Some(LockReason::Sleep)),
            (AutoLockPolicy::default(), LockEvent::WindowHidden, Some(LockReason::WindowHidden)),
            (AutoLockPolicy::default(), LockEvent::WindowShown, None),
            (all_off, LockEvent::UserRequested, Some(LockReason::User)),
            (all_off, LockEvent::ScreenLocked, None),
            (all_off, LockEvent::Sleeping, None),
            (all_off, LockEvent::WindowHidden, None),
        ];
        let t0 = Instant::now();
        for (i, (policy, event, want)) in cases.iter().enumerate() {
            let mut c = AutoLockClock::new(*policy, t0);
            c.signal(*event, t0);
            assert_eq!(c.should_lock(t0), *want, "case {i}");
        }
    }

    #[test]
    fn first_signal_wins_and_reset_clears() {
        let t0 = Instant::now();
        let mut c = AutoLockClock::new(AutoLockPolicy::default(), t0);
        c.signal(LockEvent::Sleeping, t0);
        c.signal(LockEvent::ScreenLocked, t0);
        // signal wins over idle as well
        assert_eq!(c.should_lock(t0 + 60 * MIN), Some(LockReason::Sleep));
        c.reset(t0 + 60 * MIN);
        assert_eq!(c.should_lock(t0 + 61 * MIN), None);
    }

    #[test]
    fn window_shown_counts_as_activity_and_touch_is_monotonic() {
        let t0 = Instant::now();
        let mut c = AutoLockClock::new(AutoLockPolicy::default(), t0);
        c.signal(LockEvent::WindowShown, t0 + 10 * MIN);
        assert_eq!(c.should_lock(t0 + 20 * MIN), None);
        c.touch(t0); // earlier instant must not rewind
        assert_eq!(c.should_lock(t0 + 20 * MIN), None);
        assert_eq!(c.should_lock(t0 + 25 * MIN), Some(LockReason::Idle));
        // a query before the last activity never underflows
        assert_eq!(c.should_lock(t0), None);
    }

    #[test]
    fn reason_strings_round_trip() {
        for r in [
            LockReason::User,
            LockReason::Idle,
            LockReason::ScreenLock,
            LockReason::Sleep,
            LockReason::WindowHidden,
        ] {
            assert_eq!(LockReason::parse(r.as_str()), Some(r));
            assert_eq!(r.to_string(), r.as_str());
        }
        assert_eq!(LockReason::parse("reboot"), None);
    }
}
