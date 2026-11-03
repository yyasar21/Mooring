//! Auto-lock clock (ADR-0006): table-driven event sequences through the public API.
//! Complements the unit tables in `src/autolock.rs` with multi-step scenarios.

use std::time::{Duration, Instant};

use mooring_vault::{AutoLockClock, AutoLockPolicy, LockEvent, LockReason};
use proptest::prelude::*;

const MIN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
enum Step {
    Touch(Duration),
    Signal(LockEvent, Duration),
    Reset(Duration),
    Policy(AutoLockPolicy),
    Expect(Duration, Option<LockReason>),
}

use Step::{Expect, Policy, Reset, Signal, Touch};

const OFF: AutoLockPolicy =
    AutoLockPolicy { idle: None, on_screen_lock: false, on_sleep: false, on_window_hidden: false };

fn idle(d: Duration) -> AutoLockPolicy {
    AutoLockPolicy { idle: Some(d), ..AutoLockPolicy::default() }
}

fn run(name: &str, policy: AutoLockPolicy, steps: &[Step]) {
    let t0 = Instant::now();
    let mut c = AutoLockClock::new(policy, t0);
    for (i, s) in steps.iter().enumerate() {
        match *s {
            Touch(d) => c.touch(t0 + d),
            Signal(e, d) => c.signal(e, t0 + d),
            Reset(d) => c.reset(t0 + d),
            Policy(p) => c.set_policy(p),
            Expect(d, want) => assert_eq!(c.should_lock(t0 + d), want, "{name}: step {i}"),
        }
    }
}

#[test]
fn idle_and_signal_table() {
    let cases: &[(&str, AutoLockPolicy, &[Step])] = &[
        (
            "default policy locks exactly at 15 min of inactivity",
            AutoLockPolicy::default(),
            &[
                Expect(Duration::from_nanos(15 * 60 * 1_000_000_000 - 1), None),
                Expect(15 * MIN, Some(LockReason::Idle)),
            ],
        ),
        (
            "every touch restarts the idle window",
            idle(5 * MIN),
            &[
                Touch(4 * MIN),
                Touch(8 * MIN),
                Expect(12 * MIN, None),
                Expect(13 * MIN, Some(LockReason::Idle)),
            ],
        ),
        (
            "activity does not cancel a pending OS signal",
            AutoLockPolicy::default(),
            &[
                Signal(LockEvent::ScreenLocked, MIN),
                Touch(2 * MIN),
                Signal(LockEvent::WindowShown, 3 * MIN),
                Expect(3 * MIN, Some(LockReason::ScreenLock)),
            ],
        ),
        (
            "reset after a lock clears the signal and restarts idle",
            idle(10 * MIN),
            &[
                Signal(LockEvent::Sleeping, MIN),
                Expect(MIN, Some(LockReason::Sleep)),
                Reset(30 * MIN),
                Expect(39 * MIN, None),
                Expect(40 * MIN, Some(LockReason::Idle)),
            ],
        ),
    ];
    for (name, policy, steps) in cases {
        run(name, *policy, steps);
    }
}

#[test]
fn policy_and_ordering_table() {
    let cases: &[(&str, AutoLockPolicy, &[Step])] = &[
        (
            "user request always locks, even with every trigger off",
            OFF,
            &[
                Expect(10_000 * MIN, None),
                Signal(LockEvent::UserRequested, MIN),
                Expect(MIN, Some(LockReason::User)),
            ],
        ),
        (
            "disabled triggers are ignored, not queued for later",
            OFF,
            &[
                Signal(LockEvent::ScreenLocked, MIN),
                Signal(LockEvent::Sleeping, MIN),
                Signal(LockEvent::WindowHidden, MIN),
                Policy(AutoLockPolicy::default()),
                Expect(2 * MIN, None),
            ],
        ),
        (
            "set_policy keeps a pending signal (documented)",
            AutoLockPolicy::default(),
            &[
                Signal(LockEvent::WindowHidden, MIN),
                Policy(OFF),
                Expect(2 * MIN, Some(LockReason::WindowHidden)),
            ],
        ),
        (
            "shortening idle via set_policy takes effect immediately",
            AutoLockPolicy::default(),
            &[
                Expect(5 * MIN, None),
                Policy(idle(5 * MIN)),
                Expect(5 * MIN, Some(LockReason::Idle)),
            ],
        ),
        (
            "disabling idle via set_policy stops an overdue idle lock",
            idle(MIN),
            &[Expect(2 * MIN, Some(LockReason::Idle)), Policy(OFF), Expect(2 * MIN, None)],
        ),
        (
            "first OS signal wins over later ones",
            AutoLockPolicy::default(),
            &[
                Signal(LockEvent::WindowHidden, MIN),
                Signal(LockEvent::Sleeping, 2 * MIN),
                Signal(LockEvent::UserRequested, 3 * MIN),
                Expect(3 * MIN, Some(LockReason::WindowHidden)),
            ],
        ),
        (
            "a clock queried before its start never underflows",
            idle(Duration::ZERO),
            &[Touch(10 * MIN), Expect(Duration::ZERO, Some(LockReason::Idle))],
        ),
        (
            "out-of-order touch does not rewind activity",
            idle(10 * MIN),
            &[
                Touch(20 * MIN),
                Touch(5 * MIN),
                Expect(29 * MIN, None),
                Expect(30 * MIN, Some(LockReason::Idle)),
            ],
        ),
    ];
    for (name, policy, steps) in cases {
        run(name, *policy, steps);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// With no OS signals, the clock locks iff `now - last_touch >= idle`.
    #[test]
    fn idle_only_matches_the_reference_model(
        idle_s in 1u64..3600,
        touches in proptest::collection::vec(0u64..10_000, 0..20),
        query in 0u64..20_000,
    ) {
        let t0 = Instant::now();
        let secs = Duration::from_secs;
        let mut c = AutoLockClock::new(idle(secs(idle_s)), t0);
        for t in &touches {
            c.touch(t0 + secs(*t));
        }
        let last = touches.iter().copied().max().unwrap_or(0);
        let want = (query.saturating_sub(last) >= idle_s).then_some(LockReason::Idle);
        prop_assert_eq!(c.should_lock(t0 + secs(query)), want);
    }
}
