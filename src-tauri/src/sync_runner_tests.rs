use std::time::{Duration, Instant};

use super::*;

const MIN15: Duration = Duration::from_secs(15 * 60);

#[test]
fn first_run_follows_the_unlock_within_the_jitter_then_every_interval() {
    let t0 = Instant::now();
    let mut s = Schedule::default();
    assert_eq!(s.tick(t0, true, Some(MIN15), false, false, 0.5), Tick::Idle, "jittered");
    let due = s.next().expect("scheduled");
    assert!(due > t0 && due <= t0 + UNLOCK_JITTER);
    assert_eq!(s.tick(due, true, Some(MIN15), false, false, 0.5), Tick::Run);
    let next = s.next().expect("rescheduled");
    assert!(next >= due + MIN15 && next <= due + MIN15 + INTERVAL_JITTER);
    assert_eq!(s.tick(due + Duration::from_secs(60), true, Some(MIN15), false, false, 0.5), Tick::Idle);
    // Due while another run is in flight: wait for it, run on the next tick.
    assert_eq!(s.tick(next, true, Some(MIN15), false, true, 0.5), Tick::Idle);
    assert_eq!(s.tick(next, true, Some(MIN15), false, false, 0.5), Tick::Run);
}

#[test]
fn nothing_runs_while_locked_manual_only_or_blocked_by_an_alarm() {
    let t0 = Instant::now();
    let mut s = Schedule::default();
    assert_eq!(s.tick(t0, false, Some(MIN15), false, false, 0.0), Tick::Idle);
    assert_eq!(s.tick(t0, true, None, false, false, 0.0), Tick::Idle, "manual only");
    assert_eq!(s.tick(t0, true, Some(MIN15), true, false, 0.0), Tick::Idle, "alarm");
    assert!(s.next().is_none());
    // A lock while a run is in flight stops it and forgets the due time.
    assert_eq!(s.tick(t0, true, Some(MIN15), false, false, 0.0), Tick::Run);
    assert_eq!(s.tick(t0, false, Some(MIN15), false, true, 0.0), Tick::Abort);
    assert!(s.next().is_none(), "the next unlock schedules a fresh pull");
}

#[test]
fn the_hub_is_single_flight_and_emits_only_changes() {
    let hub = SyncHub::new("device-a");
    let f = hub.try_begin().expect("first");
    assert_eq!(hub.try_begin().expect_err("second").code, "sync.in_progress");
    drop(f);
    assert!(hub.try_begin().is_ok(), "released on drop");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(0));
    let s2 = std::sync::Arc::clone(&seen);
    hub.set_emitter(Box::new(move |_| *s2.lock().expect("l") += 1));
    let st = crate::commands::sync::SyncStatus {
        state: "idle",
        config: None,
        vault_id: String::new(),
        device_id: None,
        counter: 0,
        remote_counter: None,
        remote_device: None,
        remote_created_unix: None,
        last_pull_unix: None,
        last_push_unix: None,
        last_run_unix: None,
        last_outcome: None,
        last_error: None,
        alarm: None,
        conflicts: Vec::new(),
        next_run_unix: None,
    };
    hub.emit(&st);
    hub.emit(&st);
    let mut changed = st.clone();
    changed.counter = 1;
    hub.emit(&changed);
    assert_eq!(*seen.lock().expect("l"), 2);
}
