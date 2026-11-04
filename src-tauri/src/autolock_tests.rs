//! Auto-lock wiring with a fake clock: every test passes `Instant` / `SystemTime` explicitly.

use std::time::{Duration, Instant, SystemTime};

use mooring_vault::{AutoLockPolicy, LockReason};

use super::*;
use crate::state::testing::*;

const MIN: Duration = Duration::from_secs(60);
const S: Duration = Duration::from_secs(1);

fn policy(idle: Option<Duration>, sleep: bool, hidden: bool) -> AutoLockPolicy {
    AutoLockPolicy { idle, on_screen_lock: true, on_sleep: sleep, on_window_hidden: hidden }
}

struct Clock {
    mono: Instant,
    wall: SystemTime,
}

impl Clock {
    fn new() -> Self {
        Self { mono: Instant::now(), wall: SystemTime::now() }
    }
    /// Normal running time: both clocks advance.
    fn run(&mut self, d: Duration) -> (Instant, SystemTime) {
        self.mono += d;
        self.wall += d;
        (self.mono, self.wall)
    }
    /// Suspended time: only the wall clock advances (Linux / macOS `Instant`).
    fn suspend(&mut self, d: Duration) -> (Instant, SystemTime) {
        self.wall += d;
        (self.mono, self.wall)
    }
}

fn status(f: &Fixture) -> VaultStatus {
    vault::status(&f.state).expect("status")
}

fn lock_reasons(f: &Fixture) -> Vec<String> {
    let text = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"] == "vault_locked")
        .map(|v| v["reason"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// Tick every 5 s from the clock's current time up to `until` past it.
fn run_ticks(f: &Fixture, al: &AutoLock, c: &mut Clock, until: Duration) -> Option<LockReason> {
    let mut elapsed = Duration::ZERO;
    while elapsed < until {
        let (m, w) = c.run(TICK);
        elapsed += TICK;
        if let Some(r) = tick(&f.state, al, m, w) {
            return Some(r);
        }
    }
    None
}

#[test]
fn idle_tick_locks_once_and_audits_the_reason() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(MIN), true, true), c.mono, c.wall);
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None);
    assert_eq!(status(&f), VaultStatus::Unlocked);
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * S), Some(LockReason::Idle));
    assert_eq!(status(&f), VaultStatus::Locked);
    // further ticks on a locked vault write nothing
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * MIN), None);
    assert_eq!(lock_reasons(&f), ["idle"]);
}

#[test]
fn activity_defers_the_idle_lock() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(MIN), true, true), c.mono, c.wall);
    assert_eq!(run_ticks(&f, &al, &mut c, 50 * S), None);
    al.touch(c.mono);
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None, "touch restarted the minute");
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * S), Some(LockReason::Idle));
}

#[test]
fn focus_loss_locks_as_window_hidden_after_the_grace_and_focus_counts_as_activity() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(15 * MIN), true, true), c.mono, c.wall);
    al.focus_changed(false, c.mono);
    assert_eq!(tick(&f.state, &al, c.mono, c.wall), None, "an alt-tab does not lock");
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None, "55 s < BLUR_GRACE");
    assert_eq!(BLUR_GRACE, 60 * S);
    let (m, w) = c.run(5 * S);
    assert_eq!(tick(&f.state, &al, m, w), Some(LockReason::WindowHidden), "at 60 s = BLUR_GRACE");
    assert_eq!(lock_reasons(&f), ["window_hidden"]);

    // focus back + unlock: no stale signal, and focus counted as activity
    al.focus_changed(true, c.mono);
    vault::unlock(&f.state, secrecy::SecretString::from(MASTER.to_owned())).expect("unlock");
    al.set_policy(policy(Some(MIN), true, true));
    assert_eq!(run_ticks(&f, &al, &mut c, 50 * S), None);
    al.focus_changed(true, c.mono); // e.g. after a click elsewhere and back
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None, "focus restarted the minute");
    assert_eq!(status(&f), VaultStatus::Unlocked);
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * S), Some(LockReason::Idle));
}

#[test]
fn a_short_blur_does_not_lock() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(None, true, true), c.mono, c.wall);
    al.focus_changed(false, c.mono);
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None);
    al.focus_changed(true, c.mono);
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * MIN), None, "focus came back in time");
    assert_eq!(status(&f), VaultStatus::Unlocked);
}

#[test]
fn focus_loss_during_a_native_dialog_does_not_lock() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(None, true, true), c.mono, c.wall);
    {
        let _pick = al.dialog_guard();
        al.focus_changed(false, c.mono); // the dialog takes focus
        assert!(al.dialog_open());
        assert_eq!(run_ticks(&f, &al, &mut c, 5 * MIN), None, "the user is choosing a file");
    }
    assert!(!al.dialog_open());
    // The window is still unfocused after the dialog: the grace starts when it closed.
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None);
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * S), Some(LockReason::WindowHidden));
}

/// Review 4, N-20: a dialog left open exempts focus loss for at most `DIALOG_EXEMPTION`.
#[test]
fn the_dialog_exemption_is_bounded() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(None, true, true), c.mono, c.wall);
    assert_eq!(DIALOG_EXEMPTION, crate::picks::PICK_TTL);
    let _pick = al.dialog_guard_at(c.mono);
    al.focus_changed(false, c.mono);
    assert_eq!(run_ticks(&f, &al, &mut c, DIALOG_EXEMPTION.saturating_sub(5 * S)), None, "still exempt");
    // the exemption ends; the last exempt tick restarted the grace
    assert_eq!(run_ticks(&f, &al, &mut c, 55 * S), None, "within BLUR_GRACE after it");
    assert_eq!(run_ticks(&f, &al, &mut c, 10 * S), Some(LockReason::WindowHidden));
    assert!(al.dialog_open(), "locked while the dialog is still open");
}

/// A second dialog opened later does not extend the first one's exemption.
#[test]
fn overlapping_dialogs_do_not_extend_the_exemption() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(None, true, true), c.mono, c.wall);
    let first = al.dialog_guard_at(c.mono);
    al.focus_changed(false, c.mono);
    assert_eq!(run_ticks(&f, &al, &mut c, 8 * MIN), None);
    let _second = al.dialog_guard_at(c.mono);
    drop(first);
    // `first` closing restarts the grace once, then the 10 min bound from `first` still holds
    assert_eq!(run_ticks(&f, &al, &mut c, 2 * MIN + 65 * S), Some(LockReason::WindowHidden));
}

#[test]
fn focus_loss_is_ignored_when_the_policy_says_so() {
    let f = unlocked();
    let c = Clock::new();
    let al = AutoLock::new(policy(None, true, false), c.mono, c.wall);
    al.focus_changed(false, c.mono);
    assert_eq!(tick(&f.state, &al, c.mono, c.wall), None);
    assert_eq!(status(&f), VaultStatus::Unlocked);
}

#[test]
fn signals_while_locked_are_discarded() {
    let f = unlocked();
    vault::lock(&f.state, None).expect("lock");
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(MIN), true, true), c.mono, c.wall);
    al.signal(LockEvent::ScreenLocked, c.mono);
    assert_eq!(tick(&f.state, &al, c.mono, c.wall), None);
    vault::unlock(&f.state, secrecy::SecretString::from(MASTER.to_owned())).expect("unlock");
    al.touch(c.mono);
    let (m, w) = c.run(TICK);
    assert_eq!(tick(&f.state, &al, m, w), None, "the old screen-lock signal is gone");
    assert_eq!(lock_reasons(&f), ["user"]);
}

#[test]
fn suspend_is_detected_from_the_wall_clock() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(15 * MIN), true, true), c.mono, c.wall);
    run_ticks(&f, &al, &mut c, MIN);
    let (m, w) = c.suspend(10 * MIN);
    assert_eq!(tick(&f.state, &al, m, w), Some(LockReason::Sleep));
    assert_eq!(lock_reasons(&f), ["sleep"]);
}

#[test]
fn a_late_tick_is_a_suspend_too() {
    // Windows-style: the monotonic clock kept running but no tick fired for two minutes.
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(15 * MIN), true, true), c.mono, c.wall);
    let (m, w) = c.run(2 * MIN);
    assert_eq!(tick(&f.state, &al, m, w), Some(LockReason::Sleep));
}

#[test]
fn suspended_time_counts_as_idle_when_sleep_lock_is_off() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(Some(15 * MIN), false, true), c.mono, c.wall);
    let (m, w) = c.suspend(10 * MIN);
    assert_eq!(tick(&f.state, &al, m, w), None, "10 min < 15 min");
    let (m, w) = c.suspend(6 * MIN);
    assert_eq!(tick(&f.state, &al, m, w), Some(LockReason::Idle), "16 min asleep");
}

#[test]
fn small_jitter_and_a_backwards_wall_clock_are_not_suspends() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(None, true, true), c.mono, c.wall);
    let (m, w) = c.suspend(20 * S);
    assert_eq!(tick(&f.state, &al, m, w), None, "under SLEEP_GAP");
    c.wall -= 3600 * S; // NTP / user moved the clock back an hour
    let (m, w) = c.run(TICK);
    assert_eq!(tick(&f.state, &al, m, w), None);
    assert_eq!(status(&f), VaultStatus::Unlocked);
}

#[test]
fn set_policy_takes_effect_on_the_next_tick() {
    let f = unlocked();
    let mut c = Clock::new();
    let al = AutoLock::new(policy(None, true, true), c.mono, c.wall);
    assert_eq!(run_ticks(&f, &al, &mut c, 30 * MIN), None, "idle off");
    al.set_policy(policy(Some(MIN), true, true));
    let (m, w) = c.run(TICK);
    assert_eq!(tick(&f.state, &al, m, w), Some(LockReason::Idle), "already idle 30 min");
}

#[test]
fn no_vault_never_locks() {
    let f = empty();
    let c = Clock::new();
    let al = AutoLock::new(policy(Some(MIN), true, true), c.mono, c.wall);
    al.signal(LockEvent::Sleeping, c.mono);
    assert_eq!(tick(&f.state, &al, c.mono + 10 * MIN, c.wall), None);
}

#[test]
fn passive_commands_are_not_activity() {
    for cmd in PASSIVE_COMMANDS {
        assert!(!is_activity(cmd), "{cmd}");
    }
    for cmd in ["forward_list", "sftp_transfers"] {
        assert!(!is_activity(cmd), "{cmd} is polled by the Forwards / Files panels (M-8)");
    }
    for cmd in ["vault_unlock", "session_send", "tree_list", "autolock_set", "syslog_set", ""] {
        assert!(is_activity(cmd), "{cmd}");
    }
    assert!(!is_activity("session_frame_ack"), "one ack per frame (ADR-0011, U1 contract)");
    for cmd in ["session_attach", "session_screenshot", "known_certs_remove", "connection_options_set"]
    {
        assert!(is_activity(cmd), "{cmd}");
    }
    for cmd in ["forward_open", "forward_close", "sftp_download", "sftp_pick_local"] {
        assert!(is_activity(cmd), "{cmd}");
    }
}

#[test]
fn golden_passive_commands_file_is_in_sync() {
    crate::golden::check_sorted_list("ipc-passive.json", PASSIVE_COMMANDS);
}

#[test]
fn locked_payload_wire_shape() {
    let p = LockedPayload { reason: LockReason::WindowHidden.as_str() };
    assert_eq!(serde_json::to_string(&p).expect("json"), r#"{"reason":"window_hidden"}"#);
}
