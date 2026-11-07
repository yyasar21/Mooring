//! Auto-lock wiring (ADR-0006, ADR-0010 §Auto-lock): feeds activity and OS/window signals into
//! the pure [`AutoLockClock`] and locks the vault when it says so.
//!
//! * Activity: every IPC command except the status polls in [`PASSIVE_COMMANDS`] touches the
//!   clock, from one hook in the invoke handler ([`on_invoke`]).
//! * Tick: every [`TICK`] a task calls [`tick`]; it also detects a suspended machine (a wall
//!   clock jump of more than [`SLEEP_GAP`] beyond the monotonic clock, or a tick that arrives
//!   [`SLEEP_GAP`] late) and treats it as `sleep`. The suspended time is added to the idle
//!   clock, because `Instant` does not advance during suspend on Linux and macOS.
//! * Window: `Focused(false)` on the main window → `window_hidden` after [`BLUR_GRACE`],
//!   `Focused(true)` → activity. While a Mooring-owned native dialog is open
//!   ([`AutoLock::dialog_guard`], the SFTP pick) focus loss is ignored, for at most
//!   [`DIALOG_EXEMPTION`] after the first open dialog was opened (review 4, N-20), and the grace
//!   restarts when the dialog closes.
//! * Tauri 2 exposes no OS sleep or screen-lock `RunEvent` on desktop; see the per-OS table in
//!   `docs/handoff/a1-exit-rust-core-autolock-syslog.md`.
//!
//! A lock writes the audit entry `vault_locked { reason }` (through `commands::vault::lock`) and
//! emits the UI event [`LOCKED_EVENT`] `{ reason }`.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use mooring_vault::autolock::{AutoLockClock, AutoLockPolicy, LockEvent};
use mooring_vault::LockReason;
use serde::Serialize;
use tauri::{Emitter, Manager, Runtime};

use crate::commands::vault::{self, VaultStatus};
use crate::state::AppState;

/// Tick period.
pub const TICK: Duration = Duration::from_secs(5);
/// A gap this much larger than expected between two ticks means the machine was suspended.
pub const SLEEP_GAP: Duration = Duration::from_secs(30);
/// How long the main window may stay unfocused before `window_hidden` fires (review 4, M-9):
/// an alt-tab or a notification does not lock, a screen lock (which takes focus) does within a
/// minute. Focus loss while a Mooring-owned native dialog is open is not counted at all.
pub const BLUR_GRACE: Duration = Duration::from_secs(60);
/// Longest time focus loss is ignored for an open Mooring dialog (review 4, N-20): the pick
/// TTL. A picker left open (or opened by a hostile `WebView`) does not suspend the
/// `window_hidden` lock beyond it; after it, focus loss counts again with [`BLUR_GRACE`].
pub const DIALOG_EXEMPTION: Duration = crate::picks::PICK_TTL;
/// UI event emitted after an automatic lock.
pub const LOCKED_EVENT: &str = "vault:locked";
/// Commands the UI calls on a timer or to render status; they are not user activity. Exported
/// to the UI as `src-tauri/ipc-passive.json` (`POLLED_COMMANDS`, review 4 M-8): a poller that
/// calls anything else would keep the vault from ever idle-locking.
pub const PASSIVE_COMMANDS: &[&str] = &[
    "app_info",
    "vault_status",
    "audit_verify",
    "session_list",
    "forward_list",
    "sftp_transfers",
    "autolock_get",
    "syslog_get",
    // ADR-0011: one ack per frame message (≤ 60/s) is not user activity.
    "session_frame_ack",
    // ADR-0013: polled by the web-session list (R5).
    "web_list",
    // ADR-0014 K4: polled by the cluster browser.
    "kube_access",
    "kube_namespaces",
    "kube_pods",
    // ADR-0017 (A3 S2): the sync badge polls it.
    "sync_status",
    // ADR-0015: sync status and VM power badges (cached / last refresh).
    "vsphere_status",
    "vsphere_vm_power",
    // ADR-0016 E2: polled while the OIDC window is open.
    "secret_source_oidc_status",
    // ADR-0022: the Settings toggle and the unlock screen read it.
    "biometric_status",
];

/// Payload of [`LOCKED_EVENT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LockedPayload {
    /// `idle` | `screen_lock` | `sleep` | `window_hidden`.
    pub reason: &'static str,
}

#[derive(Debug)]
struct Inner {
    clock: AutoLockClock,
    /// Suspended time detected so far; added to `Instant` readings.
    suspended: Duration,
    last_mono: Instant,
    last_wall: SystemTime,
    /// When the main window lost focus, while it is still unfocused.
    blurred_at: Option<Instant>,
    /// Mooring-owned native dialogs open right now (`sftp_pick_local`).
    dialogs: u32,
    /// When the oldest of the open dialogs was opened (`dialogs > 0`).
    dialog_since: Option<Instant>,
}

impl Inner {
    fn effective(&self, now: Instant) -> Instant {
        now + self.suspended
    }

    /// Whether focus loss is exempt now: a dialog is open, for less than [`DIALOG_EXEMPTION`].
    fn dialog_exempt(&self, now: Instant) -> bool {
        self.dialogs > 0
            && self
                .dialog_since
                .is_some_and(|t| now.saturating_duration_since(t) < DIALOG_EXEMPTION)
    }
}

/// Held while a Mooring-owned native dialog is open (see [`AutoLock::dialog_guard`]).
#[derive(Debug)]
pub struct DialogGuard<'a> {
    al: &'a AutoLock,
}

impl Drop for DialogGuard<'_> {
    fn drop(&mut self) {
        self.al.dialog_closed(Instant::now());
    }
}

/// Managed state: the clock plus suspend and focus bookkeeping.
#[derive(Debug)]
pub struct AutoLock {
    inner: Mutex<Inner>,
}

impl AutoLock {
    /// Start with `policy`; `now` counts as activity.
    pub fn new(policy: AutoLockPolicy, now: Instant, wall: SystemTime) -> Self {
        Self {
            inner: Mutex::new(Inner {
                clock: AutoLockClock::new(policy, now),
                suspended: Duration::ZERO,
                last_mono: now,
                last_wall: wall,
                blurred_at: None,
                dialogs: 0,
                dialog_since: None,
            }),
        }
    }

    /// Mark a Mooring-owned native dialog as open until the guard is dropped.
    pub fn dialog_guard(&self) -> DialogGuard<'_> {
        self.dialog_guard_at(Instant::now())
    }

    /// [`dialog_guard`](Self::dialog_guard) opened at `now` (tests drive a simulated clock).
    pub fn dialog_guard_at(&self, now: Instant) -> DialogGuard<'_> {
        self.with(|i| {
            if i.dialogs == 0 {
                i.dialog_since = Some(now);
            }
            i.dialogs += 1;
        });
        DialogGuard { al: self }
    }

    /// Whether a Mooring-owned native dialog is open.
    pub fn dialog_open(&self) -> bool {
        self.with(|i| i.dialogs > 0)
    }

    /// The dialog closed: choosing in it was user activity, and a window that is still
    /// unfocused starts its blur grace now.
    fn dialog_closed(&self, now: Instant) {
        self.with(|i| {
            i.dialogs = i.dialogs.saturating_sub(1);
            if i.dialogs == 0 {
                i.dialog_since = None;
            }
            // `observe` keeps moving `blurred_at` forward while the dialog is open; never move
            // it back.
            if let Some(b) = i.blurred_at {
                i.blurred_at = Some(b.max(now));
            }
            let t = i.effective(now);
            i.clock.touch(t);
        });
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        // A poisoned clock mutex only means a panic elsewhere mid-update; the data is plain.
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// The active policy.
    pub fn policy(&self) -> AutoLockPolicy {
        self.with(|i| i.clock.policy())
    }

    /// Replace the policy (pending signals are kept).
    pub fn set_policy(&self, policy: AutoLockPolicy) {
        self.with(|i| i.clock.set_policy(policy));
    }

    /// User activity.
    pub fn touch(&self, now: Instant) {
        self.with(|i| {
            let t = i.effective(now);
            i.clock.touch(t);
        });
    }

    /// Main window focus changed.
    pub fn focus_changed(&self, focused: bool, now: Instant) {
        self.with(|i| {
            if focused {
                i.blurred_at = None;
                let t = i.effective(now);
                i.clock.signal(LockEvent::WindowShown, t);
            } else if i.blurred_at.is_none() {
                i.blurred_at = Some(now);
            }
        });
    }

    /// Feed an OS event directly (sleep / screen lock from a platform hook). No native hook is
    /// wired yet (see the handoff); tests use it.
    #[allow(dead_code)]
    pub fn signal(&self, event: LockEvent, now: Instant) {
        self.with(|i| {
            let t = i.effective(now);
            i.clock.signal(event, t);
        });
    }

    /// Advance the bookkeeping to (`now`, `wall`) and answer whether to lock.
    pub fn observe(&self, now: Instant, wall: SystemTime) -> Option<LockReason> {
        self.with(|i| {
            let mono = now.saturating_duration_since(i.last_mono);
            // A wall clock running backwards (NTP, user) is never a suspend.
            let wall_d = wall.duration_since(i.last_wall).unwrap_or(Duration::ZERO);
            let hidden = wall_d.saturating_sub(mono);
            let late = mono.saturating_sub(TICK);
            if hidden > SLEEP_GAP || late > SLEEP_GAP {
                tracing::info!(secs = hidden.max(late).as_secs(), "suspend detected");
                i.suspended += hidden;
                let t = i.effective(now);
                i.clock.signal(LockEvent::Sleeping, t);
            }
            i.last_mono = now;
            i.last_wall = wall;
            let exempt = i.dialog_exempt(now);
            if exempt && i.blurred_at.is_some() {
                // Focus loss to a Mooring dialog is not counted (M-9), for a bounded time (N-20).
                i.blurred_at = Some(now);
            }
            let blur_expired =
                i.blurred_at.is_some_and(|b| now.saturating_duration_since(b) >= BLUR_GRACE);
            if blur_expired && !exempt {
                let t = i.effective(now);
                i.clock.signal(LockEvent::WindowHidden, t);
            }
            i.clock.should_lock(i.effective(now))
        })
    }

    /// Clear pending signals and restart the idle timer.
    pub fn reset(&self, now: Instant) {
        self.with(|i| {
            let t = i.effective(now);
            i.clock.reset(t);
        });
    }
}

/// One evaluation: lock the vault if the clock says so and the vault is unlocked. Returns the
/// reason when a lock happened. While the vault is not unlocked, signals are discarded so a
/// stale `window_hidden` cannot lock a vault right after the user unlocks it.
pub fn tick(state: &AppState, al: &AutoLock, now: Instant, wall: SystemTime) -> Option<LockReason> {
    let reason = al.observe(now, wall);
    if !matches!(vault::status(state), Ok(VaultStatus::Unlocked)) {
        al.reset(now);
        return None;
    }
    let reason = reason?;
    let locked = vault::lock(state, Some(reason.as_str()));
    al.reset(now);
    match locked {
        Ok(_) => {
            tracing::info!(reason = reason.as_str(), "vault auto-locked");
            Some(reason)
        }
        Err(e) => {
            tracing::error!(code = e.code, "auto-lock failed");
            None
        }
    }
}

/// Whether an IPC command counts as user activity.
pub fn is_activity(command: &str) -> bool {
    !PASSIVE_COMMANDS.contains(&command)
}

/// Invoke-handler hook: touch the clock for every non-passive command.
pub fn on_invoke<R: Runtime>(invoke: &tauri::ipc::Invoke<R>) {
    if !is_activity(invoke.message.command()) {
        return;
    }
    if let Some(al) = invoke.message.webview_ref().try_state::<AutoLock>() {
        al.touch(Instant::now());
    }
}

fn run_tick<R: Runtime>(app: &tauri::AppHandle<R>) {
    let (Some(state), Some(al)) = (app.try_state::<AppState>(), app.try_state::<AutoLock>())
    else {
        return;
    };
    if let Some(reason) = tick(&state, &al, Instant::now(), SystemTime::now()) {
        if let Err(e) = app.emit(LOCKED_EVENT, LockedPayload { reason: reason.as_str() }) {
            tracing::warn!(error = %e, "vault:locked emit failed");
        }
    }
}

/// Whether focus of this window counts as the app being in front: `main`, and the web and
/// detached windows (ADR-0013), so working in one of them does not start the blur grace.
pub fn tracks_focus(label: &str) -> bool {
    label == crate::navigation::MAIN_WINDOW || crate::window_lock::is_secondary(label)
}

/// Builder `on_window_event` hook: focus of the app's windows. Moving focus from one Mooring
/// window to another is a blur immediately followed by a focus, which clears the grace.
pub fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &tauri::WindowEvent) {
    if !tracks_focus(window.label()) {
        return;
    }
    if let tauri::WindowEvent::Focused(focused) = event {
        if let Some(al) = window.try_state::<AutoLock>() {
            al.focus_changed(*focused, Instant::now());
        }
        if !*focused {
            // Evaluate at once instead of waiting up to one tick, off the event-loop thread:
            // the vault mutex may be held by an unlock running Argon2id.
            let app = window.app_handle().clone();
            tauri::async_runtime::spawn_blocking(move || run_tick(&app));
        }
    }
}

/// Manage the clock (policy loaded from the store) and start the [`TICK`] task.
pub fn install<R: Runtime>(app: &tauri::App<R>) {
    let policy = {
        let state = app.state::<AppState>();
        crate::commands::autolock::load_policy(&state)
    };
    app.manage(AutoLock::new(policy, Instant::now(), SystemTime::now()));
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            run_tick(&handle);
        }
    });
}

#[cfg(test)]
#[path = "autolock_tests.rs"]
mod tests;
