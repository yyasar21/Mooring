//! Vault-sync runtime (ADR-0017 §3, A3 S2): the single-flight [`SyncHub`] shared by the
//! `sync_*` commands and the background interval runner.
//!
//! * One run at a time: `sync_now`, `sync_resolve_fork`, `sync_disable`, `sync_configure`,
//!   `vault_join` and the runner take [`SyncHub::try_begin`]; a second caller gets
//!   `sync.in_progress`.
//! * The runner wakes every [`TICK`]. While the vault is not unlocked it schedules nothing and
//!   aborts its own in-flight run (a command's run fails on its next vault access with
//!   `vault.locked`). After an unlock the first run comes within [`UNLOCK_JITTER`], then every
//!   `intervalMinutes` plus up to [`INTERVAL_JITTER`]. Manual-only configs and pending fork /
//!   rollback alarms schedule nothing.
//! * Every change of the computed [`SyncStatus`] is emitted as [`STATUS_EVENT`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mooring_sync::{Conflict, Outcome};
use rand_core::{OsRng, RngCore};
use tauri::{Emitter, Manager, Runtime};

use crate::commands::sync::SyncStatus;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// UI event carrying the new [`SyncStatus`].
pub const STATUS_EVENT: &str = "sync:status";
/// Runner wake-up period.
pub const TICK: Duration = Duration::from_secs(5);
/// Largest delay of the first run after an unlock.
pub const UNLOCK_JITTER: Duration = Duration::from_secs(30);
/// Largest extra delay added to each interval.
pub const INTERVAL_JITTER: Duration = Duration::from_secs(60);

/// Receives every new status (the app emits it; tests collect it).
pub type StatusSink = Box<dyn Fn(&SyncStatus) + Send + Sync>;

/// What one runner tick decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing to do.
    Idle,
    /// Start a run now.
    Run,
    /// The vault is not unlocked: stop the runner's in-flight run.
    Abort,
}

/// When the next background run is due (pure; driven by [`SyncHub::tick`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct Schedule {
    next: Option<Instant>,
}

impl Schedule {
    /// One decision at `now`. `jitter` is in `0..=1` (fraction of the jitter windows).
    pub fn tick(
        &mut self,
        now: Instant,
        unlocked: bool,
        interval: Option<Duration>,
        blocked: bool,
        busy: bool,
        jitter: f64,
    ) -> Tick {
        if !unlocked {
            self.next = None;
            return if busy { Tick::Abort } else { Tick::Idle };
        }
        let Some(interval) = interval.filter(|_| !blocked) else {
            self.next = None;
            return Tick::Idle;
        };
        let j = jitter.clamp(0.0, 1.0);
        let due = *self.next.get_or_insert_with(|| now + UNLOCK_JITTER.mul_f64(j));
        if now >= due && !busy {
            self.next = Some(now + interval + INTERVAL_JITTER.mul_f64(j));
            Tick::Run
        } else {
            Tick::Idle
        }
    }

    /// Forget the due time (config changed, alarm resolved): the next tick reschedules.
    pub fn reset(&mut self) {
        self.next = None;
    }

    /// The due time, if any.
    pub fn next(&self) -> Option<Instant> {
        self.next
    }
}

#[derive(Debug, Default)]
struct Inner {
    last_run_unix: Option<u64>,
    last_outcome: Option<Outcome>,
    last_error: Option<IpcError>,
    conflicts: Vec<Conflict>,
    schedule: Schedule,
    last_emitted: Option<String>,
    task: Option<tokio::task::AbortHandle>,
}

/// What the status shows from the hub.
#[derive(Debug, Clone, Default)]
pub struct HubView {
    /// A run is in flight.
    pub running: bool,
    /// Unix seconds of the last finished run.
    pub last_run_unix: Option<u64>,
    /// Its outcome.
    pub last_outcome: Option<Outcome>,
    /// Its error.
    pub last_error: Option<IpcError>,
    /// Conflicts of the last merge.
    pub conflicts: Vec<Conflict>,
    /// Unix seconds of the next background run.
    pub next_run_unix: Option<u64>,
}

/// Single-flight state, last outcome and schedule (managed by Tauri).
pub struct SyncHub {
    busy: AtomicBool,
    inner: Mutex<Inner>,
    emitter: Mutex<Option<StatusSink>>,
    device_name: String,
}

impl std::fmt::Debug for SyncHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncHub").field("busy", &self.busy.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

/// Held while a run is in flight.
#[derive(Debug)]
pub struct Flight<'a>(&'a SyncHub);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// This device's display name: the host name, printable ASCII only, ≤ 64 bytes.
pub fn default_device_name() -> String {
    let name: String = crate::commands::syslog::local_hostname()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-._ ".contains(*c))
        .take(64)
        .collect();
    if name.trim().is_empty() { "Mooring device".to_owned() } else { name }
}

impl SyncHub {
    /// A hub naming this device `device_name` in blobs and conflict copies.
    pub fn new(device_name: &str) -> Self {
        Self {
            busy: AtomicBool::new(false),
            inner: Mutex::default(),
            emitter: Mutex::new(None),
            device_name: device_name.to_owned(),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.inner.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Device display name.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Set the status receiver.
    pub fn set_emitter(&self, e: StatusSink) {
        *self.emitter.lock().unwrap_or_else(PoisonError::into_inner) = Some(e);
    }

    /// Start a run, or `sync.in_progress`.
    pub fn try_begin(&self) -> IpcResult<Flight<'_>> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Flight(self))
            .map_err(|_| IpcError::new("sync.in_progress", "a sync is already running"))
    }

    /// Whether a run is in flight.
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::Acquire)
    }

    /// Record a finished run.
    pub fn finish(&self, result: &IpcResult<Outcome>) {
        self.with(|i| {
            i.last_run_unix = Some(unix_now());
            match result {
                Ok(o) => {
                    if let Outcome::Merged { conflicts, .. } = o {
                        i.conflicts.clone_from(conflicts);
                    }
                    i.last_outcome = Some(o.clone());
                    i.last_error = None;
                }
                Err(e) => i.last_error = Some(e.clone()),
            }
        });
    }

    /// Forget outcomes and schedule (`sync_disable`, a new config).
    pub fn reset(&self) {
        self.with(|i| {
            let task = i.task.take();
            *i = Inner { last_emitted: i.last_emitted.take(), ..Inner::default() };
            if let Some(t) = task {
                t.abort();
            }
        });
    }

    /// Reschedule from the next tick (config or alarm changed).
    pub fn reschedule(&self) {
        self.with(|i| i.schedule.reset());
    }

    /// The hub part of the status.
    pub fn view(&self, now: Instant) -> HubView {
        let running = self.busy();
        self.with(|i| HubView {
            running,
            last_run_unix: i.last_run_unix,
            last_outcome: i.last_outcome.clone(),
            last_error: i.last_error.clone(),
            conflicts: i.conflicts.clone(),
            next_run_unix: i
                .schedule
                .next()
                .map(|t| unix_now() + t.saturating_duration_since(now).as_secs()),
        })
    }

    /// One schedule decision; `Abort` also aborts the runner's task.
    pub fn tick(&self, now: Instant, unlocked: bool, interval: Option<Duration>, blocked: bool) -> Tick {
        let jitter = f64::from(OsRng.next_u32() % 1001) / 1000.0;
        let busy = self.busy();
        let t = self.with(|i| i.schedule.tick(now, unlocked, interval, blocked, busy, jitter));
        if t == Tick::Abort {
            if let Some(task) = self.with(|i| i.task.take()) {
                tracing::info!("vault locked: background sync stopped");
                task.abort();
            }
        }
        t
    }

    /// Remember the runner's task so a lock can abort it.
    pub fn set_task(&self, task: tokio::task::AbortHandle) {
        self.with(|i| i.task = Some(task));
    }

    /// Emit `status` when it differs from the last one emitted.
    pub fn emit(&self, status: &SyncStatus) {
        let text = serde_json::to_string(status).unwrap_or_default();
        let changed = self.with(|i| {
            let changed = i.last_emitted.as_deref() != Some(text.as_str());
            i.last_emitted = Some(text);
            changed
        });
        if changed {
            if let Some(e) = self.emitter.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                e(status);
            }
        }
    }
}

/// Emit the current status of `state` (skipped while locked: the status needs the store).
pub fn emit_status(state: &AppState, hub: &SyncHub) {
    if let Ok(s) = crate::commands::sync::status(state, hub) {
        hub.emit(&s);
    }
}

/// One runner tick: decide, and start a background run (no prompter) when due.
pub fn runner_tick(state: &AppState, hub: &SyncHub, now: Instant) -> Tick {
    let unlocked = matches!(crate::commands::vault::status(state), Ok(crate::commands::vault::VaultStatus::Unlocked));
    let (interval, blocked) = if unlocked {
        crate::commands::sync::schedule_inputs(state).unwrap_or((None, true))
    } else {
        (None, false)
    };
    hub.tick(now, unlocked, interval, blocked)
}

/// Manage the hub and start the [`TICK`] loop.
pub fn install<R: Runtime>(app: &tauri::App<R>) {
    let hub = SyncHub::new(&default_device_name());
    let handle = app.handle().clone();
    hub.set_emitter(Box::new(move |s| {
        if let Err(e) = handle.emit(STATUS_EVENT, s) {
            tracing::warn!(error = %e, "sync:status emit failed");
        }
    }));
    app.manage(hub);
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            let (Some(state), Some(hub)) = (handle.try_state::<AppState>(), handle.try_state::<SyncHub>()) else {
                continue;
            };
            if runner_tick(&state, &hub, Instant::now()) != Tick::Run {
                continue;
            }
            let app = handle.clone();
            // Inside the Tauri (Tokio) runtime: a Tokio task gives an abort handle.
            let task = tokio::spawn(async move {
                let (Some(state), Some(hub)) = (app.try_state::<AppState>(), app.try_state::<SyncHub>()) else {
                    return;
                };
                if let Err(e) = crate::commands::sync::run_once(&state, &hub, None, None).await {
                    tracing::info!(code = e.code, "background sync did not complete");
                }
            });
            hub.set_task(task.abort_handle());
        }
    });
}

#[cfg(test)]
#[path = "sync_runner_tests.rs"]
mod tests;
