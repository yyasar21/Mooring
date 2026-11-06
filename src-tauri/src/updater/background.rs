//! Opt-in background check (ADR-0018 §3): earliest [`START_DELAY`] after start, then at most
//! once per [`PERIOD`] (measured from the stored `lastCheck`, so restarts do not reset it),
//! only while the vault is unlocked, only when `backgroundCheck` is on. It fetches the
//! manifest and emits `update:available`; it never downloads or installs.

use std::time::{Duration, Instant};

use tauri::{Emitter, Manager, Runtime};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::commands::update::{self, AVAILABLE_EVENT};
use crate::state::AppState;
use crate::updater::UpdateRuntime;

/// Loop wake-up period.
pub const TICK: Duration = Duration::from_secs(60);
/// No check before this much process uptime.
pub const START_DELAY: Duration = Duration::from_secs(60);
/// Smallest gap between two background checks.
pub const PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// What one tick sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickInput {
    /// Process uptime at the tick.
    pub uptime: Duration,
    /// `backgroundCheck` setting.
    pub enabled: bool,
    /// Vault unlocked.
    pub unlocked: bool,
    /// Wall-clock now.
    pub now: OffsetDateTime,
    /// Stored `lastCheck`, parsed.
    pub last_check: Option<OffsetDateTime>,
}

/// Whether a check is due (pure).
pub fn due(t: &TickInput) -> bool {
    if !t.enabled || !t.unlocked || t.uptime < START_DELAY {
        return false;
    }
    match t.last_check {
        None => true,
        // A `lastCheck` in the future (clock moved back) counts as "just checked".
        Some(last) => t.now - last >= PERIOD,
    }
}

/// Parse the stored RFC 3339 `lastCheck`; unreadable → `None` (a check is due).
pub fn parse_last_check(raw: Option<&str>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(raw?, &Rfc3339).ok()
}

/// Spawn the loop. Does nothing when no source is configured.
pub fn install<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    if !handle.state::<UpdateRuntime>().configured() {
        tracing::info!("updater not configured (no pubkey); background check off");
        return;
    }
    let started = Instant::now();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            let state = handle.state::<AppState>();
            let rt = handle.state::<UpdateRuntime>();
            let settings = update::stored(&state);
            let input = TickInput {
                uptime: started.elapsed(),
                enabled: settings.background_check,
                unlocked: state.ready().unlocked(),
                now: OffsetDateTime::now_utc(),
                last_check: parse_last_check(settings.last_check.as_deref()),
            };
            if !due(&input) {
                continue;
            }
            match update::check(&state, &rt, Instant::now(), false).await {
                Ok(info) if info.available.is_some() => {
                    if let Err(e) = handle.emit(AVAILABLE_EVENT, &info) {
                        tracing::warn!(error = %e, "update:available not emitted");
                    }
                }
                Ok(_) => tracing::debug!("background update check: up to date"),
                // busy / rate_limited / network: the next due tick retries.
                Err(e) => tracing::debug!(code = e.code, "background update check skipped"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(uptime_s: u64, last_ago_s: Option<i64>) -> TickInput {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("ts");
        TickInput {
            uptime: Duration::from_secs(uptime_s),
            enabled: true,
            unlocked: true,
            now,
            last_check: last_ago_s.map(|s| now - time::Duration::seconds(s)),
        }
    }

    #[test]
    fn due_only_after_the_start_delay_and_once_per_period() {
        assert!(!due(&input(59, None)), "before the start delay");
        assert!(due(&input(60, None)), "never checked");
        assert!(!due(&input(600, Some(3600))), "checked an hour ago");
        assert!(!due(&input(600, Some(86_399))), "one second short");
        assert!(due(&input(600, Some(86_400))), "exactly a day");
        assert!(due(&input(600, Some(400_000))), "long ago");
        assert!(!due(&input(600, Some(-3600))), "lastCheck in the future: clock moved back");
    }

    #[test]
    fn off_or_locked_never_runs() {
        let mut t = input(600, None);
        t.enabled = false;
        assert!(!due(&t));
        t.enabled = true;
        t.unlocked = false;
        assert!(!due(&t));
    }

    #[test]
    fn last_check_parsing() {
        assert!(parse_last_check(None).is_none());
        assert!(parse_last_check(Some("yesterday")).is_none());
        let t = parse_last_check(Some("2026-11-06T10:00:00Z")).expect("rfc3339");
        assert_eq!(t.unix_timestamp(), 1_793_959_200);
    }
}
