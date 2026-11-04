//! Scheduled vCenter refreshes (ADR-0015 §2). One task per synced vCenter whose
//! `refreshMinutes` is set (15..=1440): sleep the interval ± 10 % jitter, then a single-flight
//! refresh that never prompts. The tasks run only while the vault is unlocked: they start on
//! unlock and on `vsphere_sync_enable`, stop on lock ([`crate::vsphere_sync::VsphereHub::on_lock`])
//! and exit by themselves when the vault is locked, the epoch changed, or sync was disabled.
//! They never touch the auto-lock idle clock (no IPC is involved).

use std::time::Duration;

use mooring_core::{ConnectionId, ProtocolOptions};
use rand_core::{OsRng, RngCore};

use crate::vsphere_sync::{self, Trigger, VsCtx};

/// The refresh interval of `source` from its options, `None` = manual only / not synced.
fn interval(ctx: &VsCtx, source: ConnectionId) -> Option<Duration> {
    let minutes = ctx
        .ready
        .with_ready(|_, store| {
            if store.sync_root(source)?.is_none() {
                return Ok(None);
            }
            Ok(match store.connection_options(source)? {
                ProtocolOptions::Vsphere(o) => o.refresh_minutes,
                _ => None,
            })
        })
        .ok()
        .flatten()?;
    Some(ctx.hub.minute().saturating_mul(minutes))
}

/// `base` ± 10 %.
pub fn jitter(base: Duration) -> Duration {
    let tenth = base / 10;
    let span = u64::try_from(tenth.as_micros()).unwrap_or(u64::MAX).saturating_mul(2);
    if span == 0 {
        return base;
    }
    let offset = Duration::from_micros(OsRng.next_u64() % span);
    base.saturating_sub(tenth) + offset
}

/// (Re)start the scheduler of `source` for the current epoch. A no-op while locked or when
/// the source has no interval.
pub fn ensure(ctx: &VsCtx, source: ConnectionId) {
    if !ctx.ready.unlocked() {
        return;
    }
    let id = source.to_string();
    let entry = ctx.hub.source(&id);
    let Ok(mut timer) = entry.timer.lock() else { return };
    if let Some(old) = timer.take() {
        old.abort();
    }
    if interval(ctx, source).is_none() {
        return;
    }
    let epoch = ctx.hub.epoch();
    let task_ctx = ctx.clone();
    *timer = Some(tauri::async_runtime::spawn(async move {
        while let Some(every) = interval(&task_ctx, source) {
            tokio::time::sleep(jitter(every)).await;
            if !task_ctx.ready.unlocked() || task_ctx.hub.epoch() != epoch {
                break;
            }
            if let Err(e) = vsphere_sync::refresh(&task_ctx, source, Trigger::Schedule, None).await {
                tracing::info!(code = e.code, "scheduled vCenter refresh failed");
            }
        }
    }));
}

/// Start the schedulers of every synced vCenter (after unlock).
pub fn start_all(ctx: &VsCtx) {
    let sources = ctx.ready.with_ready(|_, store| Ok(store.sync_sources()?)).unwrap_or_default();
    for s in sources {
        ensure(ctx, s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_ten_percent() {
        let base = Duration::from_secs(600);
        for _ in 0..200 {
            let j = jitter(base);
            assert!(j >= Duration::from_secs(540) && j < Duration::from_secs(660), "{j:?}");
        }
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }
}
