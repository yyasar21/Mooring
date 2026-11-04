//! Per-session frame pump (ADR-0011 §Frame path): waits for [`FrameSink::changed`], takes at
//! most one coalesced MFR1 message per tick (`1000 / maxFps` ms), and keeps at most
//! [`MAX_IN_FLIGHT`](mooring_core::frame::credit::MAX_IN_FLIGHT) messages unacknowledged. A
//! slow UI gets fewer, newer frames: dirty rects keep merging in the framebuffer while the
//! pump waits for a credit, so nothing queues.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mooring_core::frame::{FrameCredits, FrameSink, FrameStats};
use tokio::sync::Notify;
use tokio::time::Instant;

/// Where MFR1 messages go (a raw `Channel` in the app). Returns `false` when the UI is gone.
pub type FrameOut = Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync>;

/// Default tick (30 fps).
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(33);

/// Credits shared between the pump and `session_frame_ack`.
#[derive(Debug, Clone, Default)]
pub struct FrameFlow {
    credits: Arc<Mutex<FrameCredits>>,
    acked: Arc<Notify>,
}

impl FrameFlow {
    /// Return credit for `seq` and everything before it. A forged or stale `seq` is ignored
    /// (`false`) and creates no credit.
    pub fn ack(&self, seq: u32) -> bool {
        let ok = self.credits().ack(seq);
        if ok {
            self.acked.notify_one();
        }
        ok
    }

    /// Forget every message in flight (`session_attach`: the old view never acks them).
    pub fn reset(&self) {
        self.credits().reset();
        self.acked.notify_one();
    }

    /// Messages sent and not yet acknowledged.
    pub fn in_flight(&self) -> usize {
        self.credits().in_flight()
    }

    fn credits(&self) -> std::sync::MutexGuard<'_, FrameCredits> {
        self.credits.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait for a credit and reserve the next sequence number.
    async fn reserve(&self, stats: &Mutex<FrameStats>) -> u32 {
        loop {
            // `notify_one` leaves a permit when nobody waits, so an ack between the check and
            // the await is not lost.
            if let Some(seq) = self.credits().reserve() {
                return seq;
            }
            stats.lock().unwrap_or_else(PoisonError::into_inner).record_throttled();
            self.acked.notified().await;
        }
    }
}

/// The pump. [`FramePump::run`] ends when the UI side of `out` is gone.
pub struct FramePump {
    /// Framebuffer written by the protocol.
    pub sink: FrameSink,
    /// Credits.
    pub flow: FrameFlow,
    /// Raw channel.
    pub out: FrameOut,
    /// Minimum time between two messages.
    pub interval: Duration,
    /// Counters (read by tests and the bench).
    pub stats: Arc<Mutex<FrameStats>>,
}

impl std::fmt::Debug for FramePump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramePump").field("interval", &self.interval).finish_non_exhaustive()
    }
}

/// `(records, full)` from an MFR1 header (`n` at 12, `flags` at 14).
fn header_info(msg: &[u8]) -> (u16, bool) {
    let n = msg.get(12..14).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
    let flags = msg.get(14..16).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
    (n, flags & mooring_core::frame::mfr1::FLAG_FULL != 0)
}

impl FramePump {
    /// A pump over `sink` with fresh credits.
    pub fn new(sink: FrameSink, flow: FrameFlow, out: FrameOut, interval: Duration) -> Self {
        Self { sink, flow, out, interval, stats: Arc::default() }
    }

    /// Run until `out` reports the UI gone.
    pub async fn run(self) {
        let mut last: Option<Instant> = None;
        loop {
            self.sink.changed().await;
            if let Some(t) = last {
                tokio::time::sleep_until(t + self.interval).await;
            }
            let seq = self.flow.reserve(&self.stats).await;
            // The tick starts before encoding, so encode time does not stretch the cadence.
            let tick = Instant::now();
            let Some(msg) = self.sink.take_frame(seq) else {
                self.flow.credits().cancel(seq);
                continue;
            };
            last = Some(tick);
            let (records, full) = header_info(&msg);
            let len = msg.len();
            if !(self.out)(msg) {
                tracing::debug!("frame channel gone; pump stops");
                return;
            }
            self.stats.lock().unwrap_or_else(PoisonError::into_inner).record_sent(
                len, records, full,
            );
        }
    }
}

#[cfg(test)]
#[path = "frame_pump_tests.rs"]
mod tests;
