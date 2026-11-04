//! Credit-based back-pressure and counters for the frame pump (ADR-0011: at most 2 messages
//! in flight, credit returned by `session_frame_ack`).

use std::collections::VecDeque;

/// Most `MFR1` messages sent and not yet acknowledged.
pub const MAX_IN_FLIGHT: usize = 2;

/// Sequence numbers and credits of one session's frame channel.
///
/// The pump calls [`Self::reserve`] before [`super::FrameSink::take_frame`]; `None` means no
/// credit, so it leaves the changes accumulating in the framebuffer (the UI later gets one
/// newer frame instead of a queue). `session_frame_ack(seq)` calls [`Self::ack`], which is
/// cumulative: it releases `seq` and every older message still in flight.
#[derive(Debug, Clone)]
pub struct FrameCredits {
    in_flight: VecDeque<u32>,
    next: u32,
    max: usize,
}

impl Default for FrameCredits {
    fn default() -> Self {
        Self::new(MAX_IN_FLIGHT)
    }
}

impl FrameCredits {
    /// `max` credits (clamped to 1..=[`MAX_IN_FLIGHT`]). Sequence numbers start at 1.
    pub fn new(max: usize) -> Self {
        Self { in_flight: VecDeque::new(), next: 1, max: max.clamp(1, MAX_IN_FLIGHT) }
    }

    /// Whether a message may be sent now.
    pub fn available(&self) -> bool {
        self.in_flight.len() < self.max
    }

    /// Take a credit and the sequence number for the next message, or `None` without credit.
    /// Sequence numbers wrap and skip 0.
    pub fn reserve(&mut self) -> Option<u32> {
        if !self.available() {
            return None;
        }
        let seq = self.next;
        self.next = self.next.wrapping_add(1).max(1);
        self.in_flight.push_back(seq);
        Some(seq)
    }

    /// Give back a credit that was reserved but not used (nothing changed after all).
    pub fn cancel(&mut self, seq: u32) {
        if self.in_flight.back() == Some(&seq) {
            self.in_flight.pop_back();
        }
    }

    /// Acknowledge `seq` and every older message. `false` (and no change) when `seq` is not
    /// in flight: a stale, duplicate or forged ack never creates credit.
    pub fn ack(&mut self, seq: u32) -> bool {
        let Some(pos) = self.in_flight.iter().position(|s| *s == seq) else {
            return false;
        };
        self.in_flight.drain(..=pos);
        true
    }

    /// Messages in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Drop all in-flight messages (the UI channel was replaced, e.g. on re-attach).
    pub fn reset(&mut self) {
        self.in_flight.clear();
    }
}

/// Counters for one session's frame path (logs, `frame_bench`). No pixel data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameStats {
    /// Messages sent.
    pub frames: u64,
    /// Of which full repaints.
    pub full_frames: u64,
    /// Records sent.
    pub rects: u64,
    /// Bytes sent.
    pub bytes: u64,
    /// Largest message.
    pub max_message: u64,
    /// Ticks that had changes but no credit (back-pressure).
    pub throttled: u64,
}

impl FrameStats {
    /// Count one sent message.
    pub fn record_sent(&mut self, bytes: usize, records: u16, full: bool) {
        let bytes = bytes as u64;
        self.frames += 1;
        self.full_frames += u64::from(full);
        self.rects += u64::from(records);
        self.bytes += bytes;
        self.max_message = self.max_message.max(bytes);
    }

    /// Count one tick skipped for lack of credit.
    pub fn record_throttled(&mut self) {
        self.throttled += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_in_flight_then_cumulative_ack() {
        let mut c = FrameCredits::default();
        assert_eq!(c.reserve(), Some(1));
        assert_eq!(c.reserve(), Some(2));
        assert_eq!(c.reserve(), None, "third message waits");
        assert!(!c.ack(7), "unknown seq creates no credit");
        assert!(c.ack(2), "cumulative");
        assert_eq!(c.in_flight(), 0);
        assert!(!c.ack(1), "already released");
        assert_eq!(c.reserve(), Some(3));
        c.cancel(3);
        assert_eq!(c.in_flight(), 0);
    }

    #[test]
    fn sequence_wraps_and_skips_zero() {
        let mut c = FrameCredits::new(5);
        c.next = u32::MAX;
        assert_eq!(c.reserve(), Some(u32::MAX));
        assert_eq!(c.reserve(), Some(1));
        assert_eq!(c.reserve(), None, "clamped to MAX_IN_FLIGHT");
        c.reset();
        assert!(c.available());
    }

    #[test]
    fn stats_accumulate() {
        let mut s = FrameStats::default();
        s.record_sent(100, 2, false);
        s.record_sent(400, 1, true);
        s.record_throttled();
        assert_eq!(
            s,
            FrameStats {
                frames: 2,
                full_frames: 1,
                rects: 3,
                bytes: 500,
                max_message: 400,
                throttled: 1
            }
        );
    }
}
