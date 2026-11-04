//! [`FrameSink`]: the handle a protocol crate writes frames through.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use super::{encode_update, Cursor, Framebuffer, PixelOrder, Rect};
use crate::error::Result;

#[derive(Debug, Default)]
struct FrameShared {
    fb: Mutex<Framebuffer>,
    notify: Notify,
}

/// Cloneable handle to one session's framebuffer (`Mutex<Framebuffer>` + `Notify`).
///
/// The protocol side calls `resize` / `blit` / `copy` / `fill` / `cursor`; each successful
/// change wakes the pump. The pump side calls [`Self::changed`] and [`Self::take_frame`].
/// Every method locks briefly and never blocks on the UI.
#[derive(Debug, Clone, Default)]
pub struct FrameSink(Arc<FrameShared>);

impl FrameSink {
    /// A sink over an empty 0×0 framebuffer; the protocol calls [`Self::resize`] once the
    /// desktop size is known.
    pub fn new() -> Self {
        Self::default()
    }

    fn fb(&self) -> MutexGuard<'_, Framebuffer> {
        self.0.fb.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wake(&self) {
        self.0.notify.notify_one();
    }

    fn changed_by<T>(&self, op: impl FnOnce(&mut Framebuffer) -> Result<T>) -> Result<T> {
        let out = op(&mut self.fb())?;
        self.wake();
        Ok(out)
    }

    /// Resize (each side ≤ 8192), clearing to black; the next frame is full + resized.
    pub fn resize(&self, w: u16, h: u16) -> Result<()> {
        self.changed_by(|fb| fb.resize(w, h))
    }

    /// Copy pixels from a protocol buffer. Out-of-bounds or short source → `Err`.
    pub fn blit(&self, r: Rect, src: &[u8], stride: usize, order: PixelOrder) -> Result<()> {
        self.changed_by(|fb| fb.blit(r, src, stride, order))
    }

    /// Screen-to-screen copy (RFB `CopyRect`). Out-of-bounds → `Err`.
    pub fn copy(&self, dst: Rect, src_x: u16, src_y: u16) -> Result<()> {
        self.changed_by(|fb| fb.copy(dst, src_x, src_y))
    }

    /// Solid fill. Out-of-bounds → `Err`.
    pub fn fill(&self, r: Rect, rgba: [u8; 4]) -> Result<()> {
        self.changed_by(|fb| fb.fill(r, rgba))
    }

    /// Change the pointer shape (an invalid sprite becomes the default cursor).
    pub fn cursor(&self, c: Cursor) {
        self.fb().set_cursor(c);
        self.wake();
    }

    /// Force the next frame to be full (the UI re-attached, e.g. after a window detach).
    pub fn invalidate(&self) {
        self.fb().invalidate();
        self.wake();
    }

    /// Current framebuffer size.
    pub fn size(&self) -> (u16, u16) {
        let fb = self.fb();
        (fb.width(), fb.height())
    }

    /// Wait until something changed since the last [`Self::take_frame`]. A change made while
    /// nobody waits is remembered (one permit), so no wake-up is lost. For a single pump task.
    /// Stale wake-ups (a permit left by a change that was already taken) are absorbed here, so
    /// on return something is pending unless another task took it.
    pub async fn changed(&self) {
        loop {
            if self.fb().has_pending() {
                return;
            }
            self.0.notify.notified().await;
        }
    }

    /// Take the coalesced changes as one `MFR1` message with sequence number `seq`, or `None`
    /// when nothing changed. The caller holds a credit ([`super::FrameCredits`]).
    pub fn take_frame(&self, seq: u32) -> Option<Vec<u8>> {
        let mut fb = self.fb();
        if !fb.has_pending() {
            return None;
        }
        let update = fb.take_update();
        Some(encode_update(seq, &fb, &update))
    }

    /// Copy of the whole framebuffer `(width, height, rgba)` for `session_screenshot`.
    pub fn snapshot(&self) -> (u16, u16, Vec<u8>) {
        let fb = self.fb();
        (fb.width(), fb.height(), fb.pixels().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{decode_mfr1, Mfr1Record};

    #[tokio::test]
    async fn blit_wakes_the_pump_and_frame_round_trips() {
        let sink = FrameSink::new();
        sink.resize(4, 2).expect("resize");
        sink.changed().await; // pending from the resize
        let first = decode_mfr1(&sink.take_frame(1).expect("frame")).expect("decodes");
        assert!(first.is_full() && first.is_resized());
        assert!(sink.take_frame(2).is_none(), "nothing pending");

        let pump = {
            let sink = sink.clone();
            tokio::spawn(async move {
                sink.changed().await;
                sink.take_frame(2)
            })
        };
        tokio::task::yield_now().await;
        sink.blit(Rect::new(1, 0, 1, 1), &[9, 8, 7, 6], 4, PixelOrder::Bgra).expect("blit");
        let msg = pump.await.expect("join").expect("frame");
        let f = decode_mfr1(&msg).expect("decodes");
        assert_eq!(f.seq, 2);
        assert!(!f.is_full());
        assert_eq!(
            f.records,
            vec![Mfr1Record::Rgba { rect: Rect::new(1, 0, 1, 1), data: vec![7, 8, 9, 6] }]
        );
    }

    #[test]
    fn out_of_bounds_is_an_error_not_a_panic() {
        let sink = FrameSink::new();
        sink.resize(8, 8).expect("resize");
        assert!(sink.fill(Rect::new(7, 7, 2, 1), [0; 4]).is_err());
        assert!(sink.copy(Rect::new(0, 0, 4, 4), 6, 6).is_err());
        assert!(sink.blit(Rect::new(0, 0, 2, 2), &[0; 15], 8, PixelOrder::Rgba).is_err());
        assert!(sink.resize(8193, 1).is_err());
        assert_eq!(sink.size(), (8, 8));
    }

    #[test]
    fn snapshot_and_invalidate() {
        let sink = FrameSink::new();
        sink.resize(2, 1).expect("resize");
        sink.fill(Rect::new(0, 0, 2, 1), [1, 2, 3, 4]).expect("fill");
        let _ = sink.take_frame(1);
        let (w, h, px) = sink.snapshot();
        assert_eq!((w, h, px), (2, 1, vec![1, 2, 3, 4, 1, 2, 3, 4]));
        sink.invalidate();
        let f = decode_mfr1(&sink.take_frame(2).expect("frame")).expect("decodes");
        assert!(f.is_full() && !f.is_resized());
    }
}
