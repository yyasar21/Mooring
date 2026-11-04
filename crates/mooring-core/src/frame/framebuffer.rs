//! The RGBA framebuffer and its dirty-rectangle tracking.

use super::{
    check_dims, frame_err, Cursor, PixelOrder, Rect, COALESCE_MAX_RECTS, FULL_AREA_PERCENT,
};
use crate::error::Result;

/// Pixel written by [`Framebuffer::resize`]: opaque black.
const CLEAR: [u8; 4] = [0, 0, 0, 255];

/// What changed since the last [`Framebuffer::take_update`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameUpdate {
    /// The whole framebuffer is sent (more than 32 rects, more than 60 % of the area, or a
    /// resize). `rects` is then exactly one rectangle covering the framebuffer (none when it is
    /// 0×0).
    pub full: bool,
    /// The framebuffer size changed since the previous update.
    pub resized: bool,
    /// Disjoint dirty rectangles, each inside the framebuffer.
    pub rects: Vec<Rect>,
    /// A cursor change, latest wins.
    pub cursor: Option<Cursor>,
}

impl FrameUpdate {
    /// Nothing to send.
    pub fn is_empty(&self) -> bool {
        !self.full && !self.resized && self.rects.is_empty() && self.cursor.is_none()
    }
}

/// An RGBA framebuffer, ≤ 8192 × 8192, with dirty tracking.
///
/// Dirty rectangles are kept pairwise disjoint: a new rectangle that overlaps a tracked one is
/// merged into their bounding box (repeatedly, until it overlaps none). The set therefore
/// always covers every written pixel, and its total area never exceeds the framebuffer.
#[derive(Clone, Default)]
pub struct Framebuffer {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
    dirty: Vec<Rect>,
    full: bool,
    resized: bool,
    cursor: Option<Cursor>,
}

impl std::fmt::Debug for Framebuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framebuffer")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("dirty", &self.dirty.len())
            .field("full", &self.full)
            .finish_non_exhaustive()
    }
}

impl Framebuffer {
    /// A `width × height` framebuffer filled with opaque black, fully dirty.
    pub fn new(width: u16, height: u16) -> Result<Self> {
        let mut fb = Self::default();
        fb.resize(width, height)?;
        Ok(fb)
    }

    /// Width in pixels.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// RGBA pixels, `width · height · 4` bytes, row-major.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// The whole framebuffer as a rectangle.
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    /// Resize to `width × height` (each ≤ 8192), clearing to opaque black. The tracked dirty
    /// set is dropped and the next update is full and flagged `resized`. A resize to the
    /// current size is a no-op.
    pub fn resize(&mut self, width: u16, height: u16) -> Result<()> {
        check_dims(width, height)?;
        if width == self.width && height == self.height && !self.pixels.is_empty() {
            return Ok(());
        }
        let len = usize::from(width) * usize::from(height) * 4;
        self.pixels.clear();
        self.pixels.reserve_exact(len);
        for _ in 0..usize::from(width) * usize::from(height) {
            self.pixels.extend_from_slice(&CLEAR);
        }
        self.width = width;
        self.height = height;
        self.dirty.clear();
        self.full = true;
        self.resized = true;
        Ok(())
    }

    fn check(&self, r: Rect) -> Result<()> {
        if r.fits(self.width, self.height) {
            Ok(())
        } else {
            Err(frame_err("rectangle outside the framebuffer"))
        }
    }

    fn offset(&self, x: u16, y: u16) -> usize {
        (usize::from(y) * usize::from(self.width) + usize::from(x)) * 4
    }

    /// Copy `r.w × r.h` pixels from `src` (rows `stride` bytes apart, `order` byte order) to
    /// `r`. `src` must hold at least `stride · (h − 1) + w · 4` bytes and `stride ≥ w · 4`.
    pub fn blit(&mut self, r: Rect, src: &[u8], stride: usize, order: PixelOrder) -> Result<()> {
        self.check(r)?;
        if r.is_empty() {
            return Ok(());
        }
        let row = usize::from(r.w) * 4;
        let need = stride
            .checked_mul(usize::from(r.h) - 1)
            .and_then(|n| n.checked_add(row))
            .ok_or_else(|| frame_err("source too large"))?;
        if stride < row || src.len() < need {
            return Err(frame_err("source buffer too small for the rectangle"));
        }
        for i in 0..usize::from(r.h) {
            let s = &src[i * stride..i * stride + row];
            let d0 = self.offset(r.x, r.y) + i * usize::from(self.width) * 4;
            let d = &mut self.pixels[d0..d0 + row];
            convert_row(d, s, order);
        }
        self.mark_dirty(r);
        Ok(())
    }

    /// Copy the `dst.w × dst.h` block at `(src_x, src_y)` to `dst` (screen-to-screen copy,
    /// overlap-safe like `memmove`). Both rectangles must lie inside the framebuffer.
    pub fn copy(&mut self, dst: Rect, src_x: u16, src_y: u16) -> Result<()> {
        self.check(dst)?;
        self.check(Rect::new(src_x, src_y, dst.w, dst.h))?;
        if dst.is_empty() {
            return Ok(());
        }
        copy_block(&mut self.pixels, self.width, dst, src_x, src_y);
        self.mark_dirty(dst);
        Ok(())
    }

    /// Fill `r` with one RGBA colour.
    pub fn fill(&mut self, r: Rect, rgba: [u8; 4]) -> Result<()> {
        self.check(r)?;
        if r.is_empty() {
            return Ok(());
        }
        for i in 0..usize::from(r.h) {
            let d0 = self.offset(r.x, r.y) + i * usize::from(self.width) * 4;
            for px in self.pixels[d0..d0 + usize::from(r.w) * 4].as_chunks_mut::<4>().0 {
                *px = rgba;
            }
        }
        self.mark_dirty(r);
        Ok(())
    }

    /// Record a cursor change for the next update. An invalid sprite (over 384², wrong byte
    /// length, hot spot outside) is replaced by [`Cursor::Default`] with a warning: the API
    /// mandated by ADR-0011 returns nothing here, and a broken sprite must not reach the UI.
    pub fn set_cursor(&mut self, cursor: Cursor) {
        if cursor.is_valid() {
            self.cursor = Some(cursor);
        } else {
            tracing::warn!("frame: invalid cursor sprite replaced by the default cursor");
            self.cursor = Some(Cursor::Default);
        }
    }

    /// Mark `r` (clipped to the framebuffer) as changed without writing pixels.
    pub fn mark_dirty(&mut self, r: Rect) {
        let Some(mut r) = clip(r, self.width, self.height) else {
            return;
        };
        if self.full {
            return;
        }
        while let Some(i) = self.dirty.iter().position(|o| o.overlaps(r)) {
            r = r.union(self.dirty.swap_remove(i));
        }
        self.dirty.push(r);
        let area: u64 = self.dirty.iter().map(|d| d.area()).sum();
        let total = self.bounds().area();
        if self.dirty.len() > COALESCE_MAX_RECTS || area * 100 > total * FULL_AREA_PERCENT {
            self.full = true;
            self.dirty.clear();
        }
    }

    /// Mark the whole framebuffer dirty (a UI re-attached and needs a key frame).
    pub fn invalidate(&mut self) {
        self.full = true;
        self.dirty.clear();
    }

    /// Whether [`Self::take_update`] would return a non-empty update.
    pub fn has_pending(&self) -> bool {
        self.full || self.resized || !self.dirty.is_empty() || self.cursor.is_some()
    }

    /// Take everything changed since the previous call and reset the tracking.
    pub fn take_update(&mut self) -> FrameUpdate {
        let full = std::mem::take(&mut self.full);
        let rects = if full {
            self.dirty.clear();
            let b = self.bounds();
            if b.is_empty() {
                Vec::new()
            } else {
                vec![b]
            }
        } else {
            std::mem::take(&mut self.dirty)
        };
        FrameUpdate {
            full,
            resized: std::mem::take(&mut self.resized),
            rects,
            cursor: self.cursor.take(),
        }
    }

    /// RGBA bytes of `r` (inside the framebuffer), tightly packed.
    pub fn read_rect(&self, r: Rect) -> Result<Vec<u8>> {
        self.check(r)?;
        let row = usize::from(r.w) * 4;
        let mut out = Vec::with_capacity(row * usize::from(r.h));
        for i in 0..usize::from(r.h) {
            let s0 = self.offset(r.x, r.y) + i * usize::from(self.width) * 4;
            out.extend_from_slice(&self.pixels[s0..s0 + row]);
        }
        Ok(out)
    }
}

fn clip(r: Rect, width: u16, height: u16) -> Option<Rect> {
    if r.x >= width || r.y >= height || r.is_empty() {
        return None;
    }
    let w = r.w.min(width - r.x);
    let h = r.h.min(height - r.y);
    Some(Rect::new(r.x, r.y, w, h))
}

fn convert_row(d: &mut [u8], s: &[u8], order: PixelOrder) {
    match order {
        PixelOrder::Rgba => d.copy_from_slice(s),
        PixelOrder::Bgra => {
            for (d, s) in d.as_chunks_mut::<4>().0.iter_mut().zip(s.as_chunks::<4>().0) {
                *d = [s[2], s[1], s[0], s[3]];
            }
        }
        PixelOrder::Rgbx => {
            for (d, s) in d.as_chunks_mut::<4>().0.iter_mut().zip(s.as_chunks::<4>().0) {
                *d = [s[0], s[1], s[2], 255];
            }
        }
        PixelOrder::Bgrx => {
            for (d, s) in d.as_chunks_mut::<4>().0.iter_mut().zip(s.as_chunks::<4>().0) {
                *d = [s[2], s[1], s[0], 255];
            }
        }
    }
}

/// Overlap-safe block move inside an RGBA buffer `width` pixels wide. The caller has checked
/// both rectangles against the buffer.
pub(crate) fn copy_block(pixels: &mut [u8], width: u16, dst: Rect, src_x: u16, src_y: u16) {
    let stride = usize::from(width) * 4;
    let row = usize::from(dst.w) * 4;
    let rows: Box<dyn Iterator<Item = usize>> = if src_y < dst.y {
        Box::new((0..usize::from(dst.h)).rev())
    } else {
        Box::new(0..usize::from(dst.h))
    };
    for i in rows {
        let s0 = (usize::from(src_y) + i) * stride + usize::from(src_x) * 4;
        let d0 = (usize::from(dst.y) + i) * stride + usize::from(dst.x) * 4;
        pixels.copy_within(s0..s0 + row, d0);
    }
}

#[cfg(test)]
#[path = "framebuffer_tests.rs"]
mod tests;
