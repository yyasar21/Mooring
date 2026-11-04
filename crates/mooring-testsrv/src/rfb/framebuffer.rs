//! Synthetic RGBA framebuffer the tests mutate.

/// A rectangle in framebuffer pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    pub fn is_empty(&self) -> bool {
        self.w == 0 || self.h == 0
    }

    fn right(self) -> u32 {
        u32::from(self.x) + u32::from(self.w)
    }

    fn bottom(self) -> u32 {
        u32::from(self.y) + u32::from(self.h)
    }

    /// Smallest rect covering both (an empty rect is the identity).
    #[must_use]
    pub fn union(&self, o: &Rect) -> Rect {
        if self.is_empty() {
            return *o;
        }
        if o.is_empty() {
            return *self;
        }
        let x = self.x.min(o.x);
        let y = self.y.min(o.y);
        let r = self.right().max(o.right());
        let b = self.bottom().max(o.bottom());
        Rect::new(x, y, clamp16(r - u32::from(x)), clamp16(b - u32::from(y)))
    }

    /// Intersection (empty when disjoint).
    #[must_use]
    pub fn intersect(&self, o: &Rect) -> Rect {
        let x = self.x.max(o.x);
        let y = self.y.max(o.y);
        let r = self.right().min(o.right());
        let b = self.bottom().min(o.bottom());
        if r <= u32::from(x) || b <= u32::from(y) {
            return Rect::default();
        }
        Rect::new(x, y, clamp16(r - u32::from(x)), clamp16(b - u32::from(y)))
    }
}

fn clamp16(v: u32) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

/// RGBA framebuffer, row-major, 4 bytes per pixel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framebuffer {
    pub width: u16,
    pub height: u16,
    pub rgba: Vec<u8>,
}

impl Framebuffer {
    /// A deterministic test pattern: a colour gradient with a grid every 32 pixels, so every
    /// encoder (solid tiles, palettes, raw) gets exercised by a full update.
    pub fn synthetic(width: u16, height: u16) -> Self {
        let mut rgba = Vec::with_capacity(usize::from(width) * usize::from(height) * 4);
        for y in 0..height {
            for x in 0..width {
                let px = if x % 32 == 0 || y % 32 == 0 {
                    [255, 255, 255, 255]
                } else if (x / 64 + y / 64) % 3 == 0 {
                    [0x20, 0x40, 0x80, 255] // solid area → ZRLE solid tile / Tight fill
                } else {
                    [low8(x), low8(y), low8(x ^ y), 255]
                };
                rgba.extend_from_slice(&px);
            }
        }
        Self { width, height, rgba }
    }

    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    fn offset(&self, x: u16, y: u16) -> usize {
        (usize::from(y) * usize::from(self.width) + usize::from(x)) * 4
    }

    pub fn pixel(&self, x: u16, y: u16) -> [u8; 4] {
        let o = self.offset(x, y);
        [self.rgba[o], self.rgba[o + 1], self.rgba[o + 2], self.rgba[o + 3]]
    }

    /// RGBA pixels of `r` (must lie inside the framebuffer), row-major.
    pub fn region(&self, r: Rect) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::from(r.w) * usize::from(r.h) * 4);
        for y in r.y..r.y + r.h {
            let o = self.offset(r.x, y);
            out.extend_from_slice(&self.rgba[o..o + usize::from(r.w) * 4]);
        }
        out
    }

    /// Fills the part of `r` inside the framebuffer; returns that part.
    pub fn fill(&mut self, r: Rect, rgba: [u8; 4]) -> Option<Rect> {
        let r = r.intersect(&self.bounds());
        if r.is_empty() {
            return None;
        }
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                let o = self.offset(x, y);
                self.rgba[o..o + 4].copy_from_slice(&rgba);
            }
        }
        Some(r)
    }

    /// Writes `src` (exactly `r.w * r.h * 4` bytes, `r` fully inside) into `r`.
    pub fn blit(&mut self, r: Rect, src: &[u8]) -> Option<Rect> {
        let inside = r.intersect(&self.bounds()) == r && !r.is_empty();
        if !inside || src.len() != usize::from(r.w) * usize::from(r.h) * 4 {
            return None;
        }
        let row = usize::from(r.w) * 4;
        for (i, y) in (r.y..r.y + r.h).enumerate() {
            let o = self.offset(r.x, y);
            self.rgba[o..o + row].copy_from_slice(&src[i * row..(i + 1) * row]);
        }
        Some(r)
    }

    /// Copies a `dst.w × dst.h` block from `(sx, sy)` to `dst` (both fully inside).
    pub fn copy(&mut self, dst: Rect, sx: u16, sy: u16) -> bool {
        let src = Rect::new(sx, sy, dst.w, dst.h);
        let b = self.bounds();
        if dst.is_empty() || dst.intersect(&b) != dst || src.intersect(&b) != src {
            return false;
        }
        let block = self.region(src);
        self.blit(dst, &block).is_some()
    }
}

fn low8(v: u16) -> u8 {
    v.to_le_bytes()[0]
}

#[cfg(test)]
mod tests {
    use super::{Framebuffer, Rect};

    #[test]
    fn rect_algebra() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        assert_eq!(a.union(&b), Rect::new(0, 0, 15, 15));
        assert_eq!(a.intersect(&b), Rect::new(5, 5, 5, 5));
        assert!(a.intersect(&Rect::new(20, 20, 1, 1)).is_empty());
        assert_eq!(Rect::default().union(&b), b);
    }

    #[test]
    fn fill_blit_copy_stay_in_bounds() {
        let mut fb = Framebuffer::synthetic(64, 48);
        assert_eq!(
            fb.fill(Rect::new(60, 40, 100, 100), [1, 2, 3, 4]),
            Some(Rect::new(60, 40, 4, 8))
        );
        assert_eq!(fb.pixel(63, 47), [1, 2, 3, 4]);
        assert!(fb.blit(Rect::new(63, 0, 2, 1), &[0; 8]).is_none());
        assert!(fb.copy(Rect::new(0, 0, 4, 8), 60, 40));
        assert_eq!(fb.pixel(0, 0), [1, 2, 3, 4]);
        assert!(!fb.copy(Rect::new(0, 0, 8, 8), 60, 40));
    }
}
