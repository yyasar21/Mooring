//! The shared frame path for graphical sessions (ADR-0011 §Frame path, used by RDP and VNC).
//!
//! The framebuffer lives in Rust. A protocol crate writes into it through a [`FrameSink`]
//! (`blit` / `copy` / `fill` / `cursor`); the Tauri `FramePump` waits on
//! [`FrameSink::changed`], takes a coalesced update with [`FrameSink::take_frame`] and sends it
//! to the UI as one binary `MFR1` message ([`mfr1`]). [`FrameCredits`] bounds the messages in
//! flight; a slow UI gets fewer, newer frames, never a queue.
//!
//! Pixels are stored **RGBA**, row-major, 4 bytes per pixel, no row padding. Every operation
//! checks its rectangle against the framebuffer and returns `Err` (never panics) when it does
//! not fit, so hostile protocol coordinates cannot corrupt memory or abort the process.

mod credit;
mod framebuffer;
pub mod mfr1;
mod sink;

pub use credit::{FrameCredits, FrameStats, MAX_IN_FLIGHT};
pub use framebuffer::{FrameUpdate, Framebuffer};
pub use mfr1::{decode_mfr1, encode_update, Mfr1Error, Mfr1Frame, Mfr1Record};
pub use sink::FrameSink;

use crate::error::{MooringError, Result};

/// Largest framebuffer width or height (ADR-0011: fb ≤ 8192²).
pub const MAX_DIM: u16 = 8192;
/// Largest cursor sprite width or height (ADR-0011: ≤ 384²).
pub const MAX_CURSOR: u16 = 384;
/// More dirty rectangles than this in one tick are sent as one full rectangle.
pub const COALESCE_MAX_RECTS: usize = 32;
/// More dirty area than this percentage of the framebuffer is sent as one full rectangle.
pub const FULL_AREA_PERCENT: u64 = 60;

/// A rectangle in framebuffer pixels. `w == 0` or `h == 0` is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Rect {
    /// Left edge.
    pub x: u16,
    /// Top edge.
    pub y: u16,
    /// Width.
    pub w: u16,
    /// Height.
    pub h: u16,
}

impl Rect {
    /// A rectangle.
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    /// Pixel count.
    pub const fn area(self) -> u64 {
        self.w as u64 * self.h as u64
    }

    /// No pixels.
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// One past the right edge (may exceed `u16`).
    pub const fn right(self) -> u32 {
        self.x as u32 + self.w as u32
    }

    /// One past the bottom edge (may exceed `u16`).
    pub const fn bottom(self) -> u32 {
        self.y as u32 + self.h as u32
    }

    /// Whether the rectangle lies inside a `width × height` framebuffer.
    pub const fn fits(self, width: u16, height: u16) -> bool {
        self.right() <= width as u32 && self.bottom() <= height as u32
    }

    /// Whether the two rectangles share at least one pixel.
    pub const fn overlaps(self, o: Self) -> bool {
        !self.is_empty()
            && !o.is_empty()
            && (self.x as u32) < o.right()
            && (o.x as u32) < self.right()
            && (self.y as u32) < o.bottom()
            && (o.y as u32) < self.bottom()
    }

    /// Bounding box of both. Only called on rectangles that fit a framebuffer, so the result
    /// fits it too (and therefore `u16`).
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        let left = self.x.min(other.x);
        let top = self.y.min(other.y);
        let right = self.right().max(other.right());
        let bottom = self.bottom().max(other.bottom());
        let width = u16::try_from(right - u32::from(left)).unwrap_or(u16::MAX);
        let height = u16::try_from(bottom - u32::from(top)).unwrap_or(u16::MAX);
        Self { x: left, y: top, w: width, h: height }
    }

    /// Whether pixel `(px, py)` is inside.
    pub const fn contains(self, px: u16, py: u16) -> bool {
        px >= self.x && (px as u32) < self.right() && py >= self.y && (py as u32) < self.bottom()
    }
}

/// Byte order of a source buffer handed to [`FrameSink::blit`]. `*x` orders carry no alpha;
/// alpha is written as 255. Stored pixels are always RGBA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PixelOrder {
    /// R, G, B, A (`IronRDP` `RgbA32`): a plain copy.
    Rgba,
    /// B, G, R, A.
    Bgra,
    /// R, G, B, unused (RFB 32 bpp little-endian, shifts 0/8/16).
    Rgbx,
    /// B, G, R, unused.
    Bgrx,
}

/// Pointer shape requested by the remote side.
#[derive(Clone, PartialEq, Eq)]
pub enum Cursor {
    /// The platform default arrow (MFR1 kind 6).
    Default,
    /// No cursor (MFR1 kind 5).
    Hidden,
    /// A sprite, RGBA, `w·h·4` bytes, `w, h ≤ 384`, hot spot inside (MFR1 kind 4).
    Sprite {
        /// Hot spot x.
        hot_x: u16,
        /// Hot spot y.
        hot_y: u16,
        /// Sprite width.
        w: u16,
        /// Sprite height.
        h: u16,
        /// RGBA pixels.
        rgba: Vec<u8>,
    },
}

impl std::fmt::Debug for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => f.write_str("Default"),
            Self::Hidden => f.write_str("Hidden"),
            Self::Sprite { hot_x, hot_y, w, h, rgba } => f
                .debug_struct("Sprite")
                .field("hot", &(hot_x, hot_y))
                .field("size", &(w, h))
                .field("bytes", &rgba.len())
                .finish(),
        }
    }
}

impl Cursor {
    /// Whether a sprite respects the caps (size ≤ 384², exact byte length, hot spot inside).
    /// `Default` and `Hidden` are always valid.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Default | Self::Hidden => true,
            Self::Sprite { hot_x, hot_y, w, h, rgba } => {
                (1..=MAX_CURSOR).contains(w)
                    && (1..=MAX_CURSOR).contains(h)
                    && hot_x < w
                    && hot_y < h
                    && rgba.len() == usize::from(*w) * usize::from(*h) * 4
            }
        }
    }
}

pub(crate) fn frame_err(reason: &str) -> MooringError {
    MooringError::Invalid { field: "frame", reason: reason.to_owned() }
}

pub(crate) fn check_dims(width: u16, height: u16) -> Result<()> {
    if width > MAX_DIM || height > MAX_DIM {
        return Err(frame_err("framebuffer larger than 8192x8192"));
    }
    Ok(())
}
