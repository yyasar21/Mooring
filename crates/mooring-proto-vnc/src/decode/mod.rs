//! Rectangle decoders. Every function here is pure over its input bytes (plus the
//! persistent zlib streams RFB mandates) and returns a [`RectOp`] for the session to apply to
//! the `FrameSink`, so the decoders are fuzzable without a socket.
//!
//! Hostile-input rules (ADR-0012 §Decoder caps): rectangle bounds are checked by
//! `messages::parse_rect` before anything is allocated; zlib output is capped at
//! [`MAX_INFLATE`] per rectangle with streaming inflate (zlib bombs); every index and run
//! length is checked against the tile; nothing panics.

pub mod tight;
pub mod zlib;
pub mod zrle;

use mooring_core::frame::{Cursor, Rect};

use crate::error::VncError;
use crate::messages::{enc, ext_desktop_screen, RectFrame};

pub use tight::{decode_tight, TightOutput, TightStreams};
pub use zlib::{inflate, ZStream};
pub use zrle::decode_zrle;

/// Largest zlib output for one rectangle (ADR-0012: 64 MiB).
pub const MAX_INFLATE: usize = 64 * 1024 * 1024;

/// What one rectangle does to the framebuffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RectOp {
    /// RGBX pixels (`PixelOrder::Rgbx`, stride `w·4`).
    Blit {
        /// Target.
        rect: Rect,
        /// Pixels.
        rgbx: Vec<u8>,
    },
    /// Solid fill.
    Fill {
        /// Target.
        rect: Rect,
        /// RGBA (alpha 255).
        rgba: [u8; 4],
    },
    /// `CopyRect`.
    Copy {
        /// Target.
        rect: Rect,
        /// Source x.
        src_x: u16,
        /// Source y.
        src_y: u16,
    },
    /// The desktop size changed (`DesktopSize` / `ExtendedDesktopSize`).
    Resize {
        /// New width.
        w: u16,
        /// New height.
        h: u16,
        /// `ExtendedDesktopSize`: (first screen id, flags), so `SetDesktopSize` can be sent.
        screen: Option<(u32, u32)>,
    },
    /// An `ExtendedDesktopSize` answer that did not change the size (refused request).
    ExtDesktopRefused {
        /// (first screen id, flags).
        screen: Option<(u32, u32)>,
    },
    /// New pointer shape.
    Cursor(Cursor),
    /// The server confirmed QEMU Extended Key Event.
    QemuExtKey,
    /// `LastRect`: the update ends here.
    LastRect,
    /// Nothing to do (empty rectangle).
    Nothing,
}

/// The persistent decoder state of one RFB connection (reset on reconnect).
#[derive(Debug, Default)]
pub struct Decoders {
    /// The single ZRLE zlib stream.
    pub zrle: ZStream,
    /// The four Tight zlib streams.
    pub tight: TightStreams,
}

impl Decoders {
    /// Decode a framed rectangle; `buf[frame.start..frame.end]` is its payload.
    pub fn decode(&mut self, frame: &RectFrame, buf: &[u8]) -> Result<RectOp, VncError> {
        let RectFrame { header, start, end } = *frame;
        let data = buf.get(start..end).ok_or_else(|| VncError::protocol("rectangle truncated"))?;
        let rect = header.rect;
        let short = |n: usize| {
            if data.len() < n {
                Err(VncError::protocol("rectangle truncated"))
            } else {
                Ok(())
            }
        };
        match header.encoding {
            enc::RAW => Ok(
                if rect.is_empty() || data.len() != usize::try_from(rect.area()).unwrap_or(0) * 4 {
                    RectOp::Nothing
                } else {
                    RectOp::Blit { rect, rgbx: data.to_vec() }
                },
            ),
            enc::COPY_RECT => {
                short(4)?;
                let src_x = u16::from_be_bytes([data[0], data[1]]);
                let src_y = u16::from_be_bytes([data[2], data[3]]);
                let src = Rect::new(src_x, src_y, rect.w, rect.h);
                if !src.fits(u16::MAX, u16::MAX) {
                    return Err(VncError::protocol("CopyRect source out of range"));
                }
                Ok(RectOp::Copy { rect, src_x, src_y })
            }
            enc::ZRLE => {
                short(4)?;
                let px = decode_zrle(&mut self.zrle, &data[4..], rect.w, rect.h)?;
                Ok(if rect.is_empty() { RectOp::Nothing } else { RectOp::Blit { rect, rgbx: px } })
            }
            enc::TIGHT => match decode_tight(&mut self.tight, data, rect.w, rect.h)? {
                _ if rect.is_empty() => Ok(RectOp::Nothing),
                TightOutput::Fill([r, g, b]) => Ok(RectOp::Fill { rect, rgba: [r, g, b, 255] }),
                TightOutput::Pixels(rgbx) => Ok(RectOp::Blit { rect, rgbx }),
            },
            enc::CURSOR => Ok(RectOp::Cursor(decode_cursor(rect, data))),
            enc::DESKTOP_SIZE => resize(rect, None),
            enc::EXT_DESKTOP_SIZE => {
                let screen = ext_desktop_screen(data);
                // y = status: non-zero means our SetDesktopSize was refused; x = reason
                // (1 = answer to this client). A refusal carries the unchanged size.
                if rect.y != 0 {
                    return Ok(RectOp::ExtDesktopRefused { screen });
                }
                resize(rect, screen)
            }
            enc::LAST_RECT => Ok(RectOp::LastRect),
            enc::QEMU_EXT_KEY => Ok(RectOp::QemuExtKey),
            e => Err(VncError::protocol(format!("unrequested encoding {e}"))),
        }
    }
}

fn resize(rect: Rect, screen: Option<(u32, u32)>) -> Result<RectOp, VncError> {
    let max = mooring_core::frame::MAX_DIM;
    if rect.w == 0 || rect.h == 0 || rect.w > max || rect.h > max {
        return Err(VncError::protocol("desktop size out of range"));
    }
    Ok(RectOp::Resize { w: rect.w, h: rect.h, screen })
}

/// Cursor pseudo-encoding: `w·h` RGBX pixels then a 1-bpp mask (MSB first, rows padded to
/// bytes). `rect.x/y` is the hot spot (clamped into the sprite). Empty = hidden.
pub fn decode_cursor(rect: Rect, data: &[u8]) -> Cursor {
    let (w, h) = (usize::from(rect.w), usize::from(rect.h));
    if w == 0 || h == 0 {
        return Cursor::Hidden;
    }
    let row = w.div_ceil(8);
    if data.len() < w * h * 4 + row * h {
        return Cursor::Default;
    }
    let (pixels, mask) = data.split_at(w * h * 4);
    let mut rgba = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        for x in 0..w {
            let p = &pixels[(y * w + x) * 4..(y * w + x) * 4 + 3];
            let on = mask[y * row + x / 8] & (0x80 >> (x % 8)) != 0;
            rgba.extend_from_slice(&[p[0], p[1], p[2], if on { 255 } else { 0 }]);
        }
    }
    let c = Cursor::Sprite {
        hot_x: rect.x.min(rect.w - 1),
        hot_y: rect.y.min(rect.h - 1),
        w: rect.w,
        h: rect.h,
        rgba,
    };
    if c.is_valid() {
        c
    } else {
        Cursor::Default
    }
}

/// Write a 3-byte CPIXEL/TPIXEL (R, G, B in our format) as RGBX.
#[inline]
pub(crate) fn put_cpixel(out: &mut [u8], at: usize, p: [u8; 3]) {
    out[at * 4..at * 4 + 4].copy_from_slice(&[p[0], p[1], p[2], 0]);
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
