//! Fuzz entry `framebuffer_ops` (review 5 L-28, ADR-0011 §Frame path): a hostile sequence of
//! protocol operations on the shared [`Framebuffer`] — resize, blit, copy, fill, cursor,
//! dirty tracking and the `MFR1` encode of each update — with the rectangles and sizes taken
//! from the bytes, never clamped by the harness, so out-of-bounds and overflowing shapes
//! reach the real checks.
//!
//! Bytes 0–1 pick the starting size (`1 + b0`, `1 + b1`, ≤ 256²); then 8-byte ops
//! `[kind, x, y, w, h, a, b, c]` with `x, y, w, h` doubled to `u16` (so a rectangle can reach
//! past a 256² framebuffer) and `kind % 6` choosing the operation.

use mooring_core::frame::{
    decode_mfr1, encode_update, Cursor, Framebuffer, PixelOrder, Rect, MAX_DIM,
};

/// Largest side a resize may ask for here, so an accepted resize stays cheap (the real cap
/// is 8192² = 256 MiB); one selector value asks for `MAX_DIM + 1` to exercise the cap.
const MAX_SIDE: u16 = 512;

const ORDERS: [PixelOrder; 4] =
    [PixelOrder::Rgba, PixelOrder::Bgra, PixelOrder::Rgbx, PixelOrder::Bgrx];

/// Never panics. Every accepted operation keeps the pixel buffer at `w · h · 4` bytes, a
/// rectangle is refused exactly when it lies outside the framebuffer, the dirty area never
/// exceeds the framebuffer, and each update encodes to an `MFR1` frame that decodes back to
/// the same size with every record inside it.
pub fn run(data: &[u8]) {
    let [w0, h0, rest @ ..] = data else { return };
    let Ok(mut fb) = Framebuffer::new(1 + u16::from(*w0), 1 + u16::from(*h0)) else { return };
    let mut seq = 0u32;
    for op in rest.as_chunks::<8>().0 {
        let r = Rect::new(scale(op[1]), scale(op[2]), scale(op[3]), scale(op[4]));
        let fits = r.fits(fb.width(), fb.height());
        match op[0] % 6 {
            0 => {
                let (w, h) = if op[7] == 0xFF {
                    (MAX_DIM + 1, u16::from(op[6]))
                } else {
                    ((u16::from(op[5]) * 4).min(MAX_SIDE), (u16::from(op[6]) * 4).min(MAX_SIDE))
                };
                let ok = fb.resize(w, h).is_ok();
                assert_eq!(ok, w <= MAX_DIM && h <= MAX_DIM, "resize {w}x{h}");
            }
            1 => {
                // Source rows at least as long as the rectangle, so only the bounds decide.
                let stride = usize::from(r.w) * 4 + usize::from(op[5] % 3);
                let src = vec![op[6]; stride * usize::from(r.h) + usize::from(op[7])];
                let ok = fb.blit(r, &src, stride, ORDERS[usize::from(op[5] % 4)]).is_ok();
                assert_eq!(ok, fits, "blit {r:?}");
            }
            2 => {
                let (sx, sy) = (scale(op[5]), scale(op[6]));
                let src = Rect::new(sx, sy, r.w, r.h);
                let ok = fb.copy(r, sx, sy).is_ok();
                assert_eq!(
                    ok,
                    fits && src.fits(fb.width(), fb.height()),
                    "copy {r:?} from {src:?}"
                );
            }
            3 => {
                let ok = fb.fill(r, [op[5], op[6], op[7], 255]).is_ok();
                assert_eq!(ok, fits, "fill {r:?}");
            }
            4 => {
                let (cw, ch) = (u16::from(op[5]) * 2, u16::from(op[6]) * 2);
                let len = usize::from(cw) * usize::from(ch) * 4;
                let len = if op[7] % 2 == 0 { len } else { len.saturating_sub(1) };
                fb.set_cursor(match op[7] % 3 {
                    0 => Cursor::Default,
                    1 => Cursor::Hidden,
                    _ => Cursor::Sprite {
                        hot_x: scale(op[1]),
                        hot_y: scale(op[2]),
                        w: cw,
                        h: ch,
                        rgba: vec![0; len],
                    },
                });
            }
            _ => {
                fb.mark_dirty(r);
                let update = fb.take_update();
                let area: u64 = update.rects.iter().map(|d| d.area()).sum();
                assert!(area <= fb.bounds().area(), "dirty area exceeds the framebuffer");
                assert!(update.rects.iter().all(|d| d.fits(fb.width(), fb.height())));
                if let Some(c) = &update.cursor {
                    assert!(c.is_valid(), "an invalid sprite reached the update");
                }
                let bytes = encode_update(seq, &fb, &update);
                seq = seq.wrapping_add(1);
                let frame = decode_mfr1(&bytes).expect("an encoded update must decode");
                assert_eq!((frame.width, frame.height), (fb.width(), fb.height()));
                assert!(frame.records.len() <= 256);
                let mut texture = vec![0u8; fb.pixels().len()];
                frame.apply(&mut texture);
            }
        }
        let expect = usize::from(fb.width()) * usize::from(fb.height()) * 4;
        assert_eq!(fb.pixels().len(), expect, "pixel buffer length");
    }
}

fn scale(b: u8) -> u16 {
    u16::from(b) * 2
}
