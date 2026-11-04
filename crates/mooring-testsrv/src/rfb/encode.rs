//! Rect encoders: Raw, ZRLE (RFC 6143 §7.7.6) and Tight basic (rfbproto "Tight", no JPEG).
//!
//! One [`Encoders`] per connection holds the persistent zlib streams (1 for ZRLE, 4 for Tight).

use flate2::{Compress, Compression, FlushCompress};

use super::encoding;
use super::framebuffer::{Framebuffer, Rect};
use super::pixel::PixelFormat;

/// ZRLE tile sub-encoding choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZrleMode {
    /// Solid → packed palette (≤ 16 colours) → palette RLE (≤ 127) → raw, per tile.
    #[default]
    Auto,
    /// Every tile raw (sub-encoding 0).
    Raw,
    /// Every tile plain RLE (sub-encoding 128).
    PlainRle,
}

/// Tight basic filter choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TightMode {
    /// Fill for solid rects, palette for 2–16 colours, copy otherwise.
    #[default]
    Auto,
    Copy,
    /// Palette when ≤ 256 colours, copy otherwise.
    Palette,
    /// Gradient (only for 24-bit TPIXEL formats; copy otherwise).
    Gradient,
}

/// Per-connection encoder state.
pub(crate) struct Encoders {
    zrle: Compress,
    tight: [Compress; 4],
    pub(crate) zrle_mode: ZrleMode,
    pub(crate) tight_mode: TightMode,
    pub(crate) lie_zlib_length: Option<u32>,
    pub(crate) tight_jpeg: bool,
}

/// One encoded rect ready for the wire: header fields + payload.
pub(crate) struct Encoded {
    pub(crate) rect: Rect,
    pub(crate) encoding: i32,
    pub(crate) data: Vec<u8>,
}

impl Encoders {
    pub(crate) fn new(zrle_mode: ZrleMode, tight_mode: TightMode) -> Self {
        let z = || Compress::new(Compression::default(), true);
        Self {
            zrle: z(),
            tight: [z(), z(), z(), z()],
            zrle_mode,
            tight_mode,
            lie_zlib_length: None,
            tight_jpeg: false,
        }
    }

    /// Encodes `r` (inside `fb`) as `enc`. Tight rects are split into ≤ 256 × 256 pieces.
    pub(crate) fn encode(
        &mut self,
        fb: &Framebuffer,
        r: Rect,
        enc: i32,
        pf: &PixelFormat,
    ) -> Vec<Encoded> {
        match enc {
            encoding::ZRLE => vec![Encoded { rect: r, encoding: enc, data: self.zrle(fb, r, pf) }],
            encoding::TIGHT => split(r, 256)
                .into_iter()
                .map(|p| Encoded { rect: p, encoding: enc, data: self.tight(fb, p, pf) })
                .collect(),
            _ => vec![Encoded { rect: r, encoding: encoding::RAW, data: raw(fb, r, pf) }],
        }
    }

    fn zrle(&mut self, fb: &Framebuffer, r: Rect, pf: &PixelFormat) -> Vec<u8> {
        let mut plain = Vec::new();
        for tile in tiles(r, 64) {
            let px = fb.region(tile);
            zrle_tile(&px, tile.w, pf, self.zrle_mode, &mut plain);
        }
        let z = deflate(&mut self.zrle, &plain);
        let len =
            self.lie_zlib_length.unwrap_or_else(|| u32::try_from(z.len()).unwrap_or(u32::MAX));
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(&z);
        out
    }

    fn tight(&mut self, fb: &Framebuffer, r: Rect, pf: &PixelFormat) -> Vec<u8> {
        let px = fb.region(r);
        if self.tight_jpeg {
            let mut out = vec![0x90];
            push_compact_len(&mut out, 4);
            out.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xD9]);
            return out;
        }
        let colours = palette(&px, 256);
        let mode = match self.tight_mode {
            TightMode::Auto => match colours.as_deref() {
                Some([c]) => return tight_fill(*c, pf),
                Some(p) if p.len() <= 16 => TightMode::Palette,
                _ => TightMode::Copy,
            },
            m => m,
        };
        let mut out = Vec::new();
        let (stream, data) = match (mode, colours) {
            (TightMode::Palette, Some(p)) if p.len() >= 2 => {
                out.extend_from_slice(&[
                    0x40 | (1 << 4),
                    1,
                    u8::try_from(p.len() - 1).unwrap_or(255),
                ]);
                for c in &p {
                    pf.push_tpixel(c, &mut out);
                }
                (1, palette_indices(&px, r.w, &p))
            }
            (TightMode::Gradient, _) if pf.tight_compact() => {
                out.extend_from_slice(&[0x40 | (2 << 4), 2]);
                (2, gradient(&px, r.w))
            }
            _ => {
                out.push(0x00);
                let mut d = Vec::with_capacity(px.len());
                for p in px.chunks_exact(4) {
                    pf.push_tpixel(p, &mut d);
                }
                (0, d)
            }
        };
        if data.len() < 12 {
            out.extend_from_slice(&data);
        } else {
            let z = deflate(&mut self.tight[stream], &data);
            push_compact_len(&mut out, self.lie_zlib_length.map_or(z.len(), |l| l as usize));
            out.extend_from_slice(&z);
        }
        out
    }
}

/// Raw rect payload in the client's pixel format.
pub(crate) fn raw(fb: &Framebuffer, r: Rect, pf: &PixelFormat) -> Vec<u8> {
    let px = fb.region(r);
    let mut out = Vec::with_capacity(px.len() / 4 * pf.bytes_per_pixel());
    for p in px.chunks_exact(4) {
        pf.push_pixel(p, &mut out);
    }
    out
}

fn tight_fill(c: [u8; 4], pf: &PixelFormat) -> Vec<u8> {
    let mut out = vec![0x80];
    pf.push_tpixel(&c, &mut out);
    out
}

/// Sync-flushed zlib output of `input` on a persistent stream.
fn deflate(z: &mut Compress, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 64);
    let start_in = z.total_in();
    loop {
        let consumed = usize::try_from(z.total_in() - start_in).unwrap_or(usize::MAX);
        if out.capacity() - out.len() < 64 {
            out.reserve(out.capacity().max(1024));
        }
        let before = out.len();
        let status = z.compress_vec(&input[consumed..], &mut out, FlushCompress::Sync);
        let done = usize::try_from(z.total_in() - start_in).unwrap_or(usize::MAX) == input.len();
        if status.is_err() || (done && out.len() - before < out.capacity() - before) {
            break;
        }
    }
    out
}

fn push_compact_len(out: &mut Vec<u8>, len: usize) {
    let b = |v: usize| u8::try_from(v & 0x7F).unwrap_or(0);
    if len < 0x80 {
        out.push(b(len));
    } else if len < 0x4000 {
        out.extend_from_slice(&[b(len) | 0x80, b(len >> 7)]);
    } else {
        out.extend_from_slice(&[
            b(len) | 0x80,
            b(len >> 7) | 0x80,
            u8::try_from((len >> 14) & 0xFF).unwrap_or(0xFF),
        ]);
    }
}

/// Rect split into `size × size` tiles, left to right, top to bottom.
pub(crate) fn tiles(r: Rect, size: u16) -> Vec<Rect> {
    let mut v = Vec::new();
    let mut y = r.y;
    while y < r.y + r.h {
        let h = size.min(r.y + r.h - y);
        let mut x = r.x;
        while x < r.x + r.w {
            let w = size.min(r.x + r.w - x);
            v.push(Rect::new(x, y, w, h));
            x += w;
        }
        y += h;
    }
    v
}

fn split(r: Rect, size: u16) -> Vec<Rect> {
    tiles(r, size)
}

/// Distinct colours in first-seen order, or `None` when there are more than `max`.
fn palette(px: &[u8], max: usize) -> Option<Vec<[u8; 4]>> {
    let mut p: Vec<[u8; 4]> = Vec::new();
    for c in px.chunks_exact(4) {
        let c = [c[0], c[1], c[2], 255];
        if !p.contains(&c) {
            if p.len() == max {
                return None;
            }
            p.push(c);
        }
    }
    Some(p)
}

fn index_of(p: &[[u8; 4]], c: &[u8]) -> u8 {
    let i = p.iter().position(|q| q[..3] == c[..3]).unwrap_or(0);
    u8::try_from(i).unwrap_or(0)
}

/// Packed indices: `bits` per pixel, MSB first, every row padded to a byte.
fn pack_rows(px: &[u8], w: u16, p: &[[u8; 4]], bits: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for row in px.chunks_exact(usize::from(w) * 4) {
        let (mut byte, mut used) = (0u8, 0u8);
        for c in row.chunks_exact(4) {
            byte |= index_of(p, c) << (8 - bits - used);
            used += bits;
            if used == 8 {
                out.push(byte);
                (byte, used) = (0, 0);
            }
        }
        if used > 0 {
            out.push(byte);
        }
    }
    out
}

fn palette_indices(px: &[u8], w: u16, p: &[[u8; 4]]) -> Vec<u8> {
    if p.len() == 2 {
        pack_rows(px, w, p, 1)
    } else {
        px.chunks_exact(4).map(|c| index_of(p, c)).collect()
    }
}

/// Tight gradient filter on 24-bit RGB (rfbproto "Tight", gradient filter).
fn gradient(px: &[u8], w: u16) -> Vec<u8> {
    let w = usize::from(w);
    let at = |x: usize, y: usize, c: usize| -> i32 { i32::from(px[(y * w + x) * 4 + c]) };
    let rows = px.len() / 4 / w;
    let mut out = Vec::with_capacity(rows * w * 3);
    for y in 0..rows {
        for x in 0..w {
            for c in 0..3 {
                let left = if x > 0 { at(x - 1, y, c) } else { 0 };
                let up = if y > 0 { at(x, y - 1, c) } else { 0 };
                let ul = if x > 0 && y > 0 { at(x - 1, y - 1, c) } else { 0 };
                let pred = (left + up - ul).clamp(0, 255);
                out.push(((at(x, y, c) - pred) & 0xFF).to_le_bytes()[0]);
            }
        }
    }
    out
}

/// Appends one ZRLE tile (before zlib).
fn zrle_tile(px: &[u8], w: u16, pf: &PixelFormat, mode: ZrleMode, out: &mut Vec<u8>) {
    let colours = palette(px, 127);
    match (mode, colours.as_deref()) {
        (ZrleMode::Raw, _) => {
            out.push(0);
            px.chunks_exact(4).for_each(|c| pf.push_cpixel(c, out));
        }
        (ZrleMode::PlainRle, _) => {
            out.push(128);
            for (c, n) in runs(px) {
                pf.push_cpixel(c, out);
                push_run(out, n);
            }
        }
        (ZrleMode::Auto, Some([c])) => {
            out.push(1);
            pf.push_cpixel(c, out);
        }
        (ZrleMode::Auto, Some(p)) if p.len() <= 16 => {
            out.push(u8::try_from(p.len()).unwrap_or(16));
            for c in p {
                pf.push_cpixel(c, out);
            }
            let bits = match p.len() {
                2 => 1,
                3 | 4 => 2,
                _ => 4,
            };
            out.extend_from_slice(&pack_rows(px, w, p, bits));
        }
        (ZrleMode::Auto, Some(p)) => {
            out.push(128 + u8::try_from(p.len()).unwrap_or(127));
            for c in p {
                pf.push_cpixel(c, out);
            }
            for (c, n) in runs(px) {
                let i = index_of(p, c);
                if n == 1 {
                    out.push(i);
                } else {
                    out.push(i | 0x80);
                    push_run(out, n);
                }
            }
        }
        (ZrleMode::Auto, None) => {
            out.push(0);
            px.chunks_exact(4).for_each(|c| pf.push_cpixel(c, out));
        }
    }
}

/// Runs of equal colour over the whole tile (runs cross row boundaries in ZRLE).
fn runs(px: &[u8]) -> Vec<(&[u8], usize)> {
    let mut v: Vec<(&[u8], usize)> = Vec::new();
    for c in px.chunks_exact(4) {
        match v.last_mut() {
            Some((p, n)) if p[..3] == c[..3] => *n += 1,
            _ => v.push((c, 1)),
        }
    }
    v
}

/// ZRLE run length: (n - 1) as a sum of bytes, 255 meaning "add 255 and continue".
fn push_run(out: &mut Vec<u8>, n: usize) {
    let mut rest = n - 1;
    while rest >= 255 {
        out.push(255);
        rest -= 255;
    }
    out.push(u8::try_from(rest).unwrap_or(254));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_len_vectors() {
        let enc = |n| {
            let mut v = Vec::new();
            push_compact_len(&mut v, n);
            v
        };
        assert_eq!(enc(10), [10]);
        assert_eq!(enc(200), [0xC8, 0x01]);
        assert_eq!(enc(20_000), [0xA0, 0x9C, 0x01]);
    }

    #[test]
    fn run_lengths_and_tiles() {
        let mut v = Vec::new();
        push_run(&mut v, 1);
        push_run(&mut v, 256);
        push_run(&mut v, 300);
        assert_eq!(v, [0, 255, 0, 255, 44]);
        assert_eq!(tiles(Rect::new(0, 0, 130, 65), 64).len(), 6);
    }

    #[test]
    fn deflate_round_trips_on_a_persistent_stream() {
        let mut z = Compress::new(Compression::default(), true);
        let mut d = flate2::Decompress::new(true);
        for chunk in [vec![7u8; 100_000], (0..=255).collect::<Vec<u8>>()] {
            let c = deflate(&mut z, &chunk);
            let mut out = Vec::with_capacity(chunk.len() + 16);
            d.decompress_vec(&c, &mut out, flate2::FlushDecompress::Sync).expect("inflate");
            assert_eq!(out, chunk);
        }
    }
}
