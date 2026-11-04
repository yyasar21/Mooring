//! Tight basic (rfbproto "Tight Encoding") without JPEG (owner decision 5): fill, and basic
//! compression with the copy, palette and gradient filters on four persistent zlib streams.
//! With our 32-bpp depth-24 format a TPIXEL is 3 bytes (R, G, B).
//!
//! [`frame_len`] finds the rectangle's length without touching the zlib streams (the session
//! needs it to know when the rectangle is fully buffered); [`decode_tight`] decodes it.

use super::zlib::ZStream;

use super::{inflate, put_cpixel, MAX_INFLATE};
use crate::error::VncError;
use crate::wire::{take, PResult, Parsed, Rd};

/// Below this many bytes the data is sent uncompressed.
pub const MIN_COMPRESS: usize = 12;
/// Largest compact length (22 bits).
pub const MAX_COMPACT: usize = 0x3F_FFFF;

/// The four persistent Tight zlib streams.
#[derive(Debug)]
pub struct TightStreams(pub [ZStream; 4]);

impl Default for TightStreams {
    fn default() -> Self {
        Self(std::array::from_fn(|_| ZStream::new()))
    }
}

/// A decoded Tight rectangle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TightOutput {
    /// Solid colour (R, G, B).
    Fill([u8; 3]),
    /// RGBX pixels, `w·h·4` bytes.
    Pixels(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Filter {
    Copy,
    Palette(Vec<[u8; 3]>),
    Gradient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Header {
    Fill([u8; 3]),
    Basic { stream: usize, filter: Filter, size: usize, data_at: usize, data_len: usize },
}

fn parse_header(buf: &[u8], w: u16, h: u16) -> PResult<Header> {
    let (w, h) = (usize::from(w), usize::from(h));
    let mut r = Rd::new(buf);
    let control = take!(r.u8());
    match control >> 4 {
        8 => {
            let p = take!(r.bytes(3));
            return Ok(Parsed::Done(Header::Fill([p[0], p[1], p[2]]), r.pos()));
        }
        9 => return Err(VncError::protocol("Tight JPEG is not supported (not requested)")),
        10..=15 => return Err(VncError::protocol("invalid Tight compression control")),
        _ => {}
    }
    let stream = usize::from((control >> 4) & 3);
    let filter_id = if control & 0x40 != 0 { take!(r.u8()) } else { 0 };
    let (filter, size) = match filter_id {
        0 => (Filter::Copy, w * h * 3),
        1 => {
            let n = usize::from(take!(r.u8())) + 1;
            let raw = take!(r.bytes(n * 3));
            let palette: Vec<[u8; 3]> = raw.as_chunks::<3>().0.to_vec();
            let size = if n == 2 { w.div_ceil(8) * h } else { w * h };
            (Filter::Palette(palette), size)
        }
        2 => (Filter::Gradient, w * h * 3),
        _ => return Err(VncError::protocol("invalid Tight filter")),
    };
    if size > MAX_INFLATE {
        return Err(VncError::protocol("Tight rectangle exceeds the decode cap"));
    }
    let data_len = if size < MIN_COMPRESS {
        size
    } else {
        // Compact length: 7 + 7 + 8 bits, little-endian groups.
        let b0 = take!(r.u8());
        let mut len = usize::from(b0 & 0x7f);
        if b0 & 0x80 != 0 {
            let b1 = take!(r.u8());
            len |= usize::from(b1 & 0x7f) << 7;
            if b1 & 0x80 != 0 {
                len |= usize::from(take!(r.u8())) << 14;
            }
        }
        len
    };
    let data_at = r.pos();
    take!(r.skip(data_len));
    Ok(Parsed::Done(Header::Basic { stream, filter, size, data_at, data_len }, r.pos()))
}

/// Length of a Tight rectangle payload (from the control byte on), or how much is needed.
pub fn frame_len(buf: &[u8], w: u16, h: u16) -> PResult<()> {
    Ok(parse_header(buf, w, h)?.map(|_| ()))
}

/// Decode a complete Tight rectangle payload (from the control byte on).
pub fn decode_tight(
    streams: &mut TightStreams,
    data: &[u8],
    w: u16,
    h: u16,
) -> Result<TightOutput, VncError> {
    let control = *data.first().ok_or_else(|| VncError::protocol("Tight data truncated"))?;
    for (i, z) in streams.0.iter_mut().enumerate() {
        if control & (1 << i) != 0 {
            z.reset();
        }
    }
    let Parsed::Done(header, _) = parse_header(data, w, h)? else {
        return Err(VncError::protocol("Tight data truncated"));
    };
    let (stream, filter, size, data_at, data_len) = match header {
        Header::Fill(p) => return Ok(TightOutput::Fill(p)),
        Header::Basic { stream, filter, size, data_at, data_len } => {
            (stream, filter, size, data_at, data_len)
        }
    };
    let payload = &data[data_at..data_at + data_len];
    let raw = if size < MIN_COMPRESS {
        payload.to_vec()
    } else {
        let out = inflate(&mut streams.0[stream], payload, size)?;
        if out.len() != size {
            return Err(VncError::protocol("Tight data has the wrong size"));
        }
        out
    };
    let (w, h) = (usize::from(w), usize::from(h));
    let mut px = vec![0u8; w * h * 4];
    match filter {
        Filter::Copy => {
            for (i, c) in raw.as_chunks::<3>().0.iter().enumerate() {
                put_cpixel(&mut px, i, *c);
            }
        }
        Filter::Palette(palette) => {
            let row = w.div_ceil(8);
            for y in 0..h {
                for x in 0..w {
                    let idx = if palette.len() == 2 {
                        usize::from((raw[y * row + x / 8] >> (7 - x % 8)) & 1)
                    } else {
                        usize::from(raw[y * w + x])
                    };
                    let p = palette
                        .get(idx)
                        .ok_or_else(|| VncError::protocol("Tight palette index"))?;
                    put_cpixel(&mut px, y * w + x, *p);
                }
            }
        }
        Filter::Gradient => gradient(&raw, w, h, &mut px),
    }
    Ok(TightOutput::Pixels(px))
}

/// Gradient filter (24-bit): each component is predicted as left + above − above-left,
/// clamped to 0..=255, and the data byte is added modulo 256.
fn gradient(raw: &[u8], w: usize, h: usize, px: &mut [u8]) {
    let mut prev = vec![[0i32; 3]; w];
    let mut this = vec![[0i32; 3]; w];
    for y in 0..h {
        for x in 0..w {
            let mut out = [0u8; 3];
            for c in 0..3 {
                let left = if x > 0 { this[x - 1][c] } else { 0 };
                let up_left = if x > 0 { prev[x - 1][c] } else { 0 };
                let est = (left + prev[x][c] - up_left).clamp(0, 255);
                let v = (est + i32::from(raw[(y * w + x) * 3 + c])) & 0xff;
                this[x][c] = v;
                out[c] = u8::try_from(v).unwrap_or(0);
            }
            put_cpixel(px, y * w + x, out);
        }
        std::mem::swap(&mut prev, &mut this);
    }
}

#[cfg(test)]
#[path = "tight_tests.rs"]
mod tests;
