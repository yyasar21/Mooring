//! `MFR1`: the binary frame message from Rust to the UI (ADR-0011 §Frame path).
//!
//! Little-endian. Header (16 bytes):
//! `magic "MFR1" | seq u32 | fbW u16 | fbH u16 | n u16 | flags u16` with flags
//! `1 = full`, `2 = resized`. Then `n` records, each `kind u8 | 0 u8 | x y w h u16` (10 bytes)
//! followed by the record's own fields:
//!
//! | kind | meaning | extra bytes |
//! | --- | --- | --- |
//! | 1 | RGBA pixels for `x y w h` | `w·h·4` |
//! | 2 | copy the `w×h` block at `srcX srcY` to `x y` | `srcX srcY u16` |
//! | 3 | fill `x y w h` | `rgba[4]` |
//! | 4 | cursor sprite `w×h` (`x y` are 0) | `hotX hotY u16` + `w·h·4` |
//! | 5 | cursor hidden (`x y w h` are 0) | — |
//! | 6 | cursor default (`x y w h` are 0) | — |
//!
//! Limits: `n ≤ 256`, `fbW, fbH ≤ 8192`, message ≤ `4·fbW·fbH + 64 KiB`, plus (our reading of
//! the ADR) room for one maximal cursor sprite record, since a sprite on a tiny framebuffer
//! would otherwise not fit. Records 1–3 must lie inside the framebuffer; records apply in order.
//!
//! [`decode_mfr1`] treats its input as hostile: every length is checked before it is used,
//! allocation is bounded by the input length, and it never panics (fuzz target
//! `framebuffer_ops` / `mfr1_decode`).

use super::framebuffer::copy_block;
use super::{Cursor, FrameUpdate, Framebuffer, Rect, MAX_CURSOR, MAX_DIM};

/// `"MFR1"`.
pub const MAGIC: [u8; 4] = *b"MFR1";
/// Header length.
pub const HEADER_LEN: usize = 16;
/// Record header length (`kind | 0 | x y w h`).
pub const RECORD_HEADER_LEN: usize = 10;
/// Most records in one message.
pub const MAX_RECORDS: usize = 256;
/// Slack above `4·fbW·fbH` for headers and small records.
pub const SLACK: usize = 64 * 1024;
/// Flag: the message repaints the whole framebuffer.
pub const FLAG_FULL: u16 = 1;
/// Flag: the framebuffer size changed; the UI reallocates its texture.
pub const FLAG_RESIZED: u16 = 2;
const KNOWN_FLAGS: u16 = FLAG_FULL | FLAG_RESIZED;
const CURSOR_ALLOWANCE: usize =
    RECORD_HEADER_LEN + 4 + MAX_CURSOR as usize * MAX_CURSOR as usize * 4;

/// Largest valid message for a `width × height` framebuffer.
pub const fn max_message_len(width: u16, height: u16) -> usize {
    4 * width as usize * height as usize + SLACK + CURSOR_ALLOWANCE
}

/// Why a message was refused. Carries no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Mfr1Error {
    /// Shorter than its header or a record says.
    #[error("mfr1: truncated")]
    Truncated,
    /// Not `"MFR1"`.
    #[error("mfr1: bad magic")]
    BadMagic,
    /// Framebuffer over 8192², message over the size cap, or more than 256 records.
    #[error("mfr1: over a limit")]
    TooLarge,
    /// Unknown flag bits.
    #[error("mfr1: unknown flags")]
    BadFlags,
    /// Unknown record kind or non-zero reserved byte/fields.
    #[error("mfr1: malformed record")]
    BadRecord,
    /// A rectangle outside the framebuffer.
    #[error("mfr1: rectangle out of bounds")]
    OutOfBounds,
    /// A cursor sprite over 384² or with its hot spot outside.
    #[error("mfr1: invalid cursor")]
    BadCursor,
    /// Bytes after the last record.
    #[error("mfr1: trailing bytes")]
    Trailing,
}

/// One decoded record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mfr1Record {
    /// Kind 1.
    Rgba {
        /// Target.
        rect: Rect,
        /// `w·h·4` RGBA bytes.
        data: Vec<u8>,
    },
    /// Kind 2.
    Copy {
        /// Target.
        rect: Rect,
        /// Source x.
        src_x: u16,
        /// Source y.
        src_y: u16,
    },
    /// Kind 3.
    Fill {
        /// Target.
        rect: Rect,
        /// Colour.
        rgba: [u8; 4],
    },
    /// Kinds 4, 5, 6.
    Cursor(Cursor),
}

/// A decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mfr1Frame {
    /// Sequence number, acknowledged with `session_frame_ack`.
    pub seq: u32,
    /// Framebuffer width.
    pub width: u16,
    /// Framebuffer height.
    pub height: u16,
    /// [`FLAG_FULL`] | [`FLAG_RESIZED`].
    pub flags: u16,
    /// Records in order.
    pub records: Vec<Mfr1Record>,
}

impl Mfr1Frame {
    /// Flag 1.
    pub fn is_full(&self) -> bool {
        self.flags & FLAG_FULL != 0
    }

    /// Flag 2.
    pub fn is_resized(&self) -> bool {
        self.flags & FLAG_RESIZED != 0
    }

    /// Apply the pixel records to an RGBA mirror (what the UI's texture does). The mirror is
    /// reallocated (opaque black) when the message is `resized` or its size does not match.
    /// Returns the last cursor record, if any.
    pub fn apply(&self, mirror: &mut Vec<u8>) -> Option<Cursor> {
        let len = usize::from(self.width) * usize::from(self.height) * 4;
        if self.is_resized() || mirror.len() != len {
            mirror.clear();
            mirror.resize(len, 0);
            for px in mirror.as_chunks_mut::<4>().0 {
                px[3] = 255;
            }
        }
        let stride = usize::from(self.width) * 4;
        let mut cursor = None;
        for rec in &self.records {
            match rec {
                Mfr1Record::Rgba { rect, data } => {
                    let row = usize::from(rect.w) * 4;
                    for (i, src) in data.chunks_exact(row.max(1)).enumerate() {
                        let d0 = (usize::from(rect.y) + i) * stride + usize::from(rect.x) * 4;
                        mirror[d0..d0 + row].copy_from_slice(src);
                    }
                }
                Mfr1Record::Copy { rect, src_x, src_y } => {
                    copy_block(mirror, self.width, *rect, *src_x, *src_y);
                }
                Mfr1Record::Fill { rect, rgba } => {
                    for i in 0..usize::from(rect.h) {
                        let d0 = (usize::from(rect.y) + i) * stride + usize::from(rect.x) * 4;
                        let end = d0 + usize::from(rect.w) * 4;
                        for px in mirror[d0..end].as_chunks_mut::<4>().0 {
                            *px = *rgba;
                        }
                    }
                }
                Mfr1Record::Cursor(c) => cursor = Some(c.clone()),
            }
        }
        cursor
    }
}

/// Incremental `MFR1` writer. Records are appended in order; [`Self::finish`] patches `n`.
#[derive(Debug)]
pub struct Mfr1Writer {
    buf: Vec<u8>,
    n: u16,
}

impl Mfr1Writer {
    /// Start a message.
    pub fn new(seq: u32, width: u16, height: u16, flags: u16) -> Self {
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.extend_from_slice(&width.to_le_bytes());
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        Self { buf, n: 0 }
    }

    fn record(&mut self, kind: u8, r: Rect) {
        self.n = self.n.saturating_add(1);
        self.buf.extend_from_slice(&[kind, 0]);
        for v in [r.x, r.y, r.w, r.h] {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Kind 1; `rgba` must be `w·h·4` bytes (the caller reads it from a [`Framebuffer`]).
    pub fn rgba(&mut self, r: Rect, rgba: &[u8]) {
        self.record(1, r);
        self.buf.extend_from_slice(rgba);
    }

    /// Kind 2.
    pub fn copy(&mut self, r: Rect, src_x: u16, src_y: u16) {
        self.record(2, r);
        self.buf.extend_from_slice(&src_x.to_le_bytes());
        self.buf.extend_from_slice(&src_y.to_le_bytes());
    }

    /// Kind 3.
    pub fn fill(&mut self, r: Rect, rgba: [u8; 4]) {
        self.record(3, r);
        self.buf.extend_from_slice(&rgba);
    }

    /// Kinds 4, 5, 6.
    pub fn cursor(&mut self, c: &Cursor) {
        match c {
            Cursor::Sprite { hot_x, hot_y, w, h, rgba } => {
                self.record(4, Rect::new(0, 0, *w, *h));
                self.buf.extend_from_slice(&hot_x.to_le_bytes());
                self.buf.extend_from_slice(&hot_y.to_le_bytes());
                self.buf.extend_from_slice(rgba);
            }
            Cursor::Hidden => self.record(5, Rect::default()),
            Cursor::Default => self.record(6, Rect::default()),
        }
    }

    /// Patch the record count and return the bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.buf[12..14].copy_from_slice(&self.n.to_le_bytes());
        self.buf
    }
}

/// Encode a [`FrameUpdate`] taken from `fb`: one RGBA record per dirty rectangle (≤ 32, or one
/// full rectangle), then the cursor record if the cursor changed. The R1 encoder never emits
/// kinds 2 and 3 (a protocol `copy`/`fill` is sent as the resulting pixels, which keeps the
/// record order trivially correct); [`Mfr1Writer`] and the decoder support them for later.
pub fn encode_update(seq: u32, fb: &Framebuffer, update: &FrameUpdate) -> Vec<u8> {
    let mut flags = 0;
    if update.full {
        flags |= FLAG_FULL;
    }
    if update.resized {
        flags |= FLAG_RESIZED;
    }
    let mut w = Mfr1Writer::new(seq, fb.width(), fb.height(), flags);
    for r in &update.rects {
        if let Ok(px) = fb.read_rect(*r) {
            w.rgba(*r, &px);
        }
    }
    if let Some(c) = &update.cursor {
        w.cursor(c);
    }
    w.finish()
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Mfr1Error> {
        if self.b.len() < n {
            return Err(Mfr1Error::Truncated);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    fn u16(&mut self) -> Result<u16, Mfr1Error> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, Mfr1Error> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// Decode and validate one message. Never panics.
pub fn decode_mfr1(bytes: &[u8]) -> Result<Mfr1Frame, Mfr1Error> {
    let mut r = Reader { b: bytes };
    if r.take(4)? != MAGIC {
        return Err(Mfr1Error::BadMagic);
    }
    let seq = r.u32()?;
    let width = r.u16()?;
    let height = r.u16()?;
    let n = usize::from(r.u16()?);
    let flags = r.u16()?;
    if width > MAX_DIM || height > MAX_DIM || n > MAX_RECORDS {
        return Err(Mfr1Error::TooLarge);
    }
    if bytes.len() > max_message_len(width, height) {
        return Err(Mfr1Error::TooLarge);
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Mfr1Error::BadFlags);
    }
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = r.take(2)?;
        let (kind, reserved) = (kind[0], kind[1]);
        let rect = Rect::new(r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        if reserved != 0 {
            return Err(Mfr1Error::BadRecord);
        }
        let in_fb = rect.fits(width, height);
        let rec = match kind {
            1 => {
                if !in_fb {
                    return Err(Mfr1Error::OutOfBounds);
                }
                let len = usize::try_from(rect.area() * 4).map_err(|_| Mfr1Error::TooLarge)?;
                Mfr1Record::Rgba { rect, data: r.take(len)?.to_vec() }
            }
            2 => {
                let (src_x, src_y) = (r.u16()?, r.u16()?);
                if !in_fb || !Rect::new(src_x, src_y, rect.w, rect.h).fits(width, height) {
                    return Err(Mfr1Error::OutOfBounds);
                }
                Mfr1Record::Copy { rect, src_x, src_y }
            }
            3 => {
                let c = r.take(4)?;
                if !in_fb {
                    return Err(Mfr1Error::OutOfBounds);
                }
                Mfr1Record::Fill { rect, rgba: [c[0], c[1], c[2], c[3]] }
            }
            4 => {
                let (hot_x, hot_y) = (r.u16()?, r.u16()?);
                if rect.x != 0 || rect.y != 0 {
                    return Err(Mfr1Error::BadRecord);
                }
                if rect.w == 0 || rect.h == 0 || rect.w > MAX_CURSOR || rect.h > MAX_CURSOR {
                    return Err(Mfr1Error::BadCursor);
                }
                if hot_x >= rect.w || hot_y >= rect.h {
                    return Err(Mfr1Error::BadCursor);
                }
                let len = usize::try_from(rect.area() * 4).map_err(|_| Mfr1Error::TooLarge)?;
                let rgba = r.take(len)?.to_vec();
                Mfr1Record::Cursor(Cursor::Sprite { hot_x, hot_y, w: rect.w, h: rect.h, rgba })
            }
            5 | 6 => {
                if rect != Rect::default() {
                    return Err(Mfr1Error::BadRecord);
                }
                Mfr1Record::Cursor(if kind == 5 { Cursor::Hidden } else { Cursor::Default })
            }
            _ => return Err(Mfr1Error::BadRecord),
        };
        records.push(rec);
    }
    if !r.b.is_empty() {
        return Err(Mfr1Error::Trailing);
    }
    Ok(Mfr1Frame { seq, width, height, flags, records })
}

#[cfg(test)]
#[path = "mfr1_tests.rs"]
mod tests;
