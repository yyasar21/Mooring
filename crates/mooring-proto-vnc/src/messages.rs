//! RFB normal-phase messages (RFC 6143 §7.5, §7.6): server message headers and rectangle
//! framing as pure parsers, client messages as encoders.
//!
//! A `FramebufferUpdate` is parsed as a header ([`ServerMessage::FramebufferUpdate`]) and then
//! one rectangle at a time with [`parse_rect`], which frames the rectangle (computes its
//! length) without touching the persistent zlib streams; decoding happens once the whole
//! rectangle is buffered.

use mooring_core::frame::Rect;

use crate::decode::tight;
use crate::error::VncError;
use crate::wire::{len_u32, take, PResult, Parsed, Rd};

/// Longest `ServerCutText` / `ClientCutText`, in bytes (ADR-0012: 1 MiB).
pub const MAX_CUT_TEXT: usize = 1024 * 1024;
/// Longest ZRLE compressed payload accepted for one rectangle.
pub const MAX_ZRLE_COMPRESSED: usize = 64 * 1024 * 1024;
/// Largest cursor sprite side (ADR-0011).
pub const MAX_CURSOR: u16 = mooring_core::frame::MAX_CURSOR;
/// Most screens in an `ExtendedDesktopSize` rectangle.
pub const MAX_SCREENS: usize = 16;

/// Encodings.
pub mod enc {
    /// Raw.
    pub const RAW: i32 = 0;
    /// `CopyRect`.
    pub const COPY_RECT: i32 = 1;
    /// Tight.
    pub const TIGHT: i32 = 7;
    /// ZRLE.
    pub const ZRLE: i32 = 16;
    /// `DesktopSize` pseudo-encoding.
    pub const DESKTOP_SIZE: i32 = -223;
    /// `LastRect` pseudo-encoding.
    pub const LAST_RECT: i32 = -224;
    /// Cursor pseudo-encoding.
    pub const CURSOR: i32 = -239;
    /// QEMU Extended Key Event pseudo-encoding.
    pub const QEMU_EXT_KEY: i32 = -258;
    /// `ExtendedDesktopSize` pseudo-encoding.
    pub const EXT_DESKTOP_SIZE: i32 = -308;
    /// What we advertise, in preference order (ADR-0012). No Tight JPEG quality level.
    pub const ADVERTISED: [i32; 9] = [
        COPY_RECT,
        ZRLE,
        TIGHT,
        RAW,
        DESKTOP_SIZE,
        EXT_DESKTOP_SIZE,
        LAST_RECT,
        CURSOR,
        QEMU_EXT_KEY,
    ];
}

/// A server-to-client message (header level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    /// `FramebufferUpdate` header: this many rectangles follow.
    FramebufferUpdate {
        /// Rectangle count (65535 may be ended early by `LastRect`).
        rects: u16,
    },
    /// `SetColourMapEntries`: we requested true colour, so the session refuses it.
    SetColourMapEntries,
    /// `Bell`.
    Bell,
    /// `ServerCutText` within the cap, converted from Latin-1.
    CutText(String),
    /// `ServerCutText` over the cap: the session discards `len` bytes that follow.
    CutTextTooLong {
        /// Bytes to discard after the 8-byte header.
        len: usize,
    },
}

/// Parse one server message header (or a whole small message).
pub fn parse_server_message(buf: &[u8]) -> PResult<ServerMessage> {
    let mut r = Rd::new(buf);
    match take!(r.u8()) {
        0 => {
            take!(r.skip(1));
            let rects = take!(r.u16());
            Ok(Parsed::Done(ServerMessage::FramebufferUpdate { rects }, r.pos()))
        }
        1 => {
            take!(r.skip(3));
            let n = usize::from(take!(r.u16()));
            take!(r.skip(n * 6));
            Ok(Parsed::Done(ServerMessage::SetColourMapEntries, r.pos()))
        }
        2 => Ok(Parsed::Done(ServerMessage::Bell, 1)),
        3 => {
            take!(r.skip(3));
            let len = len_u32(take!(r.u32()));
            if len > MAX_CUT_TEXT {
                return Ok(Parsed::Done(ServerMessage::CutTextTooLong { len }, r.pos()));
            }
            let text = take!(r.bytes(len));
            Ok(Parsed::Done(ServerMessage::CutText(latin1_to_string(text)), r.pos()))
        }
        t => Err(VncError::protocol(format!("unknown server message type {t}"))),
    }
}

/// Latin-1 → UTF-8 (every byte is a code point; NUL and other controls except tab/newline
/// are dropped).
pub fn latin1_to_string(b: &[u8]) -> String {
    b.iter()
        .map(|&c| char::from(c))
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\n'))
        .collect()
}

/// UTF-8 → Latin-1; `None` when a character has no Latin-1 encoding (refused, not replaced).
pub fn string_to_latin1(s: &str) -> Option<Vec<u8>> {
    s.chars().map(|c| u8::try_from(u32::from(c)).ok()).collect()
}

/// A rectangle header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RectHeader {
    /// Position and size.
    pub rect: Rect,
    /// Encoding type.
    pub encoding: i32,
}

/// A fully buffered rectangle: header plus the payload range within the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RectFrame {
    /// Header.
    pub header: RectHeader,
    /// Payload start (always 12).
    pub start: usize,
    /// Payload end (= bytes consumed).
    pub end: usize,
}

/// Frame one rectangle of a `FramebufferUpdate` for a `fb_w × fb_h` framebuffer with our
/// 32-bpp format. Bounds are checked here: pixel rectangles must lie within the framebuffer,
/// cursors ≤ 384², new desktop sizes 1..=8192.
pub fn parse_rect(buf: &[u8], fb_w: u16, fb_h: u16) -> PResult<RectFrame> {
    let mut r = Rd::new(buf);
    let rect = Rect::new(take!(r.u16()), take!(r.u16()), take!(r.u16()), take!(r.u16()));
    let encoding = take!(r.i32());
    let header = RectHeader { rect, encoding };
    let start = r.pos();
    let area = usize::from(rect.w) * usize::from(rect.h);
    let in_fb = || {
        if rect.fits(fb_w, fb_h) {
            Ok(())
        } else {
            Err(VncError::protocol("rectangle outside the framebuffer"))
        }
    };
    let payload = match encoding {
        enc::RAW => {
            in_fb()?;
            area * 4
        }
        enc::COPY_RECT => {
            in_fb()?;
            4
        }
        enc::ZRLE => {
            in_fb()?;
            let n = len_u32(take!(r.u32()));
            if n > MAX_ZRLE_COMPRESSED {
                return Err(VncError::protocol("ZRLE payload too large"));
            }
            4 + n
        }
        enc::TIGHT => {
            in_fb()?;
            match tight::frame_len(&buf[start..], rect.w, rect.h)? {
                Parsed::Need(n) => return Ok(Parsed::Need(start + n)),
                Parsed::Done((), n) => n,
            }
        }
        enc::CURSOR => {
            if rect.w > MAX_CURSOR || rect.h > MAX_CURSOR {
                return Err(VncError::protocol("cursor larger than 384x384"));
            }
            area * 4 + usize::from(rect.w).div_ceil(8) * usize::from(rect.h)
        }
        enc::EXT_DESKTOP_SIZE => {
            let n = usize::from(take!(r.u8()));
            if n == 0 || n > MAX_SCREENS {
                return Err(VncError::protocol("ExtendedDesktopSize screen count out of range"));
            }
            4 + 16 * n
        }
        enc::DESKTOP_SIZE | enc::LAST_RECT | enc::QEMU_EXT_KEY => 0,
        e => return Err(VncError::protocol(format!("unrequested encoding {e}"))),
    };
    let end = start.checked_add(payload).ok_or_else(|| VncError::protocol("length overflow"))?;
    if buf.len() < end {
        return Ok(Parsed::Need(end));
    }
    Ok(Parsed::Done(RectFrame { header, start, end }, end))
}

/// The first screen id of an `ExtendedDesktopSize` payload (needed for `SetDesktopSize`).
pub fn ext_desktop_screen(payload: &[u8]) -> Option<(u32, u32)> {
    let id = u32::from_be_bytes(payload.get(4..8)?.try_into().ok()?);
    let flags = u32::from_be_bytes(payload.get(16..20)?.try_into().ok()?);
    Some((id, flags))
}

/// Client messages.
pub mod client {
    use super::Rect;
    use crate::handshake::PixelFormat;

    /// `SetPixelFormat`.
    pub fn set_pixel_format(f: &PixelFormat) -> Vec<u8> {
        let mut m = vec![0, 0, 0, 0];
        m.extend_from_slice(&f.encode());
        m
    }

    /// `SetEncodings`.
    pub fn set_encodings(list: &[i32]) -> Vec<u8> {
        let mut m = vec![2, 0];
        m.extend_from_slice(&u16::try_from(list.len()).unwrap_or(0).to_be_bytes());
        for e in list {
            m.extend_from_slice(&e.to_be_bytes());
        }
        m
    }

    /// `FramebufferUpdateRequest`.
    pub fn update_request(incremental: bool, r: Rect) -> Vec<u8> {
        let mut m = vec![3, u8::from(incremental)];
        for v in [r.x, r.y, r.w, r.h] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m
    }

    /// `KeyEvent`.
    pub fn key_event(down: bool, keysym: u32) -> Vec<u8> {
        let mut m = vec![4, u8::from(down), 0, 0];
        m.extend_from_slice(&keysym.to_be_bytes());
        m
    }

    /// QEMU Extended Key Event (scancode + keysym).
    pub fn qemu_key_event(down: bool, keysym: u32, keycode: u32) -> Vec<u8> {
        let mut m = vec![255, 0, 0, u8::from(down)];
        m.extend_from_slice(&keysym.to_be_bytes());
        m.extend_from_slice(&keycode.to_be_bytes());
        m
    }

    /// `PointerEvent`.
    pub fn pointer_event(mask: u8, x: u16, y: u16) -> Vec<u8> {
        let mut m = vec![5, mask];
        m.extend_from_slice(&x.to_be_bytes());
        m.extend_from_slice(&y.to_be_bytes());
        m
    }

    /// `ClientCutText` (Latin-1 bytes, already capped by the caller).
    pub fn cut_text(latin1: &[u8]) -> Vec<u8> {
        let mut m = vec![6, 0, 0, 0];
        m.extend_from_slice(&u32::try_from(latin1.len()).unwrap_or(0).to_be_bytes());
        m.extend_from_slice(latin1);
        m
    }

    /// `SetDesktopSize` with one screen.
    pub fn set_desktop_size(w: u16, h: u16, screen_id: u32, flags: u32) -> Vec<u8> {
        let mut m = vec![251, 0];
        m.extend_from_slice(&w.to_be_bytes());
        m.extend_from_slice(&h.to_be_bytes());
        m.extend_from_slice(&[1, 0]);
        m.extend_from_slice(&screen_id.to_be_bytes());
        for v in [0u16, 0, w, h] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&flags.to_be_bytes());
        m
    }
}

#[cfg(test)]
#[path = "messages_tests.rs"]
mod tests;
