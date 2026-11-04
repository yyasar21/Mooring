//! RFB 3.8 handshake messages (RFC 6143 §7.1, §7.3): pure parsers and encoders.
//!
//! Only `RFB 003.008` is spoken (ADR-0012). A server announcing 3.3 or 3.7 is refused,
//! because 3.3 lets the server dictate the security type (downgrade). A server announcing a
//! newer 3.x (e.g. Apple's 3.889) gets our 3.8 answer, as RFC 6143 §7.1.1 prescribes.

use crate::error::{sanitize_server_text, VncError};
use crate::wire::{len_u32, take, PResult, Parsed, Rd};

/// What we send after the server's version.
pub const CLIENT_VERSION: &[u8; 12] = b"RFB 003.008\n";
/// Longest failure reason accepted, in bytes (ADR-0012).
pub const MAX_REASON: usize = 4096;
/// Longest desktop name accepted, in bytes (ADR-0012 L-2).
pub const MAX_NAME: usize = 4096;
/// Largest framebuffer width or height.
pub const MAX_FB: u16 = mooring_core::frame::MAX_DIM;

/// Parse the 12-byte `ProtocolVersion`. `Ok(Done(minor))` when acceptable.
pub fn parse_version(buf: &[u8]) -> PResult<u16> {
    let mut r = Rd::new(buf);
    let v = take!(r.bytes(12));
    let digits = |s: &[u8]| -> Option<u16> {
        if s.len() == 3 && s.iter().all(u8::is_ascii_digit) {
            Some(s.iter().fold(0u16, |a, d| a * 10 + u16::from(d - b'0')))
        } else {
            None
        }
    };
    if &v[..4] != b"RFB " || v[7] != b'.' || v[11] != b'\n' {
        return Err(VncError::protocol("not an RFB server"));
    }
    let (Some(major), Some(minor)) = (digits(&v[4..7]), digits(&v[8..11])) else {
        return Err(VncError::protocol("malformed RFB version"));
    };
    if major != 3 || minor < 8 {
        return Err(VncError::Unsupported(format!("RFB {major}.{minor} (only 3.8 is supported)")));
    }
    Ok(Parsed::Done(minor, 12))
}

/// A length-prefixed reason string (u32 + bytes), capped at [`MAX_REASON`]. Returns the
/// sanitised text.
pub fn parse_reason(buf: &[u8]) -> PResult<String> {
    let mut r = Rd::new(buf);
    let n = len_u32(take!(r.u32()));
    if n > MAX_REASON {
        return Err(VncError::protocol("failure reason too long"));
    }
    let text = take!(r.bytes(n));
    Ok(Parsed::Done(sanitize_server_text(text), r.pos()))
}

/// The server's security type list (3.8: `u8 n`, `n` types). `n == 0` carries a reason and
/// becomes an error.
pub fn parse_security_types(buf: &[u8]) -> PResult<Vec<u8>> {
    let mut r = Rd::new(buf);
    let n = usize::from(take!(r.u8()));
    if n == 0 {
        return match parse_reason(&buf[1..])? {
            Parsed::Need(k) => Ok(Parsed::Need(k + 1)),
            Parsed::Done(reason, _) => {
                Err(VncError::ServerEnded(format!("server refused: {reason}")))
            }
        };
    }
    let types = take!(r.bytes(n)).to_vec();
    Ok(Parsed::Done(types, r.pos()))
}

/// `SecurityResult`: `Ok(Done(()))` on success; failure carries the 3.8 reason.
pub fn parse_security_result(buf: &[u8]) -> PResult<()> {
    let mut r = Rd::new(buf);
    match take!(r.u32()) {
        0 => Ok(Parsed::Done((), 4)),
        1 | 2 => match parse_reason(&buf[4..]) {
            Ok(Parsed::Need(k)) => Ok(Parsed::Need(k + 4)),
            Ok(Parsed::Done(reason, _)) => Err(VncError::AuthFailed(if reason.is_empty() {
                "server refused the credentials".to_owned()
            } else {
                format!("server: {reason}")
            })),
            // An oversized reason after a failure is still a failure.
            Err(_) => Err(VncError::AuthFailed("server refused the credentials".to_owned())),
        },
        _ => Err(VncError::protocol("invalid SecurityResult")),
    }
}

/// RFB `PIXEL_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    /// Bits per pixel.
    pub bpp: u8,
    /// Depth.
    pub depth: u8,
    /// Big-endian flag.
    pub big_endian: bool,
    /// True-colour flag.
    pub true_colour: bool,
    /// Max values and shifts (r, g, b).
    pub max: [u16; 3],
    /// Shifts (r, g, b).
    pub shift: [u8; 3],
}

impl PixelFormat {
    /// What we request (ADR-0012): 32 bpp, depth 24, little-endian, true colour, shifts
    /// 0/8/16. On the wire each pixel is then R, G, B, X — `PixelOrder::Rgbx`.
    pub const RGBX: Self = Self {
        bpp: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        max: [255, 255, 255],
        shift: [0, 8, 16],
    };

    /// The 16 wire bytes.
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = self.bpp;
        b[1] = self.depth;
        b[2] = u8::from(self.big_endian);
        b[3] = u8::from(self.true_colour);
        for i in 0..3 {
            b[4 + 2 * i..6 + 2 * i].copy_from_slice(&self.max[i].to_be_bytes());
        }
        b[10..13].copy_from_slice(&self.shift);
        b
    }

    fn decode(b: &[u8]) -> Self {
        Self {
            bpp: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            max: [
                u16::from_be_bytes([b[4], b[5]]),
                u16::from_be_bytes([b[6], b[7]]),
                u16::from_be_bytes([b[8], b[9]]),
            ],
            shift: [b[10], b[11], b[12]],
        }
    }
}

/// `ServerInit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInit {
    /// Framebuffer width.
    pub width: u16,
    /// Framebuffer height.
    pub height: u16,
    /// The server's native pixel format (replaced by ours right away).
    pub format: PixelFormat,
    /// Desktop name, sanitised and capped.
    pub name: String,
}

/// Parse `ServerInit`. The size must be 1..=8192 per side; the name ≤ 4 KiB.
pub fn parse_server_init(buf: &[u8]) -> PResult<ServerInit> {
    let mut r = Rd::new(buf);
    let width = take!(r.u16());
    let height = take!(r.u16());
    let format = PixelFormat::decode(take!(r.bytes(16)));
    let n = len_u32(take!(r.u32()));
    if n > MAX_NAME {
        return Err(VncError::protocol("desktop name too long"));
    }
    if width == 0 || height == 0 || width > MAX_FB || height > MAX_FB {
        return Err(VncError::protocol("framebuffer size out of range"));
    }
    let name = sanitize_server_text(take!(r.bytes(n)));
    Ok(Parsed::Done(ServerInit { width, height, format, name }, r.pos()))
}

/// `ClientInit` (shared flag).
pub fn client_init(shared: bool) -> [u8; 1] {
    [u8::from(shared)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matrix() {
        assert_eq!(parse_version(b"RFB 003.008\n").expect("v"), Parsed::Done(8, 12));
        assert_eq!(parse_version(b"RFB 003.889\n").expect("v"), Parsed::Done(889, 12));
        assert_eq!(parse_version(b"RFB 003.00").expect("v"), Parsed::Need(12));
        for bad in [&b"RFB 003.003\n"[..], b"RFB 003.007\n", b"RFB 004.001\n"] {
            assert!(matches!(parse_version(bad), Err(VncError::Unsupported(_))), "{bad:?}");
        }
        for bad in [&b"SSH-2.0-xxxx"[..], b"RFB 0a3.008\n", b"RFB 003.008\r"] {
            assert!(matches!(parse_version(bad), Err(VncError::Protocol(_))), "{bad:?}");
        }
    }

    #[test]
    fn security_types_and_refusal() {
        assert_eq!(parse_security_types(&[2, 19, 2]).expect("t"), Parsed::Done(vec![19, 2], 3));
        assert_eq!(parse_security_types(&[2, 19]).expect("t"), Parsed::Need(3));
        assert_eq!(parse_security_types(&[0, 0, 0]).expect("t"), Parsed::Need(5));
        let mut refusal = vec![0, 0, 0, 0, 4];
        refusal.extend_from_slice(b"no\x07!");
        match parse_security_types(&refusal) {
            Err(VncError::ServerEnded(r)) => assert!(r.ends_with("no!"), "{r}"),
            other => panic!("{other:?}"),
        }
        assert!(parse_security_types(&[0, 0, 0, 0x10, 1]).is_err(), "reason > 4 KiB");
    }

    #[test]
    fn security_result() {
        assert_eq!(parse_security_result(&[0, 0, 0, 0]).expect("r"), Parsed::Done((), 4));
        assert_eq!(parse_security_result(&[0, 0, 0, 1, 0]).expect("r"), Parsed::Need(8));
        let mut fail = vec![0, 0, 0, 1, 0, 0, 0, 3];
        fail.extend_from_slice(b"bad");
        assert_eq!(parse_security_result(&fail), Err(VncError::AuthFailed("server: bad".into())));
        assert!(matches!(parse_security_result(&[0, 0, 0, 9]), Err(VncError::Protocol(_))));
    }

    #[test]
    fn pixel_format_bytes() {
        assert_eq!(
            PixelFormat::RGBX.encode(),
            [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0]
        );
        assert_eq!(PixelFormat::decode(&PixelFormat::RGBX.encode()), PixelFormat::RGBX);
    }

    #[test]
    fn server_init_caps() {
        let mut b = vec![0x07, 0x80, 0x04, 0x38];
        b.extend_from_slice(&PixelFormat::RGBX.encode());
        b.extend_from_slice(&[0, 0, 0, 3]);
        assert_eq!(parse_server_init(&b).expect("i"), Parsed::Need(27));
        b.extend_from_slice(b"d\x1bk");
        let Parsed::Done(init, 27) = parse_server_init(&b).expect("i") else { panic!() };
        assert_eq!((init.width, init.height, init.name.as_str()), (1920, 1080, "dk"));
        let mut huge = b.clone();
        huge[0..2].copy_from_slice(&8193u16.to_be_bytes());
        assert!(parse_server_init(&huge).is_err());
        let mut zero = b.clone();
        zero[2..4].copy_from_slice(&[0, 0]);
        assert!(parse_server_init(&zero).is_err());
        let mut long = b[..20].to_vec();
        long.extend_from_slice(&[0, 0, 0x10, 1]);
        assert!(parse_server_init(&long).is_err(), "name > 4 KiB refused before reading it");
        assert_eq!(client_init(true), [1]);
    }
}
