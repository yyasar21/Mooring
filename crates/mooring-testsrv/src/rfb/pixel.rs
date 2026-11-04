//! RFB PIXEL_FORMAT (RFC 6143 §7.4) and pixel packing, incl. ZRLE CPIXEL and Tight TPIXEL.

/// The 16-byte PIXEL_FORMAT. Only true-colour formats with 8, 16 or 32 bits per pixel are
/// served; a colour-map format ends the connection (documented limit of the test server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    /// What ServerInit announces: 32 bpp, depth 24, little-endian BGRX (shifts 16/8/0).
    pub const SERVER_DEFAULT: Self = Self {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    /// The format ADR-0012 has the Mooring client request (RGBX, shifts 0/8/16).
    pub const RGBX: Self =
        Self { red_shift: 0, green_shift: 8, blue_shift: 16, ..Self::SERVER_DEFAULT };

    pub fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = self.bits_per_pixel;
        b[1] = self.depth;
        b[2] = u8::from(self.big_endian);
        b[3] = u8::from(self.true_colour);
        b[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        b[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        b[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        b[10] = self.red_shift;
        b[11] = self.green_shift;
        b[12] = self.blue_shift;
        b
    }

    pub fn from_bytes(b: &[u8; 16]) -> Self {
        Self {
            bits_per_pixel: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            red_max: u16::from_be_bytes([b[4], b[5]]),
            green_max: u16::from_be_bytes([b[6], b[7]]),
            blue_max: u16::from_be_bytes([b[8], b[9]]),
            red_shift: b[10],
            green_shift: b[11],
            blue_shift: b[12],
        }
    }

    /// Whether the server can encode for this format.
    pub fn is_supported(&self) -> bool {
        self.true_colour
            && matches!(self.bits_per_pixel, 8 | 16 | 32)
            && [self.red_shift, self.green_shift, self.blue_shift]
                .iter()
                .all(|s| u32::from(*s) < u32::from(self.bits_per_pixel))
    }

    pub fn bytes_per_pixel(&self) -> usize {
        usize::from(self.bits_per_pixel / 8)
    }

    fn value(&self, rgba: &[u8]) -> u32 {
        let scale = |c: u8, max: u16| u32::from(c) * u32::from(max) / 255;
        (scale(rgba[0], self.red_max) << self.red_shift)
            | (scale(rgba[1], self.green_max) << self.green_shift)
            | (scale(rgba[2], self.blue_max) << self.blue_shift)
    }

    /// Appends one PIXEL (bits_per_pixel / 8 bytes) for an RGBA source pixel.
    pub fn push_pixel(&self, rgba: &[u8], out: &mut Vec<u8>) {
        let v = self.value(rgba);
        let n = self.bytes_per_pixel();
        if self.big_endian {
            out.extend_from_slice(&v.to_be_bytes()[4 - n..]);
        } else {
            out.extend_from_slice(&v.to_le_bytes()[..n]);
        }
    }

    /// ZRLE CPIXEL: 3 bytes when bpp is 32, depth ≤ 24 and every colour bit lies in the
    /// least (or most) significant three bytes; a full PIXEL otherwise (RFC 6143 §7.7.6).
    pub fn push_cpixel(&self, rgba: &[u8], out: &mut Vec<u8>) {
        if let Some(low) = self.compact_side() {
            let v = self.value(rgba);
            let le = v.to_le_bytes();
            let be = v.to_be_bytes();
            let three: &[u8] = match (low, self.big_endian) {
                (true, false) => &le[..3],
                (true, true) => &be[1..],
                (false, false) => &le[1..],
                (false, true) => &be[..3],
            };
            out.extend_from_slice(three);
        } else {
            self.push_pixel(rgba, out);
        }
    }

    /// `Some(true)` = colour fits the low 3 bytes, `Some(false)` = the high 3, `None` = no CPIXEL.
    fn compact_side(&self) -> Option<bool> {
        if self.bits_per_pixel != 32 || self.depth > 24 {
            return None;
        }
        let mask = self.value(&[255, 255, 255, 255]);
        if mask & 0xFF00_0000 == 0 {
            Some(true)
        } else if mask.trailing_zeros() >= 8 {
            Some(false)
        } else {
            None
        }
    }

    pub fn cpixel_len(&self) -> usize {
        if self.compact_side().is_some() {
            3
        } else {
            self.bytes_per_pixel()
        }
    }

    /// Tight TPIXEL: R, G, B bytes when bpp 32, depth 24 and every max is 255; a PIXEL otherwise.
    pub fn push_tpixel(&self, rgba: &[u8], out: &mut Vec<u8>) {
        if self.tight_compact() {
            out.extend_from_slice(&rgba[..3]);
        } else {
            self.push_pixel(rgba, out);
        }
    }

    pub fn tight_compact(&self) -> bool {
        self.bits_per_pixel == 32
            && self.depth == 24
            && self.red_max == 255
            && self.green_max == 255
            && self.blue_max == 255
    }
}

#[cfg(test)]
mod tests {
    use super::PixelFormat;

    #[test]
    fn bytes_round_trip_and_packing() {
        let pf = PixelFormat::RGBX;
        assert_eq!(PixelFormat::from_bytes(&pf.to_bytes()), pf);
        let mut out = Vec::new();
        pf.push_pixel(&[1, 2, 3, 255], &mut out);
        assert_eq!(out, [1, 2, 3, 0]);
        out.clear();
        PixelFormat::SERVER_DEFAULT.push_pixel(&[1, 2, 3, 255], &mut out);
        assert_eq!(out, [3, 2, 1, 0]);
        out.clear();
        pf.push_cpixel(&[1, 2, 3, 255], &mut out);
        assert_eq!(out, [1, 2, 3]);
        let be = PixelFormat { big_endian: true, ..pf };
        out.clear();
        be.push_cpixel(&[1, 2, 3, 255], &mut out);
        assert_eq!(out, [3, 2, 1]);
        let rgb565 = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            ..pf
        };
        assert!(rgb565.is_supported());
        assert_eq!(rgb565.cpixel_len(), 2);
        out.clear();
        rgb565.push_pixel(&[255, 255, 255, 255], &mut out);
        assert_eq!(out, [0xFF, 0xFF]);
        assert!(!PixelFormat { true_colour: false, ..pf }.is_supported());
    }
}
