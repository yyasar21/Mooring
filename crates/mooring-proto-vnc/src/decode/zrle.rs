//! ZRLE (RFC 6143 §7.7.6): one persistent zlib stream; 64×64 tiles, each raw, solid,
//! packed-palette, plain RLE or palette RLE. With our 32-bpp depth-24 format a CPIXEL is
//! 3 bytes (R, G, B).

use flate2::Decompress;

use super::{inflate, put_cpixel, MAX_INFLATE};
use crate::error::VncError;
use crate::wire::Rd;

/// Tile side.
pub const TILE: usize = 64;

fn truncated(_: usize) -> VncError {
    VncError::protocol("ZRLE data truncated")
}

/// Largest legal inflated size for a `w × h` rectangle: per tile one subencoding byte and a
/// 127-entry palette, per pixel at most 4 bytes (CPIXEL + 1 run byte) plus run extension
/// bytes, which are bounded by the pixel count again.
fn inflate_bound(w: usize, h: usize) -> usize {
    let tiles = w.div_ceil(TILE) * h.div_ceil(TILE);
    (tiles * (1 + 127 * 3)).saturating_add(w * h * 5).min(MAX_INFLATE)
}

fn cpixel(r: &mut Rd<'_>) -> Result<[u8; 3], VncError> {
    let b = r.bytes(3).map_err(truncated)?;
    Ok([b[0], b[1], b[2]])
}

fn run_length(r: &mut Rd<'_>, remaining: usize) -> Result<usize, VncError> {
    let mut len = 1usize;
    loop {
        let b = r.u8().map_err(truncated)?;
        len += usize::from(b);
        if len > remaining {
            return Err(VncError::protocol("ZRLE run exceeds the tile"));
        }
        if b != 255 {
            return Ok(len);
        }
    }
}

/// Decode a ZRLE rectangle. `data` is the zlib payload (after the u32 length). Returns RGBX
/// pixels, `w·h·4` bytes.
pub fn decode_zrle(z: &mut Decompress, data: &[u8], w: u16, h: u16) -> Result<Vec<u8>, VncError> {
    let (w, h) = (usize::from(w), usize::from(h));
    let raw = inflate(z, data, inflate_bound(w, h))?;
    let mut out = vec![0u8; w * h * 4];
    let mut r = Rd::new(&raw);
    let mut tile = Vec::with_capacity(TILE * TILE);
    for ty in (0..h).step_by(TILE) {
        for tx in (0..w).step_by(TILE) {
            let tw = TILE.min(w - tx);
            let th = TILE.min(h - ty);
            tile.clear();
            decode_tile(&mut r, tw, th, &mut tile)?;
            for (i, p) in tile.iter().enumerate() {
                put_cpixel(&mut out, (ty + i / tw) * w + tx + i % tw, *p);
            }
        }
    }
    Ok(out)
}

fn decode_tile(
    r: &mut Rd<'_>,
    tw: usize,
    th: usize,
    tile: &mut Vec<[u8; 3]>,
) -> Result<(), VncError> {
    let n = tw * th;
    let sub = r.u8().map_err(truncated)?;
    match sub {
        0 => {
            for _ in 0..n {
                tile.push(cpixel(r)?);
            }
        }
        1 => {
            let p = cpixel(r)?;
            tile.resize(n, p);
        }
        2..=16 => {
            let size = usize::from(sub);
            let palette = (0..size).map(|_| cpixel(r)).collect::<Result<Vec<_>, _>>()?;
            let bits = match size {
                2 => 1,
                3..=4 => 2,
                _ => 4,
            };
            let row_bytes = (tw * bits).div_ceil(8);
            for _ in 0..th {
                let row = r.bytes(row_bytes).map_err(truncated)?;
                for x in 0..tw {
                    let bit = x * bits;
                    let idx =
                        usize::from((row[bit / 8] >> (8 - bits - bit % 8)) & ((1 << bits) - 1));
                    tile.push(
                        *palette
                            .get(idx)
                            .ok_or_else(|| VncError::protocol("ZRLE palette index"))?,
                    );
                }
            }
        }
        128 => {
            while tile.len() < n {
                let p = cpixel(r)?;
                let len = run_length(r, n - tile.len())?;
                tile.resize(tile.len() + len, p);
            }
        }
        130..=255 => {
            let size = usize::from(sub - 128);
            let palette = (0..size).map(|_| cpixel(r)).collect::<Result<Vec<_>, _>>()?;
            while tile.len() < n {
                let b = r.u8().map_err(truncated)?;
                let p = *palette
                    .get(usize::from(b & 0x7f))
                    .ok_or_else(|| VncError::protocol("ZRLE palette index"))?;
                let len = if b & 0x80 != 0 { run_length(r, n - tile.len())? } else { 1 };
                tile.resize(tile.len() + len, p);
            }
        }
        _ => return Err(VncError::protocol("ZRLE reserved subencoding")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    /// Compress like a server: one persistent stream, a sync flush per rectangle.
    pub(crate) fn zlib_chunk(c: &mut Compress, raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len() * 2 + 64);
        c.compress_vec(raw, &mut out, FlushCompress::Sync).expect("compress");
        out
    }

    fn run(raws: &[&[u8]], w: u16, h: u16) -> Vec<Result<Vec<u8>, VncError>> {
        let mut c = Compress::new(Compression::default(), true);
        let mut z = Decompress::new(true);
        raws.iter().map(|raw| decode_zrle(&mut z, &zlib_chunk(&mut c, raw), w, h)).collect()
    }

    const R: [u8; 3] = [255, 0, 0];
    const G: [u8; 3] = [0, 255, 0];

    #[test]
    fn solid_raw_and_persistent_stream() {
        let solid = [&[1u8][..], &R].concat();
        let mut raw = vec![0u8];
        for i in 0..4u8 {
            raw.extend_from_slice(&[i, i, i]);
        }
        let out = run(&[&solid, &raw], 2, 2);
        assert_eq!(out[0].as_ref().expect("solid"), &[255, 0, 0, 0].repeat(4));
        assert_eq!(
            out[1].as_ref().expect("raw"),
            &[0, 0, 0, 0, 1, 1, 1, 0, 2, 2, 2, 0, 3, 3, 3, 0]
        );
    }

    #[test]
    fn packed_palette_and_rle() {
        // 3x2 tile, palette of 2 (1 bit): rows 101, 010.
        let mut pal = vec![2u8];
        pal.extend_from_slice(&R);
        pal.extend_from_slice(&G);
        pal.extend_from_slice(&[0b1010_0000, 0b0100_0000]);
        let px = run(&[&pal], 3, 2).remove(0).expect("palette");
        let at = |i: usize| [px[i * 4], px[i * 4 + 1], px[i * 4 + 2]];
        assert_eq!([at(0), at(1), at(2), at(3), at(4), at(5)], [G, R, G, R, G, R]);

        // Plain RLE: 4 red then 2 green (run bytes are len-1).
        let mut rle = vec![128u8];
        rle.extend_from_slice(&R);
        rle.push(3);
        rle.extend_from_slice(&G);
        rle.push(1);
        let px = run(&[&rle], 3, 2).remove(0).expect("rle");
        assert_eq!(&px[16..20], &[0, 255, 0, 0]);
        assert_eq!(&px[12..16], &[255, 0, 0, 0]);

        // Palette RLE: size 2; index 1 run of 5 (0x81, 4), then single index 0.
        let mut prle = vec![130u8];
        prle.extend_from_slice(&R);
        prle.extend_from_slice(&G);
        prle.extend_from_slice(&[0x81, 4, 0x00]);
        let px = run(&[&prle], 3, 2).remove(0).expect("prle");
        assert_eq!(&px[0..4], &[0, 255, 0, 0]);
        assert_eq!(&px[20..24], &[255, 0, 0, 0]);
    }

    #[test]
    fn hostile_tiles_are_errors_not_panics() {
        let cases: [&[u8]; 9] = [
            &[],                                   // no tile at all
            &[0, 1, 2],                            // raw, truncated
            &[17],                                 // reserved
            &[129],                                // reserved
            &[2, 1, 1, 1],                         // palette truncated
            &[128, 1, 2, 3, 255, 255],             // run longer than the tile
            &[130, 1, 1, 1, 2, 2, 2, 0x05],        // palette index out of range
            &[3, 1, 1, 1, 2, 2, 2, 3, 3, 3, 0xff], // 2-bit index 3 >= 3
            &[128, 1, 2, 3],                       // run length missing
        ];
        for raw in cases {
            assert!(run(&[raw], 2, 2).remove(0).is_err(), "{raw:?}");
        }
        // Corrupt zlib.
        let mut z = Decompress::new(true);
        assert!(decode_zrle(&mut z, &[0xde, 0xad, 0xbe, 0xef], 2, 2).is_err());
    }

    #[test]
    fn zlib_bomb_is_capped() {
        // A 1x1 rect may inflate to at most a few hundred bytes; send 1 MiB of zeros.
        let zeros = vec![0u8; 1 << 20];
        let r = run(&[&zeros], 1, 1).remove(0);
        assert!(matches!(r, Err(VncError::Protocol(ref m)) if m.contains("cap")), "{r:?}");
        assert!(inflate_bound(8192, 8192) <= MAX_INFLATE);
    }

    proptest::proptest! {
        #[test]
        fn never_panics(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600),
                        w in 0u16..80, h in 0u16..80) {
            let _ = run(&[&raw], w, h);
            let mut z = Decompress::new(true);
            let _ = decode_zrle(&mut z, &raw, w, h);
        }
    }
}
