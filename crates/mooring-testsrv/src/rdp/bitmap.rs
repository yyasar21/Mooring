//! Framebuffer rect → fast-path Bitmap Update PDUs (MS-RDPBCGR 2.2.9.1.2.1.2), fragmented.

use ironrdp_core::{encode_vec, Encode as _, WriteCursor};
use ironrdp_graphics::rdp6::{BitmapStreamEncoder, RgbAChannels};
use ironrdp_pdu::bitmap::{BitmapData, BitmapUpdateData, CompressedDataHeader, Compression};
use ironrdp_pdu::fast_path::{
    EncryptionFlags, FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode,
};
use ironrdp_pdu::geometry::InclusiveRectangle;

use super::{BitmapMode, Framebuffer, Rect};

/// Payload limit of one TS_FP_UPDATE (same constant as `ironrdp-server`).
const MAX_FASTPATH_UPDATE: usize = 16_374;
/// Tile size: 64 × 32 × 4 = 8 KiB raw, so `uncompressed_size` fits a u16.
const TILE_W: u16 = 64;
const TILE_H: u16 = 32;

/// Encodes `r` (inside `fb`) as one or more complete fast-path PDUs, plus the number of
/// planar-compressed tiles. `extra` appends a tile that extends past the desktop (hostile knob).
pub(crate) fn updates(
    fb: &Framebuffer,
    r: Rect,
    mode: BitmapMode,
    extra: Option<u16>,
) -> Result<(Vec<Vec<u8>>, u32), String> {
    let mut pdus = Vec::new();
    let mut planar = 0;
    for tile in crate::rfb::tiles(r, TILE_W, TILE_H) {
        let (update, compressed) = bitmap_update(fb, tile, mode)?;
        planar += u32::from(compressed);
        pdus.extend(fragment(&update)?);
    }
    if let Some(n) = extra {
        let w = 4 + n;
        let tile = Rect::new(fb.width.saturating_sub(4), 0, w, 1);
        let raw = vec![0x55u8; usize::from(w) * 4];
        let data = BitmapData {
            rectangle: inclusive(tile),
            width: w,
            height: 1,
            bits_per_pixel: 32,
            compression_flags: Compression::empty(),
            compressed_data_header: None,
            bitmap_data: &raw,
        };
        let update =
            encode_vec(&BitmapUpdateData { rectangles: vec![data] }).map_err(|e| e.to_string())?;
        pdus.extend(fragment(&update)?);
    }
    Ok((pdus, planar))
}

fn inclusive(r: Rect) -> InclusiveRectangle {
    InclusiveRectangle { left: r.x, top: r.y, right: r.x + r.w - 1, bottom: r.y + r.h - 1 }
}

/// One TS_UPDATE_BITMAP_DATA with a single rect; `true` when planar-compressed.
fn bitmap_update(fb: &Framebuffer, r: Rect, mode: BitmapMode) -> Result<(Vec<u8>, bool), String> {
    let rgba = fb.region(r);
    let row = usize::from(r.w) * 4;
    // Bottom-up rows (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
    let rows_up = || rgba.chunks_exact(row).rev();
    let mut buf = vec![0u8; usize::from(r.w) * usize::from(r.h) * 4 * 2 + 1024];
    let (flags, header, len) = if mode == BitmapMode::Planar && r.w.is_multiple_of(4) {
        let mut enc = BitmapStreamEncoder::new(usize::from(r.w), usize::from(r.h));
        let pixels = rows_up().flat_map(|row| row.chunks_exact(4));
        let len = enc
            .encode_pixels_stream::<_, RgbAChannels>(pixels, &mut buf, true)
            .map_err(|e| e.to_string())?;
        let header = CompressedDataHeader {
            main_body_size: u16::try_from(len).map_err(|e| e.to_string())?,
            scan_width: r.w,
            uncompressed_size: u16::try_from(row * usize::from(r.h)).map_err(|e| e.to_string())?,
        };
        (Compression::BITMAP_COMPRESSION, Some(header), len)
    } else {
        let mut n = 0;
        for line in rows_up() {
            for px in line.chunks_exact(4) {
                buf[n..n + 4].copy_from_slice(&[px[2], px[1], px[0], 0xFF]); // BGRX
                n += 4;
            }
        }
        (Compression::empty(), None, n)
    };
    let compressed = header.is_some();
    let data = BitmapData {
        rectangle: inclusive(r),
        width: r.w,
        height: r.h,
        bits_per_pixel: 32,
        compression_flags: flags,
        compressed_data_header: header,
        bitmap_data: &buf[..len],
    };
    let update =
        encode_vec(&BitmapUpdateData { rectangles: vec![data] }).map_err(|e| e.to_string())?;
    Ok((update, compressed))
}

/// Splits an update into Single / First / Next / Last fast-path PDUs.
fn fragment(update: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let chunks: Vec<&[u8]> = update.chunks(MAX_FASTPATH_UPDATE).collect();
    let last = chunks.len().saturating_sub(1);
    let mut out = Vec::with_capacity(chunks.len());
    for (i, data) in chunks.into_iter().enumerate() {
        let fragmentation = match (i, last) {
            (_, 0) => Fragmentation::Single,
            (0, _) => Fragmentation::First,
            (i, l) if i == l => Fragmentation::Last,
            _ => Fragmentation::Next,
        };
        let pdu = FastPathUpdatePdu {
            fragmentation,
            update_code: UpdateCode::Bitmap,
            compression_flags: None,
            compression_type: None,
            data,
        };
        let header = FastPathHeader::new(EncryptionFlags::empty(), pdu.size());
        let mut buf = vec![0u8; header.size() + pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).map_err(|e| e.to_string())?;
        pdu.encode(&mut cursor).map_err(|e| e.to_string())?;
        let n = cursor.pos();
        buf.truncate(n);
        out.push(buf);
    }
    Ok(out)
}
