use super::*;
use flate2::{Compress, Compression, FlushCompress};

fn compact(n: usize) -> Vec<u8> {
    let mut v = vec![u8::try_from(n & 0x7f).expect("b")];
    if n > 0x7f {
        v[0] |= 0x80;
        v.push(u8::try_from((n >> 7) & 0x7f).expect("b"));
        if n > 0x3fff {
            v[1] |= 0x80;
            v.push(u8::try_from(n >> 14).expect("b"));
        }
    }
    v
}

fn chunk(c: &mut Compress, raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() * 2 + 64);
    c.compress_vec(raw, &mut out, FlushCompress::Sync).expect("compress");
    out
}

/// A basic rect: control, optional filter bytes, then data (raw or compact + zlib).
fn basic(c: &mut Compress, control: u8, filter: &[u8], raw: &[u8]) -> Vec<u8> {
    let mut m = vec![control];
    m.extend_from_slice(filter);
    if raw.len() < MIN_COMPRESS {
        m.extend_from_slice(raw);
    } else {
        let z = chunk(c, raw);
        m.extend_from_slice(&compact(z.len()));
        m.extend_from_slice(&z);
    }
    m
}

fn decode(data: &[u8], w: u16, h: u16) -> Result<TightOutput, VncError> {
    let mut s = TightStreams::default();
    decode_tight(&mut s, data, w, h)
}

#[test]
fn fill_and_jpeg_refusal() {
    let fill = [0x80, 1, 2, 3];
    assert_eq!(frame_len(&fill, 9, 9).expect("f"), Parsed::Done((), 4));
    assert_eq!(decode(&fill, 9, 9).expect("fill"), TightOutput::Fill([1, 2, 3]));
    assert_eq!(frame_len(&fill[..2], 9, 9).expect("f"), Parsed::Need(4));
    assert!(frame_len(&[0x90, 0, 0], 4, 4).is_err(), "JPEG refused");
    assert!(frame_len(&[0xA0], 4, 4).is_err(), "PNG / invalid refused");
    assert!(frame_len(&[0x40, 7], 4, 4).is_err(), "unknown filter");
}

#[test]
fn copy_filter_uncompressed_and_compressed() {
    // 2x1 copy filter: 6 bytes < 12, sent raw.
    let raw = [1, 2, 3, 4, 5, 6];
    let mut c = Compress::new(Compression::default(), true);
    let m = basic(&mut c, 0x00, &[], &raw);
    assert_eq!(frame_len(&m, 2, 1).expect("f"), Parsed::Done((), 7));
    assert_eq!(decode(&m, 2, 1).expect("d"), TightOutput::Pixels(vec![1, 2, 3, 0, 4, 5, 6, 0]));

    // 4x4 copy filter on stream 2 with an explicit filter byte: 48 bytes, zlib.
    let raw: Vec<u8> = (0..48).collect();
    let m = basic(&mut c, 0x60, &[0], &raw);
    let Parsed::Done((), n) = frame_len(&m, 4, 4).expect("f") else { panic!() };
    assert_eq!(n, m.len());
    let TightOutput::Pixels(px) = decode(&m, 4, 4).expect("d") else { panic!() };
    assert_eq!(&px[4..8], &[3, 4, 5, 0]);
    assert_eq!(frame_len(&m[..m.len() - 1], 4, 4).expect("f"), Parsed::Need(m.len()));
}

#[test]
fn persistent_streams_and_reset() {
    let raw: Vec<u8> = (0..48).collect();
    let mut c = Compress::new(Compression::default(), true);
    let mut s = TightStreams::default();
    let a = basic(&mut c, 0x00, &[], &raw);
    let b = basic(&mut c, 0x00, &[], &raw); // continues the same zlib stream (no header)
    assert!(decode_tight(&mut s, &a, 4, 4).is_ok());
    assert!(decode_tight(&mut s, &b, 4, 4).is_ok());
    // A fresh compressor after a reset bit on stream 0.
    let mut c2 = Compress::new(Compression::default(), true);
    let fresh = basic(&mut c2, 0x01, &[], &raw);
    assert!(decode_tight(&mut s, &fresh, 4, 4).is_ok());
    // Without the reset bit, a fresh zlib header on a running stream is corrupt.
    let mut c3 = Compress::new(Compression::default(), true);
    let bad = basic(&mut c3, 0x00, &[], &raw);
    assert!(decode_tight(&mut s, &bad, 4, 4).is_err());
}

#[test]
fn palette_filters() {
    let mut c = Compress::new(Compression::default(), true);
    // 2 colours, 1 bit per pixel: 10x2 → 2 bytes per row, 4 bytes < 12 raw.
    let filter = [1, 1, 10, 0, 0, 0, 0, 20];
    let m = basic(&mut c, 0x40, &filter, &[0b1000_0000, 0b0100_0000, 0, 0xff]);
    let TightOutput::Pixels(px) = decode(&m, 10, 2).expect("d") else { panic!() };
    assert_eq!(&px[0..4], &[0, 0, 20, 0], "bit 1 = palette[1]");
    assert_eq!(&px[4..8], &[10, 0, 0, 0]);
    assert_eq!(&px[(10 + 9) * 4..(10 + 9) * 4 + 4], &[0, 0, 20, 0]);
    // 3 colours, 8 bits per pixel, index out of range.
    let filter = [1, 2, 1, 1, 1, 2, 2, 2, 3, 3, 3];
    let m = basic(&mut c, 0x40, &filter, &[0, 1, 2, 3]);
    assert!(decode(&m, 2, 2).is_err());
    let m = basic(&mut Compress::new(Compression::default(), true), 0x40, &filter, &[0, 1, 2, 2]);
    assert!(decode(&m, 2, 2).is_ok());
}

#[test]
fn gradient_filter() {
    // 2x2, data = 10 everywhere for R: row 0 → 10, 20; row 1 → 20, (20+20-10)+10 = 40.
    let raw = [10, 0, 0, 10, 0, 0, 10, 0, 0, 10, 0, 0];
    let m = basic(&mut Compress::new(Compression::default(), true), 0x40, &[2], &raw);
    let TightOutput::Pixels(px) = decode(&m, 2, 2).expect("d") else { panic!() };
    let reds: Vec<u8> = px.chunks_exact(4).map(|p| p[0]).collect();
    assert_eq!(reds, vec![10, 20, 20, 40]);
}

#[test]
fn hostile_sizes_and_lengths() {
    // Wrong inflated size.
    let mut c = Compress::new(Compression::default(), true);
    let m = basic(&mut c, 0x00, &[], &[0u8; 30]);
    assert!(decode(&m, 4, 4).is_err(), "30 bytes for a 48-byte rect");
    // More output than the rectangle (bomb) is cut at the cap.
    let mut c = Compress::new(Compression::default(), true);
    let m = basic(&mut c, 0x00, &[], &vec![0u8; 1 << 20]);
    assert!(decode(&m, 4, 4).is_err());
    // Rect too large for the decode cap is refused in framing.
    assert!(frame_len(&[0x00], 8192, 8192).is_err());
    assert!(decode(&[], 1, 1).is_err());
    assert_eq!(compact(MAX_COMPACT).len(), 3);
}

proptest::proptest! {
    #[test]
    fn never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400),
                    w in 0u16..40, h in 0u16..40) {
        let _ = frame_len(&data, w, h);
        let _ = decode(&data, w, h);
    }
}
