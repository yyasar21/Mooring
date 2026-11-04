//! Dispatch, framing + decode together, cursor and inflate caps.

use super::*;
use crate::messages::parse_rect;
use crate::wire::Parsed;

#[allow(clippy::many_single_char_names)]
fn rect_bytes(x: u16, y: u16, w: u16, h: u16, e: i32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    for v in [x, y, w, h] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(&e.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

fn framed(buf: &[u8], fb: (u16, u16)) -> Result<RectOp, VncError> {
    match parse_rect(buf, fb.0, fb.1)? {
        Parsed::Done(f, used) => {
            assert_eq!(used, buf.len());
            Decoders::default().decode(&f, buf)
        }
        Parsed::Need(n) => panic!("need {n}"),
    }
}

#[test]
fn raw_copy_and_bounds() {
    let b = rect_bytes(1, 1, 1, 1, enc::RAW, &[9, 8, 7, 0]);
    assert_eq!(
        framed(&b, (4, 4)).expect("raw"),
        RectOp::Blit { rect: Rect::new(1, 1, 1, 1), rgbx: vec![9, 8, 7, 0] }
    );
    assert_eq!(parse_rect(&b[..14], 4, 4).expect("p"), Parsed::Need(16));
    assert!(parse_rect(&rect_bytes(3, 3, 2, 1, enc::RAW, &[]), 4, 4).is_err(), "outside fb");
    assert!(parse_rect(&rect_bytes(u16::MAX, 0, 2, 1, enc::RAW, &[]), 4, 4).is_err());
    let c = rect_bytes(0, 0, 2, 2, enc::COPY_RECT, &[0, 1, 0, 2]);
    assert_eq!(
        framed(&c, (4, 4)).expect("copy"),
        RectOp::Copy { rect: Rect::new(0, 0, 2, 2), src_x: 1, src_y: 2 }
    );
    assert_eq!(framed(&rect_bytes(0, 0, 0, 0, enc::RAW, &[]), (4, 4)).expect("e"), RectOp::Nothing);
    assert!(parse_rect(&rect_bytes(0, 0, 1, 1, 5, &[]), 4, 4).is_err(), "hextile not requested");
    assert!(
        parse_rect(&rect_bytes(0, 0, 1, 1, -32, &[]), 4, 4).is_err(),
        "JPEG quality not requested"
    );
}

#[test]
fn pseudo_encodings() {
    let d = rect_bytes(0, 0, 800, 600, enc::DESKTOP_SIZE, &[]);
    assert_eq!(framed(&d, (4, 4)).expect("ds"), RectOp::Resize { w: 800, h: 600, screen: None });
    assert!(framed(&rect_bytes(0, 0, 0, 600, enc::DESKTOP_SIZE, &[]), (4, 4)).is_err());
    assert!(framed(&rect_bytes(0, 0, 8193, 600, enc::DESKTOP_SIZE, &[]), (4, 4)).is_err());
    let mut screen = vec![1, 0, 0, 0];
    screen.extend_from_slice(&7u32.to_be_bytes());
    screen.extend_from_slice(&[0, 0, 0, 0, 3, 32, 2, 88]);
    screen.extend_from_slice(&0u32.to_be_bytes());
    let e = rect_bytes(1, 0, 800, 600, enc::EXT_DESKTOP_SIZE, &screen);
    assert_eq!(
        framed(&e, (4, 4)).expect("eds"),
        RectOp::Resize { w: 800, h: 600, screen: Some((7, 0)) }
    );
    let refused = rect_bytes(1, 3, 800, 600, enc::EXT_DESKTOP_SIZE, &screen);
    assert_eq!(
        framed(&refused, (4, 4)).expect("r"),
        RectOp::ExtDesktopRefused { screen: Some((7, 0)) }
    );
    assert!(
        parse_rect(&rect_bytes(0, 0, 1, 1, enc::EXT_DESKTOP_SIZE, &[0, 0, 0, 0]), 4, 4).is_err()
    );
    assert_eq!(
        framed(&rect_bytes(0, 0, 0, 0, enc::LAST_RECT, &[]), (4, 4)).expect("l"),
        RectOp::LastRect
    );
    assert_eq!(
        framed(&rect_bytes(0, 0, 0, 0, enc::QEMU_EXT_KEY, &[]), (4, 4)).expect("q"),
        RectOp::QemuExtKey
    );
}

#[test]
fn cursor_sprite_and_caps() {
    // 2x1 cursor, hot spot (1, 0): pixels then mask 0b1000_0000 (first visible).
    let payload = [1, 2, 3, 0, 4, 5, 6, 0, 0b1000_0000];
    let c = rect_bytes(1, 0, 2, 1, enc::CURSOR, &payload);
    let RectOp::Cursor(Cursor::Sprite { hot_x, hot_y, w, h, rgba }) =
        framed(&c, (4, 4)).expect("c")
    else {
        panic!()
    };
    assert_eq!((hot_x, hot_y, w, h), (1, 0, 2, 1));
    assert_eq!(rgba, vec![1, 2, 3, 255, 4, 5, 6, 0]);
    // Hot spot outside is clamped; empty is hidden; too large refused.
    let c = rect_bytes(9, 9, 2, 1, enc::CURSOR, &payload);
    let RectOp::Cursor(Cursor::Sprite { hot_x, hot_y, .. }) = framed(&c, (4, 4)).expect("c") else {
        panic!()
    };
    assert_eq!((hot_x, hot_y), (1, 0));
    assert_eq!(
        framed(&rect_bytes(0, 0, 0, 0, enc::CURSOR, &[]), (4, 4)).expect("h"),
        RectOp::Cursor(Cursor::Hidden)
    );
    assert!(parse_rect(&rect_bytes(0, 0, 385, 1, enc::CURSOR, &[]), 4, 4).is_err());
    assert_eq!(decode_cursor(Rect::new(0, 0, 2, 2), &[0; 3]), Cursor::Default, "short data");
}

#[test]
fn zrle_through_dispatch() {
    use flate2::{Compress, Compression, FlushCompress};
    let mut c = Compress::new(Compression::default(), true);
    let mut z = Vec::with_capacity(64);
    c.compress_vec(&[1, 7, 7, 7], &mut z, FlushCompress::Sync).expect("z");
    let mut payload = u32::try_from(z.len()).expect("len").to_be_bytes().to_vec();
    payload.extend_from_slice(&z);
    let b = rect_bytes(0, 0, 2, 2, enc::ZRLE, &payload);
    assert_eq!(
        framed(&b, (2, 2)).expect("zrle"),
        RectOp::Blit { rect: Rect::new(0, 0, 2, 2), rgbx: [7, 7, 7, 0].repeat(4) }
    );
    let mut huge = rect_bytes(0, 0, 1, 1, enc::ZRLE, &[]);
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_rect(&huge, 2, 2).is_err(), "compressed length cap");
    // Tight fill through dispatch.
    let t = rect_bytes(0, 0, 2, 2, enc::TIGHT, &[0x80, 1, 2, 3]);
    assert_eq!(
        framed(&t, (2, 2)).expect("tight"),
        RectOp::Fill { rect: Rect::new(0, 0, 2, 2), rgba: [1, 2, 3, 255] }
    );
}

#[test]
fn inflate_limits() {
    use flate2::{Compress, Compression, FlushCompress};
    let mut c = Compress::new(Compression::default(), true);
    let mut z = Vec::with_capacity(4096);
    c.compress_vec(&[5u8; 1000], &mut z, FlushCompress::Sync).expect("z");
    let mut d = Decompress::new(true);
    assert_eq!(inflate(&mut d, &z, 1000).expect("exact").len(), 1000);
    let mut d = Decompress::new(true);
    assert!(inflate(&mut d, &z, 999).is_err());
    let mut d = Decompress::new(true);
    assert!(inflate(&mut d, &z[..z.len() / 2], 1000).expect("partial").len() < 1000);
    let mut d = Decompress::new(true);
    assert_eq!(inflate(&mut d, &[], 10).expect("empty"), Vec::<u8>::new());
}

proptest::proptest! {
    #[test]
    fn rect_parse_and_decode_never_panic(
        data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300),
        fw in 1u16..64, fh in 1u16..64,
    ) {
        let mut d = Decoders::default();
        if let Ok(Parsed::Done(f, _)) = parse_rect(&data, fw, fh) {
            if let Ok(RectOp::Blit { rect, rgbx }) = d.decode(&f, &data) {
                proptest::prop_assert!(rect.fits(fw, fh));
                proptest::prop_assert_eq!(rgbx.len() as u64, rect.area() * 4);
            }
        }
    }
}
