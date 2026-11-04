use super::*;
use proptest::prelude::*;

/// Byte-exact vector: header + one record of each kind.
#[test]
fn encoder_vector() {
    let mut w = Mfr1Writer::new(0x0102_0304, 640, 480, FLAG_FULL | FLAG_RESIZED);
    w.rgba(Rect::new(1, 2, 1, 1), &[0xAA, 0xBB, 0xCC, 0xDD]);
    w.copy(Rect::new(3, 4, 5, 6), 7, 8);
    w.fill(Rect::new(0, 0, 2, 2), [1, 2, 3, 4]);
    w.cursor(&Cursor::Sprite { hot_x: 0, hot_y: 0, w: 1, h: 1, rgba: vec![9, 9, 9, 9] });
    w.cursor(&Cursor::Hidden);
    w.cursor(&Cursor::Default);
    let bytes = w.finish();
    #[rustfmt::skip]
    let want: Vec<u8> = [
        &b"MFR1"[..], &[4, 3, 2, 1], &[0x80, 2], &[0xE0, 1], &[6, 0], &[3, 0],
        &[1, 0, 1, 0, 2, 0, 1, 0, 1, 0], &[0xAA, 0xBB, 0xCC, 0xDD],
        &[2, 0, 3, 0, 4, 0, 5, 0, 6, 0], &[7, 0, 8, 0],
        &[3, 0, 0, 0, 0, 0, 2, 0, 2, 0], &[1, 2, 3, 4],
        &[4, 0, 0, 0, 0, 0, 1, 0, 1, 0], &[0, 0, 0, 0], &[9, 9, 9, 9],
        &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[6, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(bytes, want);
    let f = decode_mfr1(&bytes).expect("decodes");
    assert_eq!((f.seq, f.width, f.height), (0x0102_0304, 640, 480));
    assert!(f.is_full() && f.is_resized());
    assert_eq!(f.records.len(), 6);
    assert_eq!(f.records[1], Mfr1Record::Copy { rect: Rect::new(3, 4, 5, 6), src_x: 7, src_y: 8 });
    assert_eq!(f.records[5], Mfr1Record::Cursor(Cursor::Default));
}

fn header(w: u16, h: u16, n: u16, flags: u16) -> Vec<u8> {
    let mut v = b"MFR1".to_vec();
    v.extend_from_slice(&1u32.to_le_bytes());
    for x in [w, h, n, flags] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

fn rec(kind: u8, left: u16, top: u16, width: u16, height: u16) -> Vec<u8> {
    let mut out = vec![kind, 0];
    for field in [left, top, width, height] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out
}

#[test]
fn decoder_refuses_hostile_messages() {
    use Mfr1Error as E;
    let ok = [header(4, 4, 0, 0)].concat();
    assert!(decode_mfr1(&ok).is_ok());
    let cases: Vec<(Vec<u8>, Mfr1Error)> = vec![
        (vec![], E::Truncated),
        (b"MFR2".to_vec(), E::BadMagic),
        (header(4, 4, 0, 0)[..15].to_vec(), E::Truncated),
        (header(8193, 1, 0, 0), E::TooLarge),
        (header(4, 4, 257, 0), E::TooLarge),
        (header(4, 4, 0, 4), E::BadFlags),
        ([header(4, 4, 1, 0), rec(1, 0, 0, 2, 2)].concat(), E::Truncated),
        ([header(4, 4, 1, 0), rec(1, 3, 0, 2, 1), vec![0; 8]].concat(), E::OutOfBounds),
        ([header(4, 4, 1, 0), rec(9, 0, 0, 0, 0)].concat(), E::BadRecord),
        ([header(4, 4, 1, 0), vec![1, 1], vec![0; 8]].concat(), E::BadRecord),
        ([header(4, 4, 1, 0), rec(2, 0, 0, 2, 2), vec![3, 0, 0, 0]].concat(), E::OutOfBounds),
        ([header(4, 4, 1, 0), rec(3, 4, 0, 1, 1), vec![0; 4]].concat(), E::OutOfBounds),
        ([header(4, 4, 1, 0), rec(4, 0, 0, 385, 1), vec![0; 4]].concat(), E::BadCursor),
        ([header(4, 4, 1, 0), rec(4, 0, 0, 1, 1), vec![1, 0, 0, 0]].concat(), E::BadCursor),
        ([header(4, 4, 1, 0), rec(4, 1, 0, 1, 1), vec![0; 8]].concat(), E::BadRecord),
        ([header(4, 4, 1, 0), rec(5, 0, 0, 1, 0)].concat(), E::BadRecord),
        ([header(4, 4, 0, 0), vec![0]].concat(), E::Trailing),
        ([header(0, 0, 0, 0), vec![0; SLACK + CURSOR_ALLOWANCE]].concat(), E::TooLarge),
    ];
    for (i, (bytes, want)) in cases.into_iter().enumerate() {
        assert_eq!(decode_mfr1(&bytes), Err(want), "case {i}");
    }
}

#[test]
fn max_cursor_fits_on_an_empty_framebuffer() {
    let mut w = Mfr1Writer::new(1, 0, 0, 0);
    let side = MAX_CURSOR;
    let rgba = vec![1; usize::from(side) * usize::from(side) * 4];
    w.cursor(&Cursor::Sprite { hot_x: side - 1, hot_y: side - 1, w: side, h: side, rgba });
    assert!(decode_mfr1(&w.finish()).is_ok());
}

#[test]
fn apply_honours_copy_and_fill_records() {
    let mut w = Mfr1Writer::new(1, 2, 2, FLAG_RESIZED);
    w.fill(Rect::new(0, 0, 1, 1), [5, 5, 5, 5]);
    w.copy(Rect::new(1, 1, 1, 1), 0, 0);
    let f = decode_mfr1(&w.finish()).expect("decodes");
    let mut mirror = Vec::new();
    assert_eq!(f.apply(&mut mirror), None);
    assert_eq!(&mirror[0..4], &[5, 5, 5, 5]);
    assert_eq!(&mirror[12..16], &[5, 5, 5, 5]);
    assert_eq!(&mirror[4..8], &[0, 0, 0, 255]);
}

fn record() -> impl Strategy<Value = Mfr1Record> {
    let r = (0..16u16, 0..16u16, 0..8u16, 0..8u16).prop_map(|(x, y, w, h)| Rect::new(x, y, w, h));
    prop_oneof![
        r.clone().prop_filter("fits", |r| r.fits(24, 24)).prop_flat_map(|rect| {
            proptest::collection::vec(any::<u8>(), usize::from(rect.w) * usize::from(rect.h) * 4)
                .prop_map(move |data| Mfr1Record::Rgba { rect, data })
        }),
        (r.clone(), 0..16u16, 0..16u16)
            .prop_filter("fits", |(r, x, y)| {
                r.fits(24, 24) && Rect::new(*x, *y, r.w, r.h).fits(24, 24)
            })
            .prop_map(|(rect, src_x, src_y)| Mfr1Record::Copy { rect, src_x, src_y }),
        (r.prop_filter("fits", |r| r.fits(24, 24)), any::<[u8; 4]>())
            .prop_map(|(rect, rgba)| Mfr1Record::Fill { rect, rgba }),
        (1..6u16, 1..6u16).prop_flat_map(|(w, h)| {
            (0..w, 0..h, proptest::collection::vec(any::<u8>(), usize::from(w * h * 4))).prop_map(
                move |(hot_x, hot_y, rgba)| {
                    Mfr1Record::Cursor(Cursor::Sprite { hot_x, hot_y, w, h, rgba })
                },
            )
        }),
        Just(Mfr1Record::Cursor(Cursor::Hidden)),
        Just(Mfr1Record::Cursor(Cursor::Default)),
    ]
}

proptest! {
    #[test]
    fn encode_decode_round_trip(
        seq in any::<u32>(),
        flags in 0..4u16,
        records in proptest::collection::vec(record(), 0..12),
    ) {
        let mut w = Mfr1Writer::new(seq, 24, 24, flags);
        for r in &records {
            match r {
                Mfr1Record::Rgba { rect, data } => w.rgba(*rect, data),
                Mfr1Record::Copy { rect, src_x, src_y } => w.copy(*rect, *src_x, *src_y),
                Mfr1Record::Fill { rect, rgba } => w.fill(*rect, *rgba),
                Mfr1Record::Cursor(c) => w.cursor(c),
            }
        }
        let f = decode_mfr1(&w.finish()).expect("round trip");
        prop_assert_eq!(f, Mfr1Frame { seq, width: 24, height: 24, flags, records });
    }

    /// Hostile bytes never panic (also the `mfr1_decode` fuzz target's property), and anything
    /// accepted can be applied to a mirror without panicking.
    #[test]
    fn hostile_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(f) = decode_mfr1(&bytes) {
            let mut mirror = Vec::new();
            let _ = f.apply(&mut mirror);
        }
    }

    #[test]
    fn mutated_valid_messages_never_panic(
        records in proptest::collection::vec(record(), 1..6),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
    ) {
        let mut w = Mfr1Writer::new(1, 24, 24, 0);
        for r in &records {
            if let Mfr1Record::Fill { rect, rgba } = r { w.fill(*rect, *rgba) } else {
                w.cursor(&Cursor::Default);
            }
        }
        let mut bytes = w.finish();
        for (i, v) in flips {
            let n = bytes.len();
            bytes[i % n] = v;
        }
        if let Ok(f) = decode_mfr1(&bytes) {
            let mut mirror = Vec::new();
            let _ = f.apply(&mut mirror);
        }
    }
}
