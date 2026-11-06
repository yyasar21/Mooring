//! Fuzz entry `mfr1_decode`: hostile `MFR1` frame messages (ADR-0011 §Frame path).
//! Shared by `fuzz/fuzz_targets/mfr1_decode.rs` and the stable corpus replay in
//! `crates/mooring-core/tests/fuzz_corpus.rs`.

use mooring_core::frame::{decode_mfr1, Mfr1Record, MAX_CURSOR, MAX_DIM};

/// Never panics. An accepted message respects the ADR caps (n ≤ 256 records, framebuffer
/// ≤ 8192², every rect inside the framebuffer, cursor sprite ≤ 384², RGBA data = w·h·4),
/// applies to a texture of exactly fbW·fbH·4 bytes, and decoding is deterministic.
pub fn run(data: &[u8]) {
    let first = decode_mfr1(data);
    let again = decode_mfr1(data);
    assert_eq!(format!("{first:?}"), format!("{again:?}"), "decode_mfr1 is not deterministic");
    if data.len() < 16 {
        assert!(first.is_err(), "a message shorter than the 16-byte header was accepted");
    }
    let Ok(frame) = first else { return };
    assert!(frame.records.len() <= 256, "more than 256 records");
    // A 0×0 framebuffer is legal (the UI before the first resize, ADR-0011): the encoder emits
    // it with no rectangles, so only the upper bound is an invariant here.
    assert!(frame.width <= MAX_DIM && frame.height <= MAX_DIM);
    for r in &frame.records {
        match r {
            Mfr1Record::Rgba { rect, data } => {
                assert!(rect.fits(frame.width, frame.height), "rgba rect outside");
                assert_eq!(data.len(), usize::from(rect.w) * usize::from(rect.h) * 4);
            }
            Mfr1Record::Copy { rect, .. } | Mfr1Record::Fill { rect, .. } => {
                assert!(rect.fits(frame.width, frame.height), "rect outside");
            }
            Mfr1Record::Cursor(c) => {
                if let mooring_core::frame::Cursor::Sprite { w, h, .. } = c {
                    assert!(*w <= MAX_CURSOR && *h <= MAX_CURSOR, "cursor over the cap");
                }
            }
        }
    }
    if usize::from(frame.width) * usize::from(frame.height) <= 1 << 20 {
        let mut texture = vec![0u8; usize::from(frame.width) * usize::from(frame.height) * 4];
        frame.apply(&mut texture);
        assert_eq!(texture.len(), usize::from(frame.width) * usize::from(frame.height) * 4);
    }
}
