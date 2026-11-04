//! Fuzz entry `mfr1_decode`: hostile `MFR1` frame messages (ADR-0011 §Frame path).
//! Shared by `fuzz/fuzz_targets/mfr1_decode.rs` and, once R1 has merged, the stable corpus
//! replay in `crates/mooring-core/tests/fuzz_corpus.rs`.
//!
//! PENDING(R1): `mooring_core::frame::decode_mfr1` is being written by rust-core (A2 task R1).
//! Until it exists the target is built without the `r1` feature and `run` is a no-op, so the
//! nightly matrix and the libFuzzer wrapper already compile. When R1 lands: build with
//! `--features r1`, check the call below against the real signature, then remove the gate.

/// Never panics. With R1: an accepted message respects the ADR caps (n ≤ 256 records,
/// framebuffer ≤ 8192², message ≤ 4·fbW·fbH + 64 KiB, every rect inside the framebuffer,
/// cursor sprite ≤ 384²) and decoding is deterministic.
#[cfg(feature = "r1")]
pub fn run(data: &[u8]) {
    let first = mooring_core::frame::decode_mfr1(data);
    let again = mooring_core::frame::decode_mfr1(data);
    assert_eq!(first.is_ok(), again.is_ok(), "decode_mfr1 is not deterministic");
    if data.len() < 16 {
        assert!(first.is_err(), "a message shorter than the 16-byte header was accepted");
    }
    if data.len() > 4 * 8192 * 8192 + 64 * 1024 {
        assert!(first.is_err(), "a message over the absolute size cap was accepted");
    }
    // TODO(R1): assert the per-record caps on the decoded value once its type is public.
}

/// Stub until R1 merges (see the module docs).
#[cfg(not(feature = "r1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
