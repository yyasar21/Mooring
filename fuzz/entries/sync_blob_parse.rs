//! Fuzz entry `sync_blob_parse`: an `MSY1` object downloaded from the bucket (ADR-0017 §2).
//! Shared by `fuzz/fuzz_targets/sync_blob_parse.rs` and the stable replay in
//! `crates/mooring-sync/tests/fuzz_corpus.rs`.

use mooring_sync::blob::{decode_msy1, MAGIC, MAX_BLOB, MIN_BLOB, TAG_LEN, VERSION};

/// Never panics. Anything shorter than the fixed header + nonce + tag or larger than the cap
/// is refused; an accepted blob starts with the magic and version, its AAD re-encodes to the
/// header (the crate entry asserts that) and `aad ‖ nonce ‖ ciphertext` is the input.
pub fn run(data: &[u8]) {
    mooring_sync::fuzz::fuzz_msy1(data);
    let r = decode_msy1(data);
    if data.len() < MIN_BLOB || data.len() > MAX_BLOB {
        assert!(r.is_err(), "blob outside the size bounds accepted");
    }
    let Ok(m) = r else { return };
    assert_eq!(&data[..4], &MAGIC);
    assert_eq!(data[4], VERSION);
    assert_eq!(m.aad.len() + m.nonce.len() + m.ciphertext.len(), data.len());
    assert!(m.ciphertext.len() >= TAG_LEN);
}
