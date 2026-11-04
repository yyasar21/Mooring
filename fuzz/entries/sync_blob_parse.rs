//! Fuzz entry `sync_blob_parse`: MSY1 object downloaded from the bucket (ADR-0017 §2).
//! Shared by `fuzz/fuzz_targets/sync_blob_parse.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(S1): `mooring_sync::fuzz::blob_parse(data)` is written by rust-core S1 (mooring-sync). Until it exists the target
//! is built without the `s1` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features s1`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; header checked (magic, ver, vault_id, size cap) before the body is allocated; AEAD failure is an error, never a panic.
#[cfg(feature = "s1")]
pub fn run(data: &[u8]) {
    mooring_sync::fuzz::blob_parse(data);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "s1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
