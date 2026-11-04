//! Fuzz entry `sync_snapshot_json`: decrypted canonical-JSON snapshot (64 MiB cap) (ADR-0017 §1).
//! Shared by `fuzz/fuzz_targets/sync_snapshot_json.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(S1): `mooring_sync::fuzz::snapshot_json(data)` is written by rust-core S1 (mooring-sync). Until it exists the target
//! is built without the `s1` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features s1`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; canonical form round-trips; caps on rows honoured.
#[cfg(feature = "s1")]
pub fn run(data: &[u8]) {
    mooring_sync::fuzz::snapshot_json(data);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "s1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
