//! Fuzz entry `external_ref_parse`: stored / imported external_ref fields (reference, fieldMap, version) (ADR-0016 §2).
//! Shared by `fuzz/fuzz_targets/external_ref_parse.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(E1): `mooring_core::credential::fuzz::external_ref(data)` is written by rust-core E1 (mooring-secrets; external_ref parser in mooring-core). Until it exists the target
//! is built without the `e1` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features e1`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; reference segments [A-Za-z0-9._-]+, no '..' or empty segment, <= 1 KiB; fieldMap keys are names of the target kind.
#[cfg(feature = "e1")]
pub fn run(data: &[u8]) {
    mooring_core::credential::fuzz::external_ref(data);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "e1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
