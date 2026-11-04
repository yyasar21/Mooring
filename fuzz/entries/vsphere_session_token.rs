//! Fuzz entry `vsphere_session_token`: POST /api/session response body (a JSON string) (ADR-0015 §1).
//! Shared by `fuzz/fuzz_targets/vsphere_session_token.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(V1): `mooring_vsphere::fuzz::session_token(data)` is written by rust-core V1 (mooring-vsphere). Until it exists the target
//! is built without the `v1` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features v1`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; only a bounded JSON string of visible ASCII is accepted.
#[cfg(feature = "v1")]
pub fn run(data: &[u8]) {
    mooring_vsphere::fuzz::session_token(data);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "v1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
