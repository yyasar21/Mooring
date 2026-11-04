//! Fuzz entry `vsphere_inventory_json`: vCenter /api/vcenter/{datacenter,cluster,host,vm} list bodies (8 MiB cap) (ADR-0015 §1-2).
//! Shared by `fuzz/fuzz_targets/vsphere_inventory_json.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(V1): `mooring_vsphere::fuzz::inventory_json(data)` is written by rust-core V1 (mooring-vsphere). Until it exists the target
//! is built without the `v1` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features v1`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; names <= 255 B, ids <= 64 B ASCII [a-z0-9-]; unknown fields ignored.
#[cfg(feature = "v1")]
pub fn run(data: &[u8]) {
    mooring_vsphere::fuzz::inventory_json(data);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "v1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
