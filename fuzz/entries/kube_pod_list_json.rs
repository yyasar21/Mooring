//! Fuzz entry `kube_pod_list_json`: API server PodList / NamespaceList body (capped at 16 MiB before parsing) (ADR-0014 §5).
//! Shared by `fuzz/fuzz_targets/kube_pod_list_json.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(K3): `mooring_proto_kube::fuzz::pod_list_json(data)` is written by rust-core K3 (mooring-proto-kube). Until it exists the target
//! is built without the `k3` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features k3`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; every returned PodSummary has bounded strings; the body cap is checked before serde_json runs.
#[cfg(feature = "k3")]
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::pod_list_json(data);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "k3"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
