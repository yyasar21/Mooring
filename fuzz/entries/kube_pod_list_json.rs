//! Fuzz entry `kube_pod_list_json`: API server `PodList` / `NamespaceList` body, capped at
//! 16 MiB before parsing (ADR-0014 §5). Shared by `fuzz/fuzz_targets/kube_pod_list_json.rs`
//! and, once reachable, a stable corpus replay in `crates/mooring-proto-kube/tests/fuzz_corpus.rs`.
//!
//! PENDING(K3): the list types (`browse::PodIn`, `List<T>`) are `pub(crate)` and the crate's
//! `fuzz` module has no entry for them (Q2 handoff, "Decision needed":
//! `mooring_proto_kube::fuzz::fuzz_pod_list_json(&[u8])`). Until then the target is built
//! without the `k3` feature and `run` is a no-op.

/// Never panics. With the parser: every `PodSummary` has bounded strings (name ≤ 253, image
/// ≤ 512, ≤ 64 containers, ≤ 32 ports) and the body cap is checked before serde_json runs.
#[cfg(feature = "k3")]
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::fuzz_pod_list_json(data);
}

/// Stub until the parser is reachable (see the module docs).
#[cfg(not(feature = "k3"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
