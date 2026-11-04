//! Fuzz entry `kube_pod_list_json`: API server `PodList` body, capped at the JSON body limit
//! before parsing (ADR-0014 §5). Shared by `fuzz/fuzz_targets/kube_pod_list_json.rs` and the
//! stable corpus replay in `crates/mooring-proto-kube/tests/fuzz_corpus.rs`.

/// Never panics. Every `PodSummary` has bounded, clean strings, and the body cap is checked
/// before `serde_json` runs (`mooring_proto_kube::fuzz::fuzz_pod_list_json`).
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::fuzz_pod_list_json(data);
}
