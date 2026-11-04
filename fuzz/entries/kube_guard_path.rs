//! Fuzz entry `kube_guard_path`: `[method selector, flags, path+query…]` through the request
//! guard that every API call passes (ADR-0014 §4: GET/HEAD only, three POST reviews, exec and
//! port-forward over GET+Upgrade, no `dryRun` / `fieldManager`, no impersonation). Shared by
//! `fuzz/fuzz_targets/kube_guard_path.rs` and the stable replay in
//! `crates/mooring-proto-kube/tests/fuzz_corpus.rs`.

/// Never panics. The crate entry asserts the oracle: an accepted request has a plain path
/// (no `%`, `..`, `;`, `//`), no mutating query key and a method its route allows.
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::fuzz_guard_path(data);
}
