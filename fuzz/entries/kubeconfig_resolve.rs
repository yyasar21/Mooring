//! Fuzz entry `kubeconfig_resolve`: pasted / imported kubeconfig, context name from the file (ADR-0014 §3).
//! Shared by `fuzz/fuzz_targets/kubeconfig_resolve.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(K2): `mooring_core::credential::kubeconfig::resolve(yaml, context)` is written by rust-core K2 (kubeconfig::resolve, JWT exp peek) in mooring-core. Until it exists the target
//! is built without the `k2` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features k2`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; an accepted context has an https server, at most one of token / client cert, CA data <= 64 KiB; proxy-url, impersonate*, username/password are refused; deterministic.
#[cfg(feature = "k2")]
pub fn run(data: &[u8]) {
    let text = std::str::from_utf8(data).unwrap_or("");
    let first = mooring_core::credential::kubeconfig::resolve(text, None);
    let again = mooring_core::credential::kubeconfig::resolve(text, None);
    assert_eq!(first.is_ok(), again.is_ok(), "resolve is not deterministic");
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "k2"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
