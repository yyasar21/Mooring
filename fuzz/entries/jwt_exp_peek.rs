//! Fuzz entry `jwt_exp_peek`: bearer token from a kubeconfig / kube_token credential (read unverified, display only) (ADR-0014 §3).
//! Shared by `fuzz/fuzz_targets/jwt_exp_peek.rs` and, once the parser lands, a stable corpus replay in
//! the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(K2): `mooring_core::credential::kubeconfig::jwt_exp_peek(token)` is written by rust-core K2 (kubeconfig::resolve, JWT exp peek) in mooring-core. Until it exists the target
//! is built without the `k2` feature and `run` is a no-op, so the nightly matrix and the
//! libFuzzer wrapper already compile. When it lands: add the crate to `fuzz/Cargo.toml`, build
//! with `--features k2`, check the call below against the real signature, add the stable
//! replay, then remove the gate (docs/qa/fuzzing.md, "A3 targets").

/// Never panics. With the parser: no panic; never allocates more than the token length; Some(exp) only for a three-part base64url token whose payload has a numeric exp.
#[cfg(feature = "k2")]
pub fn run(data: &[u8]) {
    let text = std::str::from_utf8(data).unwrap_or("");
    let _ = mooring_core::credential::kubeconfig::jwt_exp_peek(text);
}

/// Stub until the parser merges (see the module docs).
#[cfg(not(feature = "k2"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
