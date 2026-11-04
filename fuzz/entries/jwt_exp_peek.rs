//! Fuzz entry `jwt_exp_peek`: bearer token from a kubeconfig / `kube_token` credential, read
//! unverified for display only (ADR-0014 §3). Shared by `fuzz/fuzz_targets/jwt_exp_peek.rs`
//! and, once reachable, a stable corpus replay in the owning crate's `tests/fuzz_corpus.rs`.
//!
//! PENDING(K2): the parser is `mooring_app::commands::kube_jwt::peek_exp` in `src-tauri`
//! (A3 K4), which needs the WebView toolchain and is therefore not a dependency of this crate.
//! Until it moves to `mooring-core` (Q2 handoff, "Decision needed") the target is built without
//! the `k2` feature and `run` is a no-op.

/// Never panics. With the parser: `Some(exp)` only for a three-part base64url token whose
/// payload has a numeric `exp` in `0..=253_402_300_799`; a token over 16 KiB yields `None`.
#[cfg(feature = "k2")]
pub fn run(data: &[u8]) {
    let text = std::str::from_utf8(data).unwrap_or("");
    let _ = mooring_core::credential::kubeconfig::peek_exp(text);
}

/// Stub until the parser is reachable (see the module docs).
#[cfg(not(feature = "k2"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
