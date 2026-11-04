//! Fuzz entry `jwt_exp_peek`: bearer token from a kubeconfig / `kube_token` credential, read
//! unverified for display only (ADR-0014 §3). Shared by `fuzz/fuzz_targets/jwt_exp_peek.rs`
//! and the stable corpus replay in `crates/mooring-core/tests/fuzz_corpus.rs`.

/// Never panics. `Some(exp)` only for a three-part base64url token whose payload has a numeric
/// `exp` in `0..=253_402_300_799`; a token over the size cap yields `None`.
pub fn run(data: &[u8]) {
    let text = std::str::from_utf8(data).unwrap_or("");
    let _ = mooring_core::credential::kubeconfig::peek_exp(text);
}
