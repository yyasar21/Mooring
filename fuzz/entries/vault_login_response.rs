//! Fuzz entry `vault_login_response`: `AppRole` / OIDC login, `renew-self` and `lookup-self`
//! bodies (ADR-0016 §3). Shared by `fuzz/fuzz_targets/vault_login_response.rs` and the stable
//! replay in `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics on any body; a body that is not the expected shape is a decode error.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_login_response(data);
}
