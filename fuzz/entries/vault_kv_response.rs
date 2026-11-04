//! Fuzz entry `vault_kv_response`: `GET /v1/<mount>/data/<path>` body mapped into every
//! reference-target credential kind (ADR-0016 §3). Shared by
//! `fuzz/fuzz_targets/vault_kv_response.rs` and the stable replay in
//! `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics. The wire type caps field count and key length; a non-string value or a
/// duplicate key is a decode error, never a panic; nothing is logged.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_kv_response(data);
}
