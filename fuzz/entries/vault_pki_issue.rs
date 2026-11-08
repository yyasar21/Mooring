//! Fuzz entry `vault_pki_issue`: Vault `pki/issue` bodies (ADR-0026 §2), then the serial check and the `x509` validators. Shared by
//! `fuzz/fuzz_targets/vault_pki_issue.rs` and the stable replay in
//! `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_vault_pki_issue(data);
}
