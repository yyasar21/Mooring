//! Fuzz entry `vault_ssh_sign`: Vault `ssh/sign` bodies (ADR-0026 §2), then the certificate check against a fixed subject key. Shared by
//! `fuzz/fuzz_targets/vault_ssh_sign.rs` and the stable replay in
//! `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics. Only a certificate for the subject key is accepted.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_vault_ssh_sign(data);
}
