//! Fuzz entry `vault_db_creds`: Vault `database/creds`, `ssh/creds` (OTP) and `sys/leases/renew` bodies (ADR-0026 §2), then
//! the mapping into `user_password`. Shared by
//! `fuzz/fuzz_targets/vault_db_creds.rs` and the stable replay in
//! `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics. A lease id with spaces or control characters is refused; the TTL is capped.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_vault_db_creds(data);
}
