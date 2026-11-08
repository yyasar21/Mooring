//! Fuzz entry `bws_secret_json`: `bws secret get` / `secret list` / `project list` / `--version` output (ADR-0026 §4, R-SEC-CLI). Shared by
//! `fuzz/fuzz_targets/bws_secret_json.rs` and the stable replay in
//! `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics. Another secret's id and duplicate keys are refused.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_bws_secret_json(data);
}
