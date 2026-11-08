//! Fuzz entry `export_document_json`: Export document v2 (ADR-0023 §1): the JSON inside the passphrase `age` layer of a backup file. Shared by
//! `fuzz/fuzz_targets/export_document_json.rs` and the stable replay in
//! `crates/mooring-sync/tests/fuzz_corpus.rs`.

/// Never panics. An accepted document re-serialises and parses again to an equal value (the
/// crate entry asserts that); duplicate keys, folder cycles, dangling ids, a vault-id mismatch
/// and unknown versions are refused as a whole.
pub fn run(data: &[u8]) {
    mooring_sync::fuzz::fuzz_export_document_json(data);
}
