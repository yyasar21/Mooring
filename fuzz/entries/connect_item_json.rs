//! Fuzz entry `connect_item_json`: 1Password Connect item / vault list / item list bodies (ADR-0026 §3), then the field mapping
//! onto every reference-target kind. Shared by
//! `fuzz/fuzz_targets/connect_item_json.rs` and the stable replay in
//! `crates/mooring-secrets/tests/fuzz_corpus.rs`.

/// Never panics. Lists are capped; ambiguous labels are refused.
pub fn run(data: &[u8]) {
    mooring_secrets::fuzz::fuzz_connect_item_json(data);
}
