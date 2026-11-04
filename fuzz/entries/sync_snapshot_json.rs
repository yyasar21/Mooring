//! Fuzz entry `sync_snapshot_json`: the decrypted canonical-JSON snapshot (64 MiB cap)
//! (ADR-0017 §1). Shared by `fuzz/fuzz_targets/sync_snapshot_json.rs` and the stable replay in
//! `crates/mooring-sync/tests/fuzz_corpus.rs`.

/// Never panics. An accepted snapshot re-encodes canonically and decodes to an equal value
/// (the crate entry asserts that); caps on rows and tombstones are enforced by `validate`.
pub fn run(data: &[u8]) {
    mooring_sync::fuzz::fuzz_snapshot_json(data);
}
