//! Fuzz entry `op_reference_parse`: `op://` and Bitwarden references typed by the user or imported (ADR-0026 §1). Shared by
//! `fuzz/fuzz_targets/op_reference_parse.rs` and the stable replay in
//! `crates/mooring-core/tests/fuzz_corpus.rs`.

/// Never panics. A parsed `op://` reference renders back to its input (the crate entry asserts
/// that).
pub fn run(data: &[u8]) {
    mooring_core::credential::fuzz_op_reference(data);
}
