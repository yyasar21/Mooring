//! Fuzz entry `import_termius_json`: Termius JSON export: `[opt-in flag, file…]`.
//! Shared by `fuzz/fuzz_targets/import_termius_json.rs` and the stable replay in
//! `crates/mooring-import/tests/fuzz_corpus.rs`.

/// Never panics. The crate entry asserts the oracle: item caps hold, every item re-passes the
/// core validators, folder / credential keys resolve, no secret without the opt-in.
pub fn run(data: &[u8]) {
    mooring_import::fuzz::fuzz_termius_json(data);
}
