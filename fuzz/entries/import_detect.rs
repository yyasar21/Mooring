//! Fuzz entry `import_detect`: `detect` plus a parse of the detected format: `[file-name selector, file…]`.
//! Shared by `fuzz/fuzz_targets/import_detect.rs` and the stable replay in
//! `crates/mooring-import/tests/fuzz_corpus.rs`.

/// Never panics. The crate entry asserts the oracle: item caps hold, every item re-passes the
/// core validators, folder / credential keys resolve, no secret without the opt-in.
pub fn run(data: &[u8]) {
    mooring_import::fuzz::fuzz_detect(data);
}
