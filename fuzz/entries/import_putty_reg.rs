//! Fuzz entry `import_putty_reg`: PuTTY `.reg` export, UTF-16LE or UTF-8: `[opt-in flag, file…]`.
//! Shared by `fuzz/fuzz_targets/import_putty_reg.rs` and the stable replay in
//! `crates/mooring-import/tests/fuzz_corpus.rs`.

/// Never panics. The crate entry asserts the oracle: item caps hold, every item re-passes the
/// core validators, folder / credential keys resolve, no secret without the opt-in.
pub fn run(data: &[u8]) {
    mooring_import::fuzz::fuzz_putty_reg(data);
}
