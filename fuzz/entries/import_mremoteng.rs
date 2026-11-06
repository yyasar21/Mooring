//! Fuzz entry `import_mremoteng`: mRemoteNG `confCons.xml` (passwords never imported): `[opt-in flag, file…]`.
//! Shared by `fuzz/fuzz_targets/import_mremoteng.rs` and the stable replay in
//! `crates/mooring-import/tests/fuzz_corpus.rs`.

/// Never panics. The crate entry asserts the oracle: item caps hold, every item re-passes the
/// core validators, folder / credential keys resolve, no secret without the opt-in.
pub fn run(data: &[u8]) {
    mooring_import::fuzz::fuzz_mremoteng(data);
}
