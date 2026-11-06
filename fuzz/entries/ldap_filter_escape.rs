//! Fuzz entry `ldap_filter_escape`: RFC 4515 escaping of a user value plus the DN / URL parsers.
//! Shared by `fuzz/fuzz_targets/ldap_filter_escape.rs` and the stable replay in
//! `crates/mooring-import/tests/fuzz_corpus.rs`.

/// Never panics (the crate entry asserts the oracle, see `mooring_import::ldap::fuzz`).
pub fn run(data: &[u8]) {
    mooring_import::ldap::fuzz::fuzz_filter_escape(data);
}
