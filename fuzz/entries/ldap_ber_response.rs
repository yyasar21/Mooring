//! Fuzz entry `ldap_ber_response`: a server frame: iterative scan, BER parse, message / entry decoding, plan mapping.
//! Shared by `fuzz/fuzz_targets/ldap_ber_response.rs` and the stable replay in
//! `crates/mooring-import/tests/fuzz_corpus.rs`.

/// Never panics (the crate entry asserts the oracle, see `mooring_import::ldap::fuzz`).
pub fn run(data: &[u8]) {
    mooring_import::ldap::fuzz::fuzz_ber_response(data);
}
