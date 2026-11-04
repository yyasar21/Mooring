//! Fuzz entry `vault_header_from_bytes`: the vault header is read before any key exists, so it
//! is parsed as hostile input (ADR-0002, ADR-0006). Shared by
//! `fuzz/fuzz_targets/vault_header_from_bytes.rs` and `crates/mooring-vault/tests/fuzz_corpus.rs`.

use mooring_vault::{Header, MAX_HEADER_BYTES};

/// Never panics; an accepted header is within the size cap and survives a write + read.
pub fn run(data: &[u8]) {
    let Ok(header) = Header::from_bytes(data) else {
        return;
    };
    assert!(data.len() <= MAX_HEADER_BYTES, "accepted an over-size header");
    let bytes = header.to_bytes().expect("an accepted header serialises");
    let again = Header::from_bytes(&bytes).expect("a written header is accepted again");
    assert_eq!(header, again, "header changed across write + read");
}
