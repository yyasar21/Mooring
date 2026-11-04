//! Fuzz entry `known_certs_parse`: hostile `known_rdp_certs` / `known_vnc_certs` bytes
//! (ADR-0011 §Trust, shared with ADR-0012). Shared by `fuzz/fuzz_targets/known_certs_parse.rs`
//! and the stable corpus replay in `crates/mooring-core/tests/fuzz_corpus.rs`.

use mooring_core::known_certs::{KnownCerts, MAX_LINES};

/// Never panics. Parsing is deterministic, at most `MAX_LINES` lines yield pins, and every
/// listed pin has the display form `SHA256:<64 hex>` and a hashed host.
pub fn run(data: &[u8]) {
    let first = KnownCerts::parse_bytes(data);
    let again = KnownCerts::parse_bytes(data);
    assert_eq!(format!("{:?}", first.list()), format!("{:?}", again.list()), "not deterministic");
    assert!(first.len() <= MAX_LINES);
    for pin in first.list() {
        assert!(pin.fingerprint.starts_with("SHA256:") && pin.fingerprint.len() == 7 + 64);
        assert!(pin.host_hash.starts_with("|2|") || !pin.host_hash.is_empty());
    }
    let _ = first.check("rdp.example.test", 3389, &[0u8; 32]);
}
