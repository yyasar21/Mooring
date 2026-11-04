//! Fuzz entry `external_ref_parse`: a typed Vault reference (`mount/path`) and a whole
//! `external_ref` field document (ADR-0016 §2). Shared by
//! `fuzz/fuzz_targets/external_ref_parse.rs` and the stable replay in
//! `crates/mooring-core/tests/fuzz_corpus.rs`.

use mooring_core::credential::parse_vault_reference;

/// Never panics. An accepted reference round-trips (the crate entry asserts that), has no
/// empty, `.` or `..` segment, no `/` at either end and only `[A-Za-z0-9._-]` bytes.
pub fn run(data: &[u8]) {
    mooring_core::credential::fuzz_external_ref(data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(p) = parse_vault_reference(s) {
        assert!(!s.starts_with('/') && !s.ends_with('/'));
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b)), "{s:?}");
        for seg in s.split('/') {
            assert!(!seg.is_empty() && seg != "." && seg != "..", "{s:?}");
        }
        assert!(!p.mount.is_empty());
    }
}
