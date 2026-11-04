//! Fuzz entry `vsphere_session_token`: `POST /api/session` response body (a JSON string)
//! (ADR-0015 §1). Shared by `fuzz/fuzz_targets/vsphere_session_token.rs` and the stable replay
//! in `crates/mooring-vsphere/tests/fuzz_corpus.rs`.

use mooring_vsphere::parse_session_token;

/// Never panics. Only a JSON string of 1..=256 visible ASCII bytes is accepted (the crate
/// entry asserts that); a body over 4 KiB is refused; parsing is deterministic.
pub fn run(data: &[u8]) {
    mooring_vsphere::fuzz::fuzz_session_token(data);
    let first = parse_session_token(data).ok();
    let again = parse_session_token(data).ok();
    assert_eq!(first.is_some(), again.is_some(), "parse_session_token is not deterministic");
    if data.len() > 4 * 1024 {
        assert!(first.is_none(), "oversized session body accepted");
    }
}
