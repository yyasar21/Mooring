//! Fuzz entry `known_certs_parse`: hostile `known_rdp_certs` / `known_vnc_certs` bytes
//! (ADR-0011 §Trust, shared with ADR-0012). Shared by `fuzz/fuzz_targets/known_certs_parse.rs`
//! and, once R1 has merged, the stable corpus replay in `crates/mooring-core/tests/fuzz_corpus.rs`.
//!
//! PENDING(R1): `mooring_core::known_certs::parse_bytes` is being written by rust-core (A2
//! task R1). Until it exists the target is built without the `r1` feature and `run` is a no-op.
//! When R1 lands: build with `--features r1`, check the calls below against the real API, add
//! the write + re-parse round trip (as `known_hosts_parse` does), then remove the gate.

/// Never panics. With R1: parsing is deterministic and the documented caps hold (lines over
/// 8 KiB and everything past 10 000 lines are skipped, malformed lines are skipped).
#[cfg(feature = "r1")]
pub fn run(data: &[u8]) {
    let first = mooring_core::known_certs::parse_bytes(data);
    let again = mooring_core::known_certs::parse_bytes(data);
    assert_eq!(format!("{first:?}"), format!("{again:?}"), "parse_bytes is not deterministic");
    // TODO(R1): assert entry count ≤ 10 000 and the to-file + re-parse fixed point.
}

/// Stub until R1 merges (see the module docs).
#[cfg(not(feature = "r1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
