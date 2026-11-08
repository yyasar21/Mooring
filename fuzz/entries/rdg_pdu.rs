//! Fuzz entry `rdg_pdu`: MS-TSGU packets and WebSocket frames from an RD Gateway (ADR-0027 §1), both roles. Shared by
//! `fuzz/fuzz_targets/rdg_pdu.rs` and the stable replay in
//! `crates/mooring-proto-rdp/tests/fuzz_corpus.rs`.

/// Never panics; work is bounded by `MAX_PACKET` / `MAX_FRAME`.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::gateway::fuzz_rdg_pdu(data);
}
