//! Fuzz entry `rdp_fastpath`: hostile fast-path / X.224 server PDUs into the RDP active stage
//! (ADR-0011 §Tests, `rdp_active_stage`): byte 0 picks fast-path (even) or X.224 (odd), the rest
//! goes through `ActiveStage::process` at 1024×768 and every graphics update into a `FrameSink`.
//! Upstream `IronRDP` targets (`pdu_decoding`, `bitmap_stream`, …) stay a separate item (Q1).

/// Never panics; sink writes are bounds-checked by `FrameSink`.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::fuzz::active_stage(data);
}
