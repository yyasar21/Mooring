//! Fuzz entry `rdp_fastpath`: hostile fast-path / X.224 server PDUs into the RDP active stage
//! (ADR-0011 §Tests, "rdp_active_stage": bytes → `ActiveStage::process` at 1024×768, through
//! Mooring's frame sink).
//!
//! PENDING(R3): `mooring-proto-rdp` (A2 task R3) does not yet expose its active-stage driver.
//! Placeholder so the nightly matrix is ready; build with `--features r3` once R3 exposes an
//! entry that feeds one PDU through `ActiveStage::process` into a `FrameSink`, then remove the
//! gate. Invariants to assert then: no panic, every sink write inside the framebuffer, no
//! allocation beyond the MFR1 caps. Upstream IronRDP targets (`pdu_decoding`,
//! `bitmap_stream`, …) stay a separate nightly item (Q1).

#[cfg(feature = "r3")]
pub fn run(data: &[u8]) {
    // TODO(R3): call the RDP active-stage driver here.
    let _ = data;
}

/// Stub until R3 merges (see the module docs).
#[cfg(not(feature = "r3"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
