//! Fuzz entry `rfb_server_msg`: hostile RFB server messages after ServerInit (ADR-0012 §Tests,
//! "rfb_server_message": dispatch over FramebufferUpdate with every encoding, ServerCutText,
//! Bell, SetColourMapEntries).
//!
//! PENDING(R4): the RFB client in `mooring-proto-vnc` is being written by rust-core (A2 task
//! R4) and has no public decoder entry yet. Placeholder so the nightly matrix is ready; build
//! with `--features r4` once R4 exposes one (e.g. a `decode_server_message(&mut state, &[u8])`
//! writing into a `FrameSink`), then remove the gate. Invariants to assert then: no panic,
//! decoded output within the ADR caps (fb ≤ 8192², zlib output ≤ 64 MiB per rect, Tight
//! palette ≤ 256, cursor ≤ 384², ServerCutText ≤ 1 MiB), every write inside the `FrameSink`.
//! The RFB test server (`mooring-testsrv::rfb`) can generate valid seeds for every encoding.

#[cfg(feature = "r4")]
pub fn run(data: &[u8]) {
    // TODO(R4): call the RFB server-message decoder here.
    let _ = data;
}

/// Stub until R4 merges (see the module docs).
#[cfg(not(feature = "r4"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
