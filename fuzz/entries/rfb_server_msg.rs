//! Fuzz entry `rfb_server_msg`: hostile RFB server messages after `ServerInit` (ADR-0012
//! §Tests, `rfb_server_message`: `FramebufferUpdate` with every encoding, `ServerCutText`,
//! `Bell`, `SetColourMapEntries`) through the session's own framing and decoders into a
//! `FrameSink`. Bytes 0–1 pick the starting framebuffer size (see `mooring_proto_vnc::fuzz`).

/// Never panics; every decoded rect lies inside the framebuffer and has exactly w·h·4 bytes.
pub fn run(data: &[u8]) {
    mooring_proto_vnc::fuzz::server_messages(data);
}
