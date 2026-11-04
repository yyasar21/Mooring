//! Fuzz entry `rfb_handshake`: the pre-TLS RFB handshake (version, security list or reason, security selection matrix, `SecurityResult`, `ServerInit`) that a T3 controls (review 5 L-28).

/// Never panics; a selected type was offered and a pin forces `VeNCrypt`; `ServerInit` is ≤ 8192².
pub fn run(data: &[u8]) {
    mooring_proto_vnc::fuzz::handshake(data);
}
