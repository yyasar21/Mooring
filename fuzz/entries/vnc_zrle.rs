//! Fuzz entry `vnc_zrle`: one ZRLE rect payload (ADR-0012 `zrle_decode`); bytes 0–1 pick the rect size ≤ 64².

/// Never panics; decoded pixels are exactly w·h·4 bytes.
pub fn run(data: &[u8]) {
    mooring_proto_vnc::fuzz::zrle(data);
}
