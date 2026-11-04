//! Fuzz entry `vnc_tight`: one Tight basic rect payload (ADR-0012 `tight_decode`); bytes 0–1 pick the rect size ≤ 64².

/// Never panics; decoded pixels are exactly w·h·4 bytes.
pub fn run(data: &[u8]) {
    mooring_proto_vnc::fuzz::tight(data);
}
