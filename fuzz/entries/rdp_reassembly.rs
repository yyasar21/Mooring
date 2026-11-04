//! Fuzz entry `rdp_reassembly`: framed server PDUs (`[action, len16, bytes]`) through the interim channel / fast-path reassembly caps (review 5 M-14, L-28).

/// Never panics; oversized reassembly is refused before it is counted past 8 MiB.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::fuzz::reassembly(data);
}
