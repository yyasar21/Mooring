//! Fuzz entry `vencrypt_negotiation`: the `VeNCrypt` 0.2 sub-negotiation before the TLS upgrade (version, ack, subtype list, subtype ack) (review 5 L-28).

/// Never panics; a selected subtype was offered.
pub fn run(data: &[u8]) {
    mooring_proto_vnc::fuzz::vencrypt(data);
}
