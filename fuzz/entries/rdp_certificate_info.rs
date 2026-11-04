//! Fuzz entry `rdp_certificate_info`: hostile leaf DER → `CertificateInfo` and the `CredSSP` public key (ADR-0011 `certificate_info`).

/// Never panics.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::fuzz::certificate_info(data);
}
