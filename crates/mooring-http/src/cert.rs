//! Leaf certificate DER → [`CertificateInfo`] for the `certificate_trust` prompt.
//!
//! The DER is server-controlled: `x509-parser` (pure Rust), a size cap, trailing bytes refused,
//! and every string goes through `CertificateInfo::new` (control / bidi characters replaced,
//! lengths capped). An unparsable leaf still gets a fingerprint: the user decides on that.
//! Fuzzed through [`crate::fuzz::fuzz_certificate_info`].

use mooring_core::known_certs::{CertProblem, CertificateInfo};
use time::OffsetDateTime;
use x509_parser::extensions::GeneralName;

/// Largest leaf certificate we parse (real server certificates are 1–4 KiB).
pub const MAX_CERT_DER: usize = 64 * 1024;

/// Describe `der`. `problems` are what the chain verifier and the name check reported; this
/// adds what the certificate itself says (self-signed, expired / not yet valid at `now`).
pub fn certificate_info(
    der: &[u8],
    mut problems: Vec<CertProblem>,
    now: OffsetDateTime,
) -> CertificateInfo {
    let parsed = if der.len() > MAX_CERT_DER {
        None
    } else {
        match x509_parser::parse_x509_certificate(der) {
            Ok(([], cert)) => Some(cert),
            _ => None,
        }
    };
    let Some(cert) = parsed else {
        let epoch = OffsetDateTime::UNIX_EPOCH;
        return CertificateInfo::new(
            der,
            "(unparsable certificate)",
            "",
            epoch,
            epoch,
            &[],
            problems,
        );
    };
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    if now > not_after {
        problems.push(CertProblem::Expired);
    }
    if now < not_before {
        problems.push(CertProblem::NotYetValid);
    }
    if cert.subject().as_raw() == cert.issuer().as_raw() {
        problems.push(CertProblem::SelfSigned);
    }
    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => san.push((*d).to_owned()),
                GeneralName::IPAddress(ip) => san.push(ip_text(ip)),
                _ => {}
            }
        }
    }
    CertificateInfo::new(
        der,
        &cert.subject().to_string(),
        &cert.issuer().to_string(),
        not_before,
        not_after,
        &san,
        problems,
    )
}

fn ip_text(raw: &[u8]) -> String {
    if let Ok(v4) = <[u8; 4]>::try_from(raw) {
        std::net::Ipv4Addr::from(v4).to_string()
    } else if let Ok(v6) = <[u8; 16]>::try_from(raw) {
        std::net::Ipv6Addr::from(v6).to_string()
    } else {
        "(invalid IP)".to_owned()
    }
}
