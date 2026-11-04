//! Leaf certificate DER → [`CertificateInfo`] (what the TOFU dialog shows) and the
//! `SubjectPublicKey` bytes `CredSSP` binds to (ADR-0011 §Trust).
//!
//! The DER comes from the server and is hostile: parsing is `x509-parser` (pure Rust, no
//! `unsafe` in our code), trailing bytes are refused, and every string goes through
//! `CertificateInfo::new`, which strips control / bidi characters and caps lengths. Fuzzed via
//! [`crate::fuzz::certificate_info`].

use std::net::IpAddr;

use mooring_core::known_certs::{CertProblem, CertificateInfo};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;

/// Largest leaf certificate we look at (a real RDP certificate is 1–2 KiB).
pub const MAX_CERT_DER: usize = 64 * 1024;

/// Why a DER blob could not be described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertParseError {
    /// Larger than [`MAX_CERT_DER`].
    TooLarge,
    /// Not a single well-formed X.509 certificate.
    Malformed,
}

impl std::fmt::Display for CertParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "certificate too large",
            Self::Malformed => "malformed certificate",
        })
    }
}

impl std::error::Error for CertParseError {}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, CertParseError> {
    if der.len() > MAX_CERT_DER {
        return Err(CertParseError::TooLarge);
    }
    match x509_parser::parse_x509_certificate(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(CertParseError::Malformed),
    }
}

/// The raw `subjectPublicKey` BIT STRING contents of the leaf, which `CredSSP` uses for the
/// public-key binding (the same bytes `ironrdp-tls` extracts).
pub fn server_public_key(der: &[u8]) -> Result<Vec<u8>, CertParseError> {
    let cert = parse(der)?;
    let key = cert.public_key().subject_public_key.data.to_vec();
    if key.is_empty() {
        return Err(CertParseError::Malformed);
    }
    Ok(key)
}

/// Describe the leaf for the `certificate_trust` prompt.
///
/// `chain_problems` are what the chain verifier reported; this adds the facts we can read from
/// the certificate itself (self-signed, expired / not yet valid at `now`, the name not matching
/// `host`), so the dialog is complete even when the verifier stopped at its first error.
pub fn certificate_info(
    der: &[u8],
    host: &str,
    now: OffsetDateTime,
    chain_problems: &[CertProblem],
) -> Result<CertificateInfo, CertParseError> {
    let cert = parse(der)?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    let names = subject_names(&cert);

    let mut problems = chain_problems.to_vec();
    if cert.subject().as_raw() == cert.issuer().as_raw() {
        problems.push(CertProblem::SelfSigned);
    }
    if now > not_after {
        problems.push(CertProblem::Expired);
    }
    if now < not_before {
        problems.push(CertProblem::NotYetValid);
    }
    if !names.iter().any(|n| name_matches(n, host)) {
        problems.push(CertProblem::NameMismatch);
    }
    let san: Vec<String> = names.into_iter().map(|n| n.to_string()).collect();
    Ok(CertificateInfo::new(der, &subject, &issuer, not_before, not_after, &san, problems))
}

/// A name the certificate is valid for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CertName {
    Dns(String),
    Ip(IpAddr),
}

impl std::fmt::Display for CertName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns(d) => f.write_str(d),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// SAN DNS names and IP addresses; the subject CNs only when there is no SAN extension
/// (RFC 6125 §6.4.4).
fn subject_names(cert: &X509Certificate<'_>) -> Vec<CertName> {
    let mut out = Vec::new();
    let san = cert.subject_alternative_name().ok().flatten();
    if let Some(san) = san {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(d) => out.push(CertName::Dns((*d).to_owned())),
                GeneralName::IPAddress(b) => {
                    if let Ok(v4) = <[u8; 4]>::try_from(*b) {
                        out.push(CertName::Ip(IpAddr::from(v4)));
                    } else if let Ok(v6) = <[u8; 16]>::try_from(*b) {
                        out.push(CertName::Ip(IpAddr::from(v6)));
                    }
                }
                _ => {}
            }
        }
        return out;
    }
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            out.push(match s.parse::<IpAddr>() {
                Ok(ip) => CertName::Ip(ip),
                Err(_) => CertName::Dns(s.to_owned()),
            });
        }
    }
    out
}

/// Case-insensitive DNS match with a single left-most `*` label, or an exact IP match. Only
/// used to fill `problems` for the dialog; the chain decision is webpki's.
fn name_matches(name: &CertName, host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match (name, host.parse::<IpAddr>()) {
        (CertName::Ip(ip), Ok(h)) => *ip == h,
        (CertName::Dns(pattern), Err(_)) => dns_matches(pattern, host),
        _ => false,
    }
}

fn dns_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.split_once('.').is_some_and(|(label, rest)| {
            !label.is_empty() && rest == suffix && suffix.contains('.')
        });
    }
    pattern == host
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_certs::self_signed;

    #[test]
    fn describes_a_self_signed_leaf() {
        let (der, _) = self_signed(&["rdp.example.test"]);
        let now = OffsetDateTime::now_utc();
        let info = certificate_info(&der, "rdp.example.test", now, &[CertProblem::UnknownIssuer])
            .expect("parses");
        assert_eq!(info.problems, vec![CertProblem::SelfSigned, CertProblem::UnknownIssuer]);
        assert_eq!(info.san, vec!["rdp.example.test".to_owned()]);
        assert!(info.subject.contains("CN="), "{}", info.subject);
        assert_eq!(info.sha256.len(), 64);
    }

    #[test]
    fn flags_name_and_time_problems() {
        let (der, _) = self_signed(&["other.example.test", "192.0.2.10"]);
        // rcgen's default validity is 1975-01-01 .. 4096-01-01.
        let later = time::macros::datetime!(4097-01-01 0:00 UTC);
        let info = certificate_info(&der, "rdp.example.test", later, &[]).expect("parses");
        assert!(info.problems.contains(&CertProblem::NameMismatch));
        assert!(info.problems.contains(&CertProblem::Expired));
        let early =
            certificate_info(&der, "192.0.2.10", OffsetDateTime::UNIX_EPOCH, &[]).expect("ok");
        assert_eq!(early.problems, vec![CertProblem::SelfSigned, CertProblem::NotYetValid]);
        let ip = certificate_info(&der, "192.0.2.10", OffsetDateTime::now_utc(), &[]).expect("ip");
        assert!(!ip.problems.contains(&CertProblem::NameMismatch), "{:?}", ip.problems);
    }

    #[test]
    fn refuses_trailing_bytes_and_garbage() {
        let (mut der, _) = self_signed(&["a.example.test"]);
        assert!(server_public_key(&der).is_ok());
        der.push(0);
        assert_eq!(server_public_key(&der), Err(CertParseError::Malformed));
        assert_eq!(server_public_key(&[0x30, 0x03, 1, 2, 3]), Err(CertParseError::Malformed));
        assert_eq!(server_public_key(&vec![0; MAX_CERT_DER + 1]), Err(CertParseError::TooLarge));
    }

    #[test]
    fn wildcard_rules() {
        assert!(dns_matches("*.example.test", "a.example.test"));
        assert!(!dns_matches("*.example.test", "a.b.example.test"));
        assert!(!dns_matches("*.test", "example.test"));
        assert!(dns_matches("RDP.Example.Test.", "rdp.example.test"));
    }
}
