//! [`CertificateInfo`]: what the TOFU dialog shows about a server certificate.

use serde::{Deserialize, Serialize};
use sha2_next::{Digest, Sha256};
use time::OffsetDateTime;

use crate::model::is_bidi_or_invisible;

/// Longest subject / issuer shown, in characters.
pub const MAX_DN: usize = 1024;
/// Most SAN entries shown.
pub const MAX_SAN: usize = 64;
/// Longest SAN entry shown, in characters.
pub const MAX_SAN_LEN: usize = 255;

/// Why the chain did not validate (ADR-0011 `problems`). Set by our verifier, never parsed
/// from server text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertProblem {
    /// Issuer equals subject and it is not a trusted root.
    SelfSigned,
    /// The chain does not lead to a trusted root (system roots + `caPem`).
    UnknownIssuer,
    /// The certificate does not name the host we connected to.
    NameMismatch,
    /// `not_after` is in the past.
    Expired,
    /// `not_before` is in the future.
    NotYetValid,
}

/// A server certificate as shown in the `certificate_trust` prompt.
///
/// Built by the protocol crate's verifier from the leaf DER (R3/R4: the DER → fields parser
/// lives there, behind its own fuzz target). The constructor here sanitises the strings, since
/// subject, issuer and SANs are server-controlled: control, bidi and invisible characters are
/// replaced with `?` and lengths are capped. Wire form (inside `SessionEvent::Prompt`) is
/// `snake_case` like the rest of `SessionEvent`; times are RFC 3339 strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject distinguished name, RFC 4514 text.
    pub subject: String,
    /// Issuer distinguished name, RFC 4514 text.
    pub issuer: String,
    /// Start of validity.
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// End of validity.
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// SHA-256 of the leaf DER, 64 lowercase hex digits (shown as `SHA256:<hex>`).
    pub sha256: String,
    /// Subject alternative names (DNS names and IP addresses as text). Addition to the ADR
    /// field list, requested by the R1 brief.
    #[serde(default)]
    pub san: Vec<String>,
    /// Chain problems, sorted, without duplicates. Empty when only the pin was missing.
    pub problems: Vec<CertProblem>,
}

impl CertificateInfo {
    /// Build from already-parsed fields; `der` is the leaf certificate, fingerprinted here.
    pub fn new(
        der: &[u8],
        subject: &str,
        issuer: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        san: &[String],
        mut problems: Vec<CertProblem>,
    ) -> Self {
        problems.sort_unstable();
        problems.dedup();
        Self {
            subject: sanitize(subject, MAX_DN),
            issuer: sanitize(issuer, MAX_DN),
            not_before,
            not_after,
            sha256: hex(&fingerprint(der)),
            san: san.iter().take(MAX_SAN).map(|s| sanitize(s, MAX_SAN_LEN)).collect(),
            problems,
        }
    }

    /// Whether the verifier found the certificate self-signed.
    pub fn is_self_signed(&self) -> bool {
        self.problems.contains(&CertProblem::SelfSigned)
    }

    /// `SHA256:<hex>`, the form used in `Connected.peer_identity` (after `x509 `) and in the
    /// mismatch reason.
    pub fn display_fingerprint(&self) -> String {
        format!("SHA256:{}", self.sha256)
    }
}

/// SHA-256 of a certificate's DER (the pin).
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    out
}

/// `SHA256:<hex>` of a pin.
pub fn display_fingerprint(sha256: &[u8; 32]) -> String {
    format!("SHA256:{}", hex(sha256))
}

/// `"x509 SHA256:<hex>"` for `Connected.peer_identity` (ADR-0011).
pub fn peer_identity(sha256: &[u8; 32]) -> String {
    format!("x509 {}", display_fingerprint(sha256))
}

fn sanitize(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() || is_bidi_or_invisible(c) { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_and_fingerprints() {
        let t = OffsetDateTime::UNIX_EPOCH;
        let info = CertificateInfo::new(
            b"abc",
            "CN=evil\u{202E}gpj.exe\n",
            &"x".repeat(5000),
            t,
            t,
            &vec!["a.example.test".to_owned(); 100],
            vec![CertProblem::UnknownIssuer, CertProblem::SelfSigned, CertProblem::SelfSigned],
        );
        assert_eq!(info.subject, "CN=evil?gpj.exe?");
        assert_eq!(info.issuer.chars().count(), MAX_DN);
        assert_eq!(info.san.len(), MAX_SAN);
        assert_eq!(info.problems, vec![CertProblem::SelfSigned, CertProblem::UnknownIssuer]);
        assert!(info.is_self_signed());
        // SHA-256("abc")
        assert_eq!(info.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(peer_identity(&fingerprint(b"abc")), format!("x509 SHA256:{}", info.sha256));
    }

    #[test]
    fn wire_shape() {
        let t = OffsetDateTime::UNIX_EPOCH;
        let info =
            CertificateInfo::new(b"", "CN=a", "CN=a", t, t, &[], vec![CertProblem::NotYetValid]);
        let v = serde_json::to_value(&info).expect("json");
        assert_eq!(v["not_before"], "1970-01-01T00:00:00Z");
        assert_eq!(v["problems"][0], "not_yet_valid");
        let back: CertificateInfo = serde_json::from_value(v).expect("round trip");
        assert_eq!(back, info);
    }
}
