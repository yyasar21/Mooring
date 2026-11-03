//! Public-material parsers and `SHA256:` fingerprints (ADR-0009 §1, §7).
//!
//! OpenSSH public keys and certificates go through `RustCrypto` `ssh-key`; X.509 certificates
//! through `pem-rfc7468` + SHA-256 over the DER. Every input is size-capped before parsing and
//! every parser returns an error (never panics) on hostile input. Fingerprints use the OpenSSH
//! form `SHA256:<base64, no padding>`.

use sha2_next::{Digest, Sha256};
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};

use super::CredentialError;

/// Largest OpenSSH public key line (bytes).
pub const MAX_PUBLIC_KEY: usize = 16 * 1024;
/// Largest certificate / private key text (bytes).
pub const MAX_PEM: usize = 64 * 1024;

const CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const CERT_END: &str = "-----END CERTIFICATE-----";

/// `cert_pem` of an x509 row migrated from schema v2 before its first reseal (migration 0003).
/// The only `cert_pem` value that is not a parsable certificate.
pub const X509_MIGRATION_PLACEHOLDER: &str = "(sealed until the next unlock)";

/// Every PEM block in `text` must be a certificate: a private key (or any other block) in the
/// plaintext `cert_pem` would be stored in clear and served to the UI (review 3, B-3).
fn certificates_only(text: &str) -> Result<(), CredentialError> {
    let mut rest = text;
    while let Some(i) = rest.find("-----BEGIN ") {
        if !rest[i..].starts_with(CERT_BEGIN) {
            return Err(bad(
                "cert_pem",
                "may contain certificates only; put the private key in key_pem",
            ));
        }
        rest = &rest[i + CERT_BEGIN.len()..];
    }
    Ok(())
}

fn bad(field: &'static str, reason: &str) -> CredentialError {
    CredentialError::invalid(field, reason)
}

fn openssh_line<'a>(
    field: &'static str,
    text: &'a str,
    max: usize,
) -> Result<&'a str, CredentialError> {
    if text.len() > max {
        return Err(bad(field, "too long"));
    }
    let line = text.trim();
    if line.is_empty() || line.contains(['\n', '\r']) {
        return Err(bad(field, "must be one OpenSSH line"));
    }
    Ok(line)
}

/// `SHA256:` fingerprint of an OpenSSH public key line (`ssh-ed25519 AAAA… comment`).
pub fn ssh_public_key(text: &str) -> Result<String, CredentialError> {
    let line = openssh_line("public_key", text, MAX_PUBLIC_KEY)?;
    let key = PublicKey::from_openssh(line)
        .map_err(|_| bad("public_key", "not an OpenSSH public key"))?;
    if is_certificate_algorithm(line) {
        return Err(bad("public_key", "this is a certificate; put it in certificate"));
    }
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}

fn is_certificate_algorithm(line: &str) -> bool {
    line.split_whitespace().next().is_some_and(|a| a.ends_with("-cert-v01@openssh.com"))
}

/// `SHA256:` fingerprint of the key an OpenSSH certificate (`*-cert.pub`) certifies.
pub fn ssh_certificate(text: &str) -> Result<String, CredentialError> {
    let line = openssh_line("certificate", text, MAX_PEM)?;
    let cert = Certificate::from_openssh(line)
        .map_err(|_| bad("certificate", "not an OpenSSH certificate"))?;
    Ok(ssh_key::Fingerprint::new(HashAlg::Sha256, cert.public_key()).to_string())
}

/// Facts about a private key that are readable without its passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyInfo {
    /// `SHA256:` fingerprint when the key is in OpenSSH format (the public half is clear text).
    pub fingerprint: Option<String>,
    /// A FIDO2 `sk-*` key handle: needs the authenticator at connect time.
    pub security_key: bool,
}

/// Inspect a private key PEM without decrypting it. Legacy PEM (PKCS#1 / PKCS#8) has no clear
/// public half: `fingerprint` is `None` there. Fails only when the text is not PEM at all.
pub fn ssh_private_key(pem: &[u8]) -> Result<PrivateKeyInfo, CredentialError> {
    if pem.len() > MAX_PEM {
        return Err(bad("private_key", "larger than 64 KiB"));
    }
    let text = std::str::from_utf8(pem).map_err(|_| bad("private_key", "must be PEM text"))?;
    if !text.contains("-----BEGIN ") || !text.contains("PRIVATE KEY-----") {
        return Err(bad(
            "private_key",
            "must be a PEM private key (-----BEGIN … PRIVATE KEY-----)",
        ));
    }
    match PrivateKey::from_openssh(text.trim()) {
        Ok(key) => Ok(PrivateKeyInfo {
            fingerprint: Some(key.public_key().fingerprint(HashAlg::Sha256).to_string()),
            security_key: matches!(
                key.algorithm(),
                Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
            ),
        }),
        Err(_) => Ok(PrivateKeyInfo { fingerprint: None, security_key: false }),
    }
}

/// `SHA256:` fingerprint of the first certificate in a PEM text (leaf of a chain): SHA-256 over
/// the DER, OpenSSH-style base64. The DER must at least be a SEQUENCE, and every PEM block in
/// the text must be a `CERTIFICATE` (no private key may ride along).
pub fn x509_pem(text: &str) -> Result<String, CredentialError> {
    if text.len() > MAX_PEM {
        return Err(bad("cert_pem", "larger than 64 KiB"));
    }
    certificates_only(text)?;
    let start =
        text.find(CERT_BEGIN).ok_or_else(|| bad("cert_pem", "must be a PEM certificate"))?;
    let rest = &text[start..];
    let end =
        rest.find(CERT_END).ok_or_else(|| bad("cert_pem", "certificate PEM is not closed"))?;
    let block = &rest[..end + CERT_END.len()];
    let (label, der) =
        pem_rfc7468::decode_vec(block.as_bytes()).map_err(|_| bad("cert_pem", "invalid PEM"))?;
    if label != "CERTIFICATE" || der.first() != Some(&0x30) || der.len() < 16 {
        return Err(bad("cert_pem", "not a DER certificate"));
    }
    let digest = Sha256::digest(&der);
    Ok(format!("SHA256:{}", data_encoding::BASE64_NOPAD.encode(&digest)))
}

/// `true` for `SHA256:` + 43 base64 characters (an OpenSSH SHA-256 fingerprint).
#[must_use]
pub fn is_sha256_fingerprint(s: &str) -> bool {
    s.strip_prefix("SHA256:").is_some_and(|b| {
        b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    use crate::credential::testdata::{CERT_FP, CERT_PEM as CERT, ED25519_FP, ED25519_PUB};

    #[test]
    fn public_key_fingerprint() {
        let fp = ssh_public_key(ED25519_PUB).expect("parses");
        assert_eq!(fp, ED25519_FP);
        assert!(is_sha256_fingerprint(&fp), "{fp}");
        assert_eq!(ssh_public_key(&format!("  {ED25519_PUB}\n")).expect("trim"), fp);
        assert!(ssh_public_key("ssh-ed25519 notbase64").is_err());
        assert!(ssh_public_key(&format!("{ED25519_PUB}\n{ED25519_PUB}")).is_err());
        assert!(ssh_public_key(&"A".repeat(MAX_PUBLIC_KEY + 1)).is_err());
    }

    #[test]
    fn certificate_rejects_garbage() {
        assert!(ssh_certificate(ED25519_PUB).is_err(), "a plain key is not a certificate");
        assert!(ssh_certificate("ssh-ed25519-cert-v01@openssh.com AAAA").is_err());
    }

    #[test]
    fn private_key_inspection() {
        let seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).expect("small"));
        let kp = ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let key = PrivateKey::from(kp);
        let pem = key.to_openssh(ssh_key::LineEnding::LF).expect("encode");
        let info = ssh_private_key(pem.as_bytes()).expect("openssh");
        assert_eq!(info.fingerprint.as_deref(), Some(ED25519_FP), "same key as the public line");
        assert!(!info.security_key);
        assert!(ssh_private_key(b"not a key").is_err());
        let legacy = crate::credential::testdata::placeholder_key_pem();
        assert_eq!(
            ssh_private_key(legacy.as_bytes()).expect("pem"),
            PrivateKeyInfo { fingerprint: None, security_key: false }
        );
    }

    #[test]
    fn x509_fingerprint_is_sha256_of_der() {
        let fp = x509_pem(CERT).expect("parses");
        assert_eq!(fp, CERT_FP);
        let chain = format!("{CERT}{CERT}");
        assert_eq!(x509_pem(&chain).expect("chain"), fp, "leaf only");
        assert!(x509_pem("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----").is_err());
        assert!(x509_pem("-----BEGIN CERTIFICATE-----\nMIIB").is_err());
        assert!(x509_pem("hello").is_err());
    }

    #[test]
    fn x509_refuses_any_non_certificate_block() {
        let key = crate::credential::testdata::placeholder_key_pem();
        for bundle in
            [format!("{CERT}{key}"), format!("{key}{CERT}"), format!("{CERT}\n{key}{CERT}")]
        {
            let e = x509_pem(&bundle).expect_err("cert + key bundle refused").to_string();
            assert!(e.contains("put the private key in key_pem"), "{e}");
            assert!(!e.contains("AAAA") && !e.contains("PRIVATE"), "no echo: {e}");
        }
        let other = format!("{CERT}-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
        assert!(x509_pem(&other).is_err(), "only CERTIFICATE blocks");
        assert!(x509_pem(X509_MIGRATION_PLACEHOLDER).is_err(), "the placeholder is not a cert");
    }

    #[test]
    fn fingerprint_shape() {
        assert!(is_sha256_fingerprint(&format!("SHA256:{}", "a".repeat(43))));
        assert!(!is_sha256_fingerprint(&format!("SHA256:{}", "a".repeat(42))));
        assert!(!is_sha256_fingerprint(&format!("MD5:{}", "a".repeat(43))));
    }

    proptest! {
        #[test]
        fn parsers_never_panic(s in "\\PC{0,400}") {
            let _ = ssh_public_key(&s);
            let _ = ssh_certificate(&s);
            let _ = ssh_private_key(s.as_bytes());
            let _ = x509_pem(&s);
        }

        #[test]
        fn parsers_never_panic_on_framed_noise(body in "[A-Za-z0-9+/=\n]{0,300}") {
            let _ = x509_pem(&format!("{CERT_BEGIN}\n{body}\n{CERT_END}"));
            let _ = ssh_public_key(&format!("ssh-ed25519 {body}"));
            let _ = ssh_certificate(&format!("ssh-ed25519-cert-v01@openssh.com {body}"));
            let _ = ssh_private_key(format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
            ).as_bytes());
        }
    }
}
