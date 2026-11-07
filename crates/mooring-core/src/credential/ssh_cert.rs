//! OpenSSH certificates signed by a Vault SSH CA (ADR-0026 §1 `ssh_sign`): the public half of
//! the vault's own key (only that goes to Vault) and the check that a returned certificate
//! certifies **that** key, is a user certificate and is valid now. A certificate for another
//! key, a host certificate or an expired one is refused before it reaches the handshake.

use ssh_key::certificate::CertType;
use ssh_key::{Certificate, PrivateKey, PublicKey};

use super::fingerprint::{MAX_PEM, MAX_PUBLIC_KEY};
use super::CredentialError;

fn bad(reason: &'static str) -> CredentialError {
    CredentialError::invalid("certificate", reason)
}

/// The OpenSSH public key line (`<algorithm> <base64>`, no comment) of the key credential:
/// from the stored `public_key` when given, else from the clear public half of an OpenSSH
/// private key (readable without the passphrase). Legacy PEM keys need `public_key`.
pub fn ssh_public_key_line(
    public_key: Option<&str>,
    private_pem: &[u8],
) -> Result<String, CredentialError> {
    let key = match public_key.map(str::trim).filter(|s| !s.is_empty()) {
        Some(line) if line.len() <= MAX_PUBLIC_KEY => PublicKey::from_openssh(line)
            .map_err(|_| CredentialError::invalid("public_key", "not an OpenSSH public key"))?,
        Some(_) => return Err(CredentialError::invalid("public_key", "too long")),
        None => {
            if private_pem.len() > MAX_PEM {
                return Err(CredentialError::invalid("private_key", "larger than 64 KiB"));
            }
            let text = std::str::from_utf8(private_pem)
                .map_err(|_| CredentialError::invalid("private_key", "must be PEM text"))?;
            PrivateKey::from_openssh(text.trim())
                .map_err(|_| {
                    CredentialError::invalid(
                        "public_key",
                        "is needed for a PEM key (only OpenSSH keys carry their public half)",
                    )
                })?
                .public_key()
                .clone()
        }
    };
    let mut key = key;
    key.set_comment("");
    key.to_openssh().map(|s| s.trim().to_owned()).map_err(|_| bad("public key not encodable"))
}

/// Facts of a checked certificate (for the audit row; no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCertificate {
    /// The certificate line, re-encoded (`<algorithm>-cert-v01@openssh.com <base64>`).
    pub line: String,
    /// Number of principals.
    pub principals: usize,
    /// `valid_before` (Unix seconds).
    pub valid_before: u64,
    /// Certificate serial.
    pub serial: u64,
}

/// Check `cert_line` (Vault's `signed_key`) against `public_key_line` at `now` (Unix seconds).
pub fn check_signed_certificate(
    cert_line: &str,
    public_key_line: &str,
    now: u64,
) -> Result<SignedCertificate, CredentialError> {
    let line = cert_line.trim();
    if line.is_empty() || line.len() > MAX_PEM || line.contains(['\n', '\r']) {
        return Err(bad("must be one OpenSSH certificate line"));
    }
    let cert = Certificate::from_openssh(line).map_err(|_| bad("not an OpenSSH certificate"))?;
    let key = PublicKey::from_openssh(public_key_line.trim())
        .map_err(|_| CredentialError::invalid("public_key", "not an OpenSSH public key"))?;
    if cert.public_key() != key.key_data() {
        return Err(bad("certifies another key than the SSH key credential"));
    }
    if cert.cert_type() != CertType::User {
        return Err(bad("is not a user certificate"));
    }
    if cert.valid_before() <= now || cert.valid_after() > now.saturating_add(300) {
        return Err(bad("is not valid now"));
    }
    let line = cert.to_openssh().map_err(|_| bad("not encodable"))?;
    Ok(SignedCertificate {
        line: line.trim().to_owned(),
        principals: cert.valid_principals().len(),
        valid_before: cert.valid_before(),
        serial: cert.serial(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::testdata::placeholder_key_pem;
    use ssh_key::certificate::Builder;
    use ssh_key::private::Ed25519Keypair;

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn cert(
        subject: &PrivateKey,
        ca: &PrivateKey,
        kind: CertType,
        after: u64,
        before: u64,
    ) -> String {
        let mut b = Builder::new([7u8; 16], subject.public_key().key_data().clone(), after, before)
            .expect("builder");
        b.cert_type(kind).expect("type");
        b.valid_principal("deploy").expect("principal");
        b.serial(42).expect("serial");
        b.sign(ca).expect("sign").to_openssh().expect("line")
    }

    #[test]
    fn public_key_from_private_or_field() {
        let pem = key(3).to_openssh(ssh_key::LineEnding::LF).expect("pem");
        let line = ssh_public_key_line(None, pem.as_bytes()).expect("from pem");
        assert!(line.starts_with("ssh-ed25519 "), "{line}");
        assert_eq!(line.split_whitespace().count(), 2, "no comment");
        let field = format!("{line} user@example.test");
        assert_eq!(ssh_public_key_line(Some(&field), b"").expect("field"), line);
        assert!(
            ssh_public_key_line(None, placeholder_key_pem().as_bytes()).is_err(),
            "PEM: no public half"
        );
        assert!(ssh_public_key_line(Some("ssh-ed25519 !!"), b"").is_err());
    }

    #[test]
    fn certificate_must_certify_our_key_now() {
        let (me, other, ca) = (key(1), key(2), key(9));
        let mut pub_line = me.public_key().clone();
        pub_line.set_comment("");
        let pub_line = pub_line.to_openssh().expect("pub");
        let now = 1_800_000_000;
        let ok = check_signed_certificate(
            &cert(&me, &ca, CertType::User, now - 60, now + 3600),
            &pub_line,
            now,
        )
        .expect("ok");
        assert_eq!((ok.principals, ok.valid_before, ok.serial), (1, now + 3600, 42));
        let e = check_signed_certificate(
            &cert(&other, &ca, CertType::User, now - 60, now + 3600),
            &pub_line,
            now,
        )
        .expect_err("wrong key");
        assert!(e.to_string().contains("another key"), "{e}");
        assert!(check_signed_certificate(
            &cert(&me, &ca, CertType::Host, now - 60, now + 3600),
            &pub_line,
            now
        )
        .is_err());
        assert!(check_signed_certificate(
            &cert(&me, &ca, CertType::User, now - 7200, now - 1),
            &pub_line,
            now
        )
        .is_err());
        for junk in ["", "ssh-ed25519-cert-v01@openssh.com AAAA", &pub_line, "a\nb"] {
            assert!(check_signed_certificate(junk, &pub_line, now).is_err(), "{junk}");
        }
    }

    #[test]
    fn fixtures_check() {
        use crate::credential::testdata as t;
        let ok = check_signed_certificate(t::SSH_CA_CERT, t::SSH_CA_SUBJECT_PUB, 1_800_000_000)
            .expect("fixture");
        assert_eq!(ok.principals, 1);
        assert!(
            check_signed_certificate(t::SSH_CA_CERT_OTHER_KEY, t::SSH_CA_SUBJECT_PUB, 1).is_err()
        );
        assert!(check_signed_certificate(t::SSH_CA_CERT_HOST, t::SSH_CA_SUBJECT_PUB, 1).is_err());
    }
}
