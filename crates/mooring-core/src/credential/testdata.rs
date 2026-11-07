//! Synthetic public test material shared by the credential tests of this and other crates
//! (store, Tauri). Nothing here is a real key or certificate of any system.

/// Self-signed P-256 certificate for `client.example.test` (public material).
pub const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBKDCBz6ADAgECAgEBMAoGCCqGSM49BAMCMB4xHDAaBgNVBAMME2NsaWVudC5l
eGFtcGxlLnRlc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAeMRww
GgYDVQQDDBNjbGllbnQuZXhhbXBsZS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEJu/OvQ7p40pmkYfhizqRIrL3M5RbZJzJ+fkh6fna2BKQI4venMe7Mw0V
DGdwTdJa5wVSBXRLbzG/QHB0WHLQ5jAKBggqhkjOPQQDAgNIADBFAiAz4qIZQnek
9uPm+oH7lfZ2caYItyhZVZBRp0LuDQr+0AIhAOO9oZuzE0bingvMGB/dqUd+jlcS
T/ZqAF/6XQz6JbEB
-----END CERTIFICATE-----
";

/// SHA-256 over the DER of [`CERT_PEM`] (computed independently with Python `cryptography`).
pub const CERT_FP: &str = "SHA256:1lOqB+uHMtVZO4n0LcJlNNnCV0/rnYXDh+3bMCPvSTs";

/// Ed25519 public key whose private seed is the bytes `0..32` (test only).
pub const ED25519_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4 test@example.test";

/// OpenSSH fingerprint of [`ED25519_PUB`] (computed independently).
pub const ED25519_FP: &str = "SHA256:lbmsoA0yIEcEiVDRnMWuzm+nV+3ZEEpVIURqFoeSspg";

/// A PEM-framed placeholder private key: right shape for validation, no key material.
#[must_use]
pub fn placeholder_key_pem() -> String {
    let label = ["PRIVATE", "KEY"].join(" ");
    format!("-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n")
}

/// A self-contained kubeconfig with two contexts and an inline (fake) token.
pub const KUBECONFIG: &str = "apiVersion: v1
kind: Config
current-context: lab
clusters:
- name: lab
  cluster:
    server: https://k8s.example.test:6443
    certificate-authority-data: AAAA
contexts:
- name: lab
  context:
    cluster: lab
    user: ops
- name: lab-admin
  context: {cluster: lab, user: ops, namespace: kube-system}
users:
- name: ops
  user:
    token: test-only-token
";

/// ADR-0026 `ssh_sign` fixtures (deterministic Ed25519 test keys from fixed seeds, public
/// material only): the subject key's public line, a user certificate for it with principal
/// `deploy` valid forever, one for another key and a host certificate, all from one test CA.
pub const SSH_CA_SUBJECT_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIhLiFf06qFhPGFQTbNNS+rzRlF6DjHePN3U2bQgHZ0L";

/// User certificate of [`SSH_CA_SUBJECT_PUB`] (principal `deploy`, serial 42, forever).
pub const SSH_CA_CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAEAcHBwcHBwcHBwcHBwcHBwcAAAAgiEuIV/TqoWE8YVBNs01L6vNGUXoOMd483dTZtCAdnQsAAAAAAAAAKgAAAAEAAAAAAAAACgAAAAZkZXBsb3kAAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD6SDQUf25pDDaT7/YTNgRkA82K4qFPMbPEBzWFaSOVZQAAAFMAAAALc3NoLWVkMjU1MTkAAABAvWX9GDMVhDVfbMHEJQc/PCw13h5KGh2TJwNMx7chq3aySqCouPwSzlJNE2sxhYNrWDszTV4j02xMrPTODMpVCg==";

/// The same CA certifying another key.
pub const SSH_CA_CERT_OTHER_KEY: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAEAcHBwcHBwcHBwcHBwcHBwcAAAAgoJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPAAAAAAAAAAKgAAAAEAAAAAAAAACgAAAAZkZXBsb3kAAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD6SDQUf25pDDaT7/YTNgRkA82K4qFPMbPEBzWFaSOVZQAAAFMAAAALc3NoLWVkMjU1MTkAAABANAt73Dlf4GOum/BNPO8M/pYE1a9I1/KADxN2BsfH73MGipQz5Nbh3JeckQmQDqt2/1DWBdTR8ey/UloQ1mvlDQ==";

/// A host certificate of [`SSH_CA_SUBJECT_PUB`].
pub const SSH_CA_CERT_HOST: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAEAcHBwcHBwcHBwcHBwcHBwcAAAAgiEuIV/TqoWE8YVBNs01L6vNGUXoOMd483dTZtCAdnQsAAAAAAAAAKgAAAAIAAAAAAAAACgAAAAZkZXBsb3kAAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD6SDQUf25pDDaT7/YTNgRkA82K4qFPMbPEBzWFaSOVZQAAAFMAAAALc3NoLWVkMjU1MTkAAABAeLlRHPzKSdaGcugS5UJRCFbE/IyQKXT1tEitvijw1+xXNVpRGVJeT8IQYvvATDKyrJ9btACdhTBuQkewvikEAg==";

/// ADR-0024 fixtures: an `sk-ssh-ed25519@openssh.com` key over the 32-byte Ed25519 point
/// `point` (pass the public half of a seeded test key to sign with it in a fake agent).
#[must_use]
pub fn sk_ed25519_public(point: [u8; 32], application: &str) -> ssh_key::PublicKey {
    let key = ssh_key::public::SkEd25519::new(
        ssh_key::public::Ed25519PublicKey(point),
        application.to_owned(),
    );
    ssh_key::PublicKey::new(ssh_key::public::KeyData::SkEd25519(key), "")
}

/// The `sk-ecdsa-sha2-nistp256@openssh.com` key over the P-256 generator point.
#[must_use]
pub fn sk_ecdsa_public(application: &str) -> ssh_key::PublicKey {
    const G: &[u8] = b"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    let g = data_encoding::HEXLOWER.decode(G).unwrap_or_default();
    let key = match ssh_key::public::EcdsaPublicKey::from_sec1_bytes(&g) {
        Ok(ssh_key::public::EcdsaPublicKey::NistP256(p)) => {
            ssh_key::public::KeyData::SkEcdsaSha2NistP256(
                ssh_key::public::SkEcdsaSha2NistP256::new(p, application.to_owned()),
            )
        }
        _ => ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([0; 32])),
    };
    ssh_key::PublicKey::new(key, "")
}

/// The OpenSSH line of a public key (no comment).
#[must_use]
pub fn public_line(key: &ssh_key::PublicKey) -> String {
    key.to_openssh().unwrap_or_default()
}

/// An unencrypted key-handle file (`id_ed25519_sk`) for `public` with `flags` and `handle`
/// (test material: a FIDO handle is useless without the authenticator).
#[must_use]
pub fn sk_key_handle_pem(public: &ssh_key::PublicKey, flags: u8, handle: &[u8]) -> String {
    use ssh_key::private::{self, KeypairData};
    use ssh_key::public::KeyData;
    let data = match public.key_data() {
        KeyData::SkEd25519(k) => private::SkEd25519::new(k.clone(), flags, handle.to_vec())
            .ok()
            .map(KeypairData::SkEd25519),
        KeyData::SkEcdsaSha2NistP256(k) => {
            private::SkEcdsaSha2NistP256::new(k.clone(), flags, handle.to_vec())
                .ok()
                .map(KeypairData::SkEcdsaSha2NistP256)
        }
        _ => None,
    };
    data.and_then(|d| ssh_key::PrivateKey::new(d, "sk@example.test").ok())
        .and_then(|k| k.to_openssh(ssh_key::LineEnding::LF).ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}
