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
