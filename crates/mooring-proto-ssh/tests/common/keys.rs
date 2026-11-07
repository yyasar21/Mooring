//! Deterministic test keys and the CA check of the test server's certificate auth
//! (ADR-0026 §1). Test material only.

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Certificate, HashAlg, PrivateKey, PublicKey};
use secrecy::SecretString;

/// Deterministic test key from a seed byte.
pub fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

/// Unencrypted OpenSSH PEM of a test key (test material only).
pub fn pem(key: &PrivateKey) -> SecretString {
    SecretString::from(key.to_openssh(LineEnding::LF).expect("encode test key").to_string())
}

/// A user certificate for `user`, signed by `ca` (and valid now), is accepted.
pub fn certificate_ok(ca: Option<&PublicKey>, certificate: &Certificate, user: &str) -> bool {
    ca.is_some_and(|ca| {
        let fp = ca.fingerprint(HashAlg::Sha256);
        certificate.validate([&fp]).is_ok()
            && certificate.valid_principals().iter().any(|p| p == user)
    })
}

/// Pre-trust the server key in a fresh `known_hosts` file.
pub fn trust(kh: &std::path::Path, port: u16, key: &PublicKey) {
    let mut store = mooring_proto_ssh::KnownHosts::new();
    store.add_hashed("127.0.0.1", port, key).expect("add");
    store.save(kh).expect("save");
}
