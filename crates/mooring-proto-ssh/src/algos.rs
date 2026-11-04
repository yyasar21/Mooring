//! Algorithm policy (ADR-0007 §Algorithms) mapped onto russh 0.65 names.
//!
//! Only what the ADR allows is offered. Differences from the ADR text, all forced by or
//! available in russh 0.65:
//! * `mlkem768x25519-sha256` (post-quantum hybrid) is offered first: the ADR allows PQ hybrids
//!   "when russh exposes them", and 0.65 does. `sntrup761x25519` is not implemented by russh.
//! * `ext-info-c` and `kex-strict-c-v00@openssh.com` are protocol extension markers, not key
//!   exchanges; they are required for `server-sig-algs` (RSA SHA-2 auth) and the Terrapin
//!   (CVE-2023-48795) countermeasure.
//! * `diffie-hellman-group-exchange-sha256` is not in the ADR list and is not offered.
//! * Compression is `none` only (no compression oracle surface); the ADR does not name it.
//! * No host-key certificate algorithms are advertised: CA trust is not in A1.

use std::borrow::Cow;
use std::time::Duration;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{cipher, compression, kex, mac, Preferred, SshId};

/// Identification string sent to the server.
pub const CLIENT_ID: &str = concat!("SSH-2.0-Mooring_", env!("CARGO_PKG_VERSION"));

/// Key exchange, most preferred first.
pub const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_G16_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// Host key algorithms (and the RSA signature hashes we accept).
pub const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
    Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
    Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
];

/// Ciphers.
pub const CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_128_CTR,
];

/// MACs (only used with the CTR ciphers; AEAD ciphers ignore them).
pub const MACS: &[mac::Name] =
    &[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM, mac::HMAC_SHA512, mac::HMAC_SHA256];

/// The restricted preference lists.
pub fn preferred() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(KEX),
        key: Cow::Borrowed(HOST_KEYS),
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Borrowed(CIPHERS),
        mac: Cow::Borrowed(MACS),
        compression: Cow::Borrowed(&[compression::NONE]),
    }
}

/// russh client configuration for one connection.
pub fn client_config(keepalive: Option<Duration>, keepalive_max: usize) -> russh::client::Config {
    russh::client::Config {
        client_id: SshId::Standard(Cow::Borrowed(CLIENT_ID)),
        preferred: preferred(),
        keepalive_interval: keepalive,
        keepalive_max,
        nodelay: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        let mut out: Vec<String> = KEX.iter().map(|n| n.as_ref().to_owned()).collect();
        out.extend(HOST_KEYS.iter().map(ToString::to_string));
        out.extend(CIPHERS.iter().map(|n| n.as_ref().to_owned()));
        out.extend(MACS.iter().map(|n| n.as_ref().to_owned()));
        out
    }

    #[test]
    fn no_forbidden_algorithm_is_offered() {
        for name in names() {
            let n = name.as_str();
            assert!(!n.contains("sha1"), "{n}");
            assert!(!n.contains("cbc"), "{n}");
            assert!(!n.contains("3des"), "{n}");
            assert!(!n.contains("arcfour"), "{n}");
            assert!(!n.contains("md5"), "{n}");
            assert!(!n.contains("group1-"), "{n}");
            assert!(!n.contains("group-exchange"), "{n}");
            assert_ne!(n, "ssh-rsa", "SHA-1 RSA host keys are forbidden");
            assert_ne!(n, "ssh-dss");
            assert_ne!(n, "none");
        }
    }

    /// Review 5 N-35: compression is `none` only, so russh's zlib path (the `flate2` feature,
    /// now dropped from the workspace manifest) can never be negotiated.
    #[test]
    fn compression_is_none_only() {
        let p = preferred();
        assert_eq!(p.compression.as_ref(), &[compression::NONE]);
        assert_eq!(client_config(None, 3).preferred.compression.as_ref(), &[compression::NONE]);
    }

    #[test]
    fn adr_algorithms_are_all_offered() {
        let all = names();
        for want in [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group14-sha256",
            "ssh-ed25519",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes128-ctr",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256",
        ] {
            assert!(all.iter().any(|n| n == want), "missing {want}");
        }
        assert!(all.iter().any(|n| n.starts_with("ecdsa-sha2-nistp")));
    }

    #[test]
    fn client_config_uses_policy_and_mooring_id() {
        let cfg = client_config(Some(Duration::from_secs(30)), 3);
        assert_eq!(cfg.preferred.cipher.len(), CIPHERS.len());
        assert_eq!(cfg.keepalive_interval, Some(Duration::from_secs(30)));
        assert_eq!(cfg.keepalive_max, 3);
        assert!(CLIENT_ID.starts_with("SSH-2.0-Mooring_"));
    }
}
