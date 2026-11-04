//! Self-signed test certificates and rustls (ring) server configs shared by both servers.

use std::fmt;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};

/// A freshly generated self-signed certificate (ECDSA P-256) for loopback test servers.
///
/// The private key never leaves the process; it is test material only and is never written to
/// disk by this crate.
#[derive(Clone)]
pub struct TestCert {
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    public_key: Vec<u8>,
}

impl fmt::Debug for TestCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestCert").field("sha256", &self.sha256_hex()).finish_non_exhaustive()
    }
}

impl TestCert {
    /// Generates a self-signed certificate for `names` (default: `localhost`, `example.test`).
    pub fn generate(names: &[&str]) -> Result<Self, rcgen::Error> {
        let names: Vec<String> = if names.is_empty() {
            vec!["localhost".to_owned(), "example.test".to_owned()]
        } else {
            names.iter().map(|n| (*n).to_owned()).collect()
        };
        let ck = rcgen::generate_simple_self_signed(names)?;
        Ok(Self {
            cert_der: ck.cert.der().clone(),
            key_der: ck.signing_key.serialize_der(),
            public_key: ck.signing_key.public_key_raw().to_vec(),
        })
    }

    /// A leaf for `names` (non-empty) signed by a fresh test CA; returns the leaf and the CA
    /// certificate as PEM (a connection's `caPem`), for the CA-valid trust row (review 5 M-13).
    pub fn generate_ca_issued(names: &[&str]) -> Result<(Self, String), rcgen::Error> {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Mooring Test CA");
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;
        let key = KeyPair::generate()?;
        let sans: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        let mut params = CertificateParams::new(sans)?;
        params
            .distinguished_name
            .push(DnType::CommonName, names.first().copied().unwrap_or("leaf"));
        let leaf = params.signed_by(&key, &ca)?;
        let cert = Self {
            cert_der: leaf.der().clone(),
            key_der: key.serialize_der(),
            public_key: key.public_key_raw().to_vec(),
        };
        Ok((cert, ca.pem()))
    }

    /// DER of the leaf certificate (what a client pins).
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Raw `subjectPublicKey` bytes (the BIT STRING contents of the SPKI). CredSSP binds
    /// `pubKeyAuth` to exactly these bytes, so an RDP client passes them to `connect_finalize`.
    pub fn public_key_raw(&self) -> &[u8] {
        &self.public_key
    }

    /// SHA-256 of the leaf DER as lowercase hex (the `x509-sha256` pin of ADR-0011).
    pub fn sha256_hex(&self) -> String {
        let digest = Sha256::digest(self.cert_der.as_ref());
        digest.iter().fold(String::with_capacity(64), |mut s, b| {
            use fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// A rustls server config (ring provider, TLS 1.2 + 1.3) presenting this certificate.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, rustls::Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert_der.clone()], key)?;
        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::TestCert;

    #[test]
    fn generates_distinct_certs_with_valid_configs() {
        let a = TestCert::generate(&[]).expect("cert a");
        let b = TestCert::generate(&["example.test"]).expect("cert b");
        assert_ne!(a.sha256_hex(), b.sha256_hex());
        assert_eq!(a.sha256_hex().len(), 64);
        assert!(!a.public_key_raw().is_empty());
        a.server_config().expect("server config");
    }
}
