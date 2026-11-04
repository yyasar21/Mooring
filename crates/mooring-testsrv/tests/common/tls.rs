//! Test-only rustls client verifier: accepts any chain but still checks handshake signatures
//! (ring), and records the leaf so the test can compare it with the server's pin.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
pub struct RecordingVerifier {
    provider: Arc<CryptoProvider>,
    pub leaf: Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.leaf.lock().expect("leaf lock") = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config plus the verifier that records the presented leaf.
pub fn client_config() -> (Arc<ClientConfig>, Arc<RecordingVerifier>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        Arc::new(RecordingVerifier { provider: Arc::clone(&provider), leaf: Mutex::new(None) });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    (Arc::new(config), verifier)
}
