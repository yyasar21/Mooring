//! Verifier decision table (ADR-0011, 4 rows + pin-over-CA) and real loopback handshakes that
//! prove handshake signatures are still enforced when a pin accepts the chain.

use std::sync::Arc;

use mooring_core::known_certs::{fingerprint, CertProblem, CertVerdict, KnownCerts};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::test_certs::{ca, self_signed, signed_by};

const HOST: &str = "rdp.example.test";
const PORT: u16 = 3389;

fn verifier(known: KnownCerts, ca_pem: Option<&str>) -> (TofuVerifier, DecisionSlot) {
    let slot = DecisionSlot::default();
    let roots = root_store(&[], ca_pem);
    (TofuVerifier::new(HOST, PORT, known, roots, Arc::clone(&slot)), slot)
}

fn pinned(der: &[u8]) -> KnownCerts {
    let mut k = KnownCerts::new();
    k.add(HOST, PORT, &fingerprint(der), OffsetDateTime::now_utc());
    k
}

fn verify(v: &TofuVerifier, der: &[u8]) -> Result<(), rustls::Error> {
    let name = server_name(HOST).expect("name");
    v.verify_server_cert(&CertificateDer::from(der.to_vec()), &[], &name, &[], UnixTime::now())
        .map(|_| ())
}

#[test]
fn unknown_self_signed_fails_and_asks() {
    let (der, _) = self_signed(&[HOST]);
    let (v, slot) = verifier(KnownCerts::new(), None);
    assert!(verify(&v, &der).is_err());
    let d = take_decision(&slot).expect("recorded");
    assert_eq!(d.verdict, CertVerdict::Prompt);
    assert_eq!(d.problems, vec![CertProblem::UnknownIssuer]);
    assert_eq!(d.der, der);
}

#[test]
fn pinned_is_accepted_even_without_a_chain() {
    let (der, _) = self_signed(&[HOST]);
    let (v, slot) = verifier(pinned(&der), None);
    verify(&v, &der).expect("pin accepts");
    assert_eq!(
        take_decision(&slot).expect("recorded").verdict,
        CertVerdict::AcceptPinned { chain_valid: false }
    );
}

#[test]
fn changed_certificate_is_a_hard_stop() {
    let (old, _) = self_signed(&[HOST]);
    let (new, _) = self_signed(&[HOST]);
    let (v, slot) = verifier(pinned(&old), None);
    assert!(verify(&v, &new).is_err());
    assert_eq!(
        take_decision(&slot).expect("recorded").verdict,
        CertVerdict::Mismatch { expected: fingerprint(&old) }
    );
}

#[test]
fn ca_valid_is_accepted_without_pin_and_pin_wins_over_ca() {
    let (ca_pem, issuer) = ca();
    let (leaf, _) = signed_by(&[HOST], &issuer);
    let (v, slot) = verifier(KnownCerts::new(), Some(&ca_pem));
    verify(&v, &leaf).expect("CA accepts");
    assert_eq!(take_decision(&slot).expect("recorded").verdict, CertVerdict::AcceptCa);

    // A CA-valid certificate that differs from a pin is still a mismatch.
    let (other, _) = self_signed(&[HOST]);
    let (v, slot) = verifier(pinned(&other), Some(&ca_pem));
    assert!(verify(&v, &leaf).is_err());
    assert!(matches!(take_decision(&slot).expect("rec").verdict, CertVerdict::Mismatch { .. }));
}

#[test]
fn ca_leaf_for_another_name_asks_with_name_mismatch() {
    let (ca_pem, issuer) = ca();
    let (leaf, _) = signed_by(&["other.example.test"], &issuer);
    let (v, slot) = verifier(KnownCerts::new(), Some(&ca_pem));
    assert!(verify(&v, &leaf).is_err());
    let d = take_decision(&slot).expect("recorded");
    assert_eq!(d.verdict, CertVerdict::Prompt);
    assert_eq!(d.problems, vec![CertProblem::NameMismatch]);
}

#[test]
fn signature_schemes_are_offered_and_server_names_parse() {
    let (v, _) = verifier(KnownCerts::new(), None);
    assert!(!v.supported_verify_schemes().is_empty());
    assert!(server_name("192.0.2.1").is_some());
    assert!(server_name("[2001:db8::1]").is_some());
    assert!(server_name("bad host").is_none());
}

/// Serves `cert` but signs the handshake with `key` (which may not belong to `cert`).
#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

async fn handshake(cert: Vec<u8>, key: &rcgen::KeyPair, known: KnownCerts) -> Result<(), String> {
    let p = provider();
    let signing = p
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
        .expect("key");
    let certified = Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert)], signing));
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&p))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let srv = tokio::spawn(async move {
        let (s, _) = listener.accept().await.expect("accept");
        let _ = acceptor.accept(s).await;
    });
    let (v, _) = verifier(known, None);
    let config = client_config(Arc::new(v)).expect("config");
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let name = server_name(HOST).expect("name");
    let out = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    srv.abort();
    out
}

#[tokio::test]
async fn loopback_pinned_handshake_succeeds() {
    let (der, key) = self_signed(&[HOST]);
    handshake(der.clone(), &key, pinned(&der)).await.expect("pinned handshake");
}

#[tokio::test]
async fn loopback_pin_does_not_bypass_the_signature_check() {
    // The server presents the pinned certificate but does not hold its private key.
    let (der, _) = self_signed(&[HOST]);
    let (_, wrong_key) = self_signed(&[HOST]);
    let err = handshake(der.clone(), &wrong_key, pinned(&der)).await.expect_err("must fail");
    // N-23: specifically the handshake signature, not an unrelated failure.
    assert!(err.contains("BadSignature") || err.contains("signature"), "{err}");
    assert!(!err.contains("UnknownIssuer"), "the pin was accepted: {err}");
}

#[tokio::test]
async fn loopback_unknown_certificate_fails_the_handshake() {
    let (der, key) = self_signed(&[HOST]);
    assert!(handshake(der, &key, KnownCerts::new()).await.is_err());
}
