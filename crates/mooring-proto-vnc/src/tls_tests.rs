//! The ADR-0011 decision table through the real rustls verifier, with rcgen certificates.

use super::*;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};

const HOST: &str = "vnc.example.test";
const PORT: u16 = 5900;

fn self_signed() -> CertificateDer<'static> {
    rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).expect("rcgen").cert.der().clone()
}

fn ca_and_leaf(name: &str) -> (String, CertificateDer<'static>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("key")).expect("ca");
    let leaf_key = KeyPair::generate().expect("key");
    let mut leaf_params = CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
    // rcgen gives every certificate the same default DN; a distinct subject keeps the
    // "issuer == subject" self-signed heuristic meaningful.
    leaf_params.distinguished_name.push(DnType::CommonName, name);
    let leaf = leaf_params.signed_by(&leaf_key, &ca).expect("leaf");
    (ca.pem(), leaf.der().clone())
}

fn verify(
    known: KnownCerts,
    ca_pem: Option<&str>,
    leaf: &CertificateDer<'_>,
    name: &str,
) -> (bool, TrustOutcome) {
    let roots = root_store(ca_pem, false).expect("roots");
    let v = TofuVerifier::new(known, HOST, PORT, roots);
    let sn = ServerName::try_from(name.to_owned()).expect("name");
    let ok = v.verify_server_cert(leaf, &[], &sn, &[], UnixTime::now()).is_ok();
    (ok, v.outcome().expect("outcome recorded"))
}

fn pinned(der: &[u8]) -> KnownCerts {
    let mut k = KnownCerts::new();
    k.add(HOST, PORT, &fingerprint(der), OffsetDateTime::now_utc());
    k
}

#[test]
fn row_no_pin_invalid_chain_prompts() {
    let leaf = self_signed();
    let (ok, out) = verify(KnownCerts::new(), None, &leaf, HOST);
    assert!(!ok);
    let TrustOutcome::Unknown { fp, info } = out else { panic!("{out:?}") };
    assert_eq!(fp, fingerprint(&leaf));
    assert_eq!(info.sha256, mooring_core::known_certs::hex(&fp));
    assert!(info.is_self_signed());
    assert!(info.problems.contains(&CertProblem::UnknownIssuer));
    assert!(!info.problems.contains(&CertProblem::NameMismatch));
    assert_eq!(info.san, vec![HOST.to_owned()]);
}

#[test]
fn row_pin_matches_accepts_even_with_invalid_chain() {
    let leaf = self_signed();
    let (ok, out) = verify(pinned(&leaf), None, &leaf, HOST);
    assert!(ok);
    assert_eq!(out, TrustOutcome::Pinned { fp: fingerprint(&leaf), chain_valid: false });
}

#[test]
fn row_pin_differs_is_mismatch_even_with_valid_chain() {
    let (ca, leaf) = ca_and_leaf(HOST);
    let other = self_signed();
    let (ok, out) = verify(pinned(&other), Some(&ca), &leaf, HOST);
    assert!(!ok);
    assert_eq!(
        out,
        TrustOutcome::Mismatch { expected: fingerprint(&other), presented: fingerprint(&leaf) }
    );
}

#[test]
fn row_no_pin_valid_chain_accepts_ca() {
    let (ca, leaf) = ca_and_leaf(HOST);
    let (ok, out) = verify(KnownCerts::new(), Some(&ca), &leaf, HOST);
    assert!(ok);
    assert_eq!(out, TrustOutcome::CaValid { fp: fingerprint(&leaf) });
    assert_eq!(out.presented(), fingerprint(&leaf));
}

#[test]
fn name_mismatch_is_a_problem_and_prompts() {
    let (ca, leaf) = ca_and_leaf("other.example.test");
    let (ok, out) = verify(KnownCerts::new(), Some(&ca), &leaf, HOST);
    assert!(!ok);
    let TrustOutcome::Unknown { info, .. } = out else { panic!("{out:?}") };
    assert!(info.problems.contains(&CertProblem::NameMismatch), "{:?}", info.problems);
    assert!(!info.is_self_signed());
}

#[test]
fn ip_server_names_and_bad_pem() {
    assert!(server_name("192.0.2.10").is_ok());
    assert!(server_name("[2001:db8::1]").is_ok());
    assert!(server_name(HOST).is_ok());
    assert!(root_store(
        Some("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"),
        false
    )
    .is_err());
    assert!(root_store(None, false).expect("empty").is_empty());
    assert_eq!(ip_text(&[192, 0, 2, 1]), "192.0.2.1");
    assert_eq!(ip_text(&[1, 2, 3]), "(invalid IP)");
}

#[test]
fn unparsable_leaf_still_gets_a_fingerprint() {
    let info = certificate_info(b"garbage", vec![], true, OffsetDateTime::now_utc());
    assert_eq!(info.sha256, mooring_core::known_certs::hex(&fingerprint(b"garbage")));
    assert_eq!(info.subject, "(unparsable certificate)");
}

#[test]
fn chain_problem_mapping() {
    use rustls::Error::InvalidCertificate as I;
    assert_eq!(chain_problems(&I(CertificateError::Expired)), vec![CertProblem::Expired]);
    assert_eq!(chain_problems(&I(CertificateError::NotValidYet)), vec![CertProblem::NotYetValid]);
    assert_eq!(
        chain_problems(&I(CertificateError::NotValidForName)),
        vec![CertProblem::NameMismatch]
    );
    assert_eq!(
        chain_problems(&I(CertificateError::BadSignature)),
        vec![CertProblem::UnknownIssuer]
    );
    assert_eq!(chain_problems(&rustls::Error::DecryptError), vec![CertProblem::UnknownIssuer]);
}
