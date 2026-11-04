//! TOFU prompt / pin / mismatch / CA-valid / name mismatch / anchored mode / fail-closed store
//! / handshake signatures, against an in-process TLS server.

mod common;

use common::*;
use mooring_core::known_certs::{fingerprint, CertProblem, CertTrust, KnownCerts};
use mooring_http::{Headers, HttpClient, HttpError, TrustVerdict};

#[derive(serde::Deserialize, Debug)]
struct Ok_ {
    ok: bool,
}

async fn get(c: &HttpClient) -> Result<Ok_, HttpError> {
    c.get_json::<Ok_>("/x", &Headers::new()).await
}

#[tokio::test]
async fn unknown_cert_prompts_then_trusted_once_then_pin() {
    let (s, der) = self_signed_server(ok_json()).await;
    let client = HttpClient::new(s.config()).expect("client");
    let err = get(&client).await.expect_err("prompt");
    let HttpError::TrustPrompt(d) = &err else { panic!("{err:?}") };
    assert_eq!(d.verdict, TrustVerdict::Prompt);
    assert_eq!(d.trust, CertTrust::Unknown);
    assert_eq!(d.fingerprint, fingerprint(&der));
    assert!(d.info.problems.contains(&CertProblem::SelfSigned), "{:?}", d.info.problems);
    assert!(d.info.problems.contains(&CertProblem::UnknownIssuer));
    assert_eq!(err.code(), "http.trust_prompt");
    assert_eq!(s.hits(), 0, "no request reached the server");

    // "Yes, once": accepted without writing a pin.
    let mut cfg = s.config();
    cfg.trusted_once = Some(fingerprint(&der));
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    cfg.trust_events = Some(tx);
    assert!(get(&HttpClient::new(cfg).expect("client")).await.expect("once").ok);
    let ev = rx.try_recv().expect("decision event");
    assert_eq!(ev.verdict, TrustVerdict::Pinned { chain_valid: false });
    assert!(KnownCerts::load(&s.known()).expect("load").is_empty(), "no pin written");

    // The Gate writes the pin; the *same* client reconnects and now succeeds.
    pin(&s, &der);
    assert!(get(&client).await.expect("pinned").ok);
}

#[tokio::test]
async fn changed_certificate_is_a_hard_stop_even_with_trusted_once() {
    let (s, der) = self_signed_server(ok_json()).await;
    let (other, _) = self_signed(&["127.0.0.1"]);
    pin(&s, &other);
    let mut cfg = s.config();
    cfg.trusted_once = Some(fingerprint(&der));
    let err = get(&HttpClient::new(cfg).expect("client")).await.expect_err("mismatch");
    let HttpError::TrustMismatch(d) = &err else { panic!("{err:?}") };
    assert_eq!(d.verdict, TrustVerdict::Mismatch { expected: fingerprint(&other) });
    assert_eq!(d.trust, CertTrust::Mismatch { expected: fingerprint(&other) });
}

#[tokio::test]
async fn ca_valid_is_accepted_and_reported() {
    let (ca_pem, issuer) = ca();
    let (leaf, key) = signed_by(&["127.0.0.1"], &issuer);
    let s = serve_tls(leaf, &key, ok_json()).await;
    let mut cfg = s.config();
    cfg.extra_ca_pem = Some(ca_pem);
    let c = HttpClient::new(cfg).expect("client");
    let r = c.request(http::Method::GET, "/x", &Headers::new(), None, 1024).await.expect("ok");
    let d = r.trust.expect("decision on the response");
    assert_eq!(d.verdict, TrustVerdict::CaValid);
    assert!(d.info.problems.is_empty(), "{:?}", d.info.problems);
}

#[tokio::test]
async fn ca_leaf_for_another_name_prompts_with_name_mismatch() {
    let (ca_pem, issuer) = ca();
    let (leaf, key) = signed_by(&["other.example.test"], &issuer);
    let s = serve_tls(leaf, &key, ok_json()).await;
    let mut cfg = s.config();
    cfg.extra_ca_pem = Some(ca_pem.clone());
    let err = get(&HttpClient::new(cfg).expect("client")).await.expect_err("name");
    let HttpError::TrustPrompt(d) = &err else { panic!("{err:?}") };
    assert_eq!(d.info.problems, vec![CertProblem::NameMismatch]);

    // The same server under tls_server_name = the certificate's name validates.
    let mut cfg = s.config();
    cfg.extra_ca_pem = Some(ca_pem);
    cfg.tls_server_name = Some("other.example.test".into());
    assert!(get(&HttpClient::new(cfg).expect("client")).await.expect("sni").ok);
}

#[tokio::test]
async fn anchored_mode_rejects_without_prompt_and_ignores_pins() {
    let (ca_pem, issuer) = ca();
    let (leaf, key) = signed_by(&["other.example.test"], &issuer);
    let s = serve_tls(leaf.clone(), &key, ok_json()).await;
    pin(&s, &leaf); // a pin never overrides an explicit anchor
    let mut cfg = s.config();
    cfg.extra_ca_pem = Some(ca_pem.clone());
    cfg.ca_exclusive = true;
    let err = get(&HttpClient::new(cfg).expect("client")).await.expect_err("rejected");
    assert!(matches!(&err, HttpError::TrustRejected(d) if d.verdict == TrustVerdict::Rejected));
    assert_eq!(err.code(), "http.trust_rejected");

    let (leaf, key) = signed_by(&["127.0.0.1"], &issuer);
    let s = serve_tls(leaf, &key, ok_json()).await;
    let (other, _) = self_signed(&["127.0.0.1"]);
    pin(&s, &other);
    let mut cfg = s.config();
    cfg.extra_ca_pem = Some(ca_pem);
    cfg.ca_exclusive = true;
    let c = HttpClient::new(cfg).expect("client");
    assert!(get(&c).await.expect("anchored valid, pin not consulted").ok);

    let mut cfg = s.config();
    cfg.ca_exclusive = true;
    assert!(matches!(HttpClient::new(cfg), Err(HttpError::InvalidConfig(_))));
}

#[tokio::test]
async fn unreadable_store_fails_closed() {
    let (s, der) = self_signed_server(ok_json()).await;
    std::fs::create_dir_all(s.known()).expect("dir in place of the file");
    let mut cfg = s.config();
    cfg.trusted_once = Some(fingerprint(&der));
    let err = get(&HttpClient::new(cfg).expect("client")).await.expect_err("closed");
    assert!(matches!(err, HttpError::TrustStore), "{err:?}");
}

#[tokio::test]
async fn a_pin_does_not_bypass_the_handshake_signature() {
    let (der, _) = self_signed(&["127.0.0.1"]);
    let (_, wrong_key) = self_signed(&["127.0.0.1"]);
    let s = serve_tls(der.clone(), &wrong_key, ok_json()).await;
    pin(&s, &der);
    let err = get(&HttpClient::new(s.config()).expect("client")).await.expect_err("sig");
    let HttpError::Tls(msg) = &err else { panic!("{err:?}") };
    assert!(msg.to_ascii_lowercase().contains("signature"), "{msg}");
}
