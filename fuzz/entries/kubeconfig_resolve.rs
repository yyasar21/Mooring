//! Fuzz entry `kubeconfig_resolve`: pasted / imported kubeconfig resolved to one context
//! (ADR-0014 §3). Shared by `fuzz/fuzz_targets/kubeconfig_resolve.rs` and the stable corpus
//! replay in `crates/mooring-core/tests/fuzz_corpus.rs`.

use mooring_core::credential::fingerprint::x509_pem;
use mooring_core::credential::kubeconfig::{self, CaSource, KubeAuth, MAX_CA_PEM, MAX_TOKEN};
use secrecy::ExposeSecret as _;

/// Never panics. An accepted context passed `parse` (so none of the forbidden keys), has an
/// `https` server, a certificate-only CA (≤ 64 KiB) or none, a visible-ASCII token ≤ 16 KiB
/// or a certificate pair, a DNS-label namespace, and resolves the same way twice.
pub fn run(data: &[u8]) {
    let first = kubeconfig::resolve(data, None);
    let again = kubeconfig::resolve(data, None);
    assert_eq!(first.is_ok(), again.is_ok(), "resolve is not deterministic");
    let Ok(r) = first else { return };
    assert!(kubeconfig::parse(data).is_ok(), "resolve accepted what parse refuses");
    assert!(r.server.as_str().starts_with("https://"), "server is not https");
    assert!(!r.context_name.is_empty() && r.context_name.len() <= kubeconfig::MAX_CONTEXT_NAME);
    match &r.ca {
        CaSource::Pem(pem) => {
            assert!(pem.len() <= MAX_CA_PEM, "CA PEM over the cap");
            assert!(!r.insecure_skip, "CA data together with insecure-skip-tls-verify");
            let text = std::str::from_utf8(pem).expect("CA PEM is text");
            assert!(x509_pem(text).is_ok(), "CA PEM is not a certificate");
        }
        CaSource::None => {}
    }
    match &r.auth {
        KubeAuth::Token(t) => {
            let t = t.expose_secret();
            assert!(!t.is_empty() && t.len() <= MAX_TOKEN, "token outside 1..=16 KiB");
            assert!(t.bytes().all(|b| b.is_ascii_graphic()), "token is not visible ASCII");
        }
        KubeAuth::ClientCert { cert_pem, key_pem } => {
            assert!(x509_pem(cert_pem).is_ok(), "client cert is not a certificate");
            assert!(key_pem.expose_secret().contains("PRIVATE KEY"), "key is not a key PEM");
        }
    }
    if let Some(ns) = &r.namespace {
        assert!(kubeconfig::is_dns_label(ns), "namespace is not a DNS label");
    }
    if let Some(sni) = &r.tls_server_name {
        assert!(kubeconfig::is_dns_subdomain(sni), "tls-server-name is not a DNS name");
    }
    // The named context must resolve to the same thing as the default one.
    let named = kubeconfig::resolve(data, Some(&r.context_name)).expect("named context resolves");
    assert_eq!(named.server, r.server);
    assert_eq!(named.auth.kind(), r.auth.kind());
}
