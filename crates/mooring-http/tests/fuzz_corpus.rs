//! Stable replay of the HTTP fuzz corpora (`http_certificate_info`, `http_response_headers`,
//! `http_json_body`) and crash regressions through the same entry points the cargo-fuzz
//! targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/http_certificate_info.rs"]
mod http_certificate_info;
#[path = "../../../fuzz/entries/http_json_body.rs"]
mod http_json_body;
#[path = "../../../fuzz/entries/http_response_headers.rs"]
mod http_response_headers;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

use mooring_core::known_certs::CertProblem;
use mooring_http::{certificate_info, decode_json};
use time::OffsetDateTime;

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn http_certificate_info_corpus() {
    assert!(replay::replay("http_certificate_info", http_certificate_info::run) >= 2);
}

/// The DER seed must keep parsing as a certificate, or the fuzzer only sees garbage.
#[test]
fn certificate_seed_is_a_certificate() {
    let der = seed("http_certificate_info", "ec-self-signed");
    let info = certificate_info(&der, vec![CertProblem::UnknownIssuer], OffsetDateTime::UNIX_EPOCH);
    assert!(info.subject.contains("k.example.test"), "{}", info.subject);
    assert_eq!(info.sha256.len(), 64);
}

#[test]
fn http_response_headers_corpus() {
    assert!(replay::replay("http_response_headers", http_response_headers::run) >= 4);
}

#[test]
fn http_json_body_corpus() {
    assert!(replay::replay("http_json_body", http_json_body::run) >= 2);
}

/// Deep nesting is a decode error, never a stack overflow (serde_json's recursion limit).
#[test]
fn deep_nesting_seed_is_refused() {
    let deep = seed("http_json_body", "deep-nesting");
    assert!(decode_json::<serde_json::Value>(&deep).is_err());
    let deeper = "[".repeat(100_000);
    assert!(decode_json::<serde_json::Value>(deeper.as_bytes()).is_err());
}
