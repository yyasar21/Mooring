//! Fuzz entry `http_certificate_info`: a hostile leaf certificate DER from a TLS server, as
//! shown in the trust prompt (ADR-0011 §Trust, ADR-0014 §3). Shared by
//! `fuzz/fuzz_targets/http_certificate_info.rs` and the stable replay in
//! `crates/mooring-http/tests/fuzz_corpus.rs`.

/// Never panics (the crate entry); a DER over `MAX_CERT_DER` is refused.
pub fn run(data: &[u8]) {
    mooring_http::fuzz::fuzz_certificate_info(data);
}
