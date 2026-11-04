//! Fuzz entry `http_response_headers`: `[selector, value…]` for `Content-Length`,
//! `Retry-After` and `Location` from an API server (ADR-0014 §4, ADR-0015 §1). Shared by
//! `fuzz/fuzz_targets/http_response_headers.rs` and the stable replay in
//! `crates/mooring-http/tests/fuzz_corpus.rs`.

/// Never panics; a redirect that leaves the origin is never followed (the crate entry).
pub fn run(data: &[u8]) {
    mooring_http::fuzz::fuzz_response_headers(data);
}
