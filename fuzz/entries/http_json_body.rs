//! Fuzz entry `http_json_body`: a capped response body through `decode_json` (ADR-0014 §4).
//! Shared by `fuzz/fuzz_targets/http_json_body.rs` and the stable replay in
//! `crates/mooring-http/tests/fuzz_corpus.rs`.

/// Never panics; deep nesting is a decode error, not a stack overflow.
pub fn run(data: &[u8]) {
    mooring_http::fuzz::fuzz_json_body(data);
}
