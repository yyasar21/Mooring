//! Fuzz entry `rdg_http_response`: The RD Gateway upgrade response head, its body length and `WWW-Authenticate` challenges
//! (NTLM token base64) (ADR-0027 §1). Shared by
//! `fuzz/fuzz_targets/rdg_http_response.rs` and the stable replay in
//! `crates/mooring-proto-rdp/tests/fuzz_corpus.rs`.

/// Never panics; the head, header count and token are capped.
pub fn run(data: &[u8]) {
    mooring_proto_rdp::gateway::fuzz_rdg_http_response(data);
}
