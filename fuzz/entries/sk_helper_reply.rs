//! Fuzz entry `sk_helper_reply`: `ssh-sk-helper` stdout (ADR-0024 §3, R-SK-HELPER). Shared by
//! `fuzz/fuzz_targets/sk_helper_reply.rs` and the stable replay in
//! `crates/mooring-proto-ssh/tests/fuzz_corpus.rs`.

/// Never panics. The frame length must equal the rest; another protocol version is refused.
pub fn run(data: &[u8]) {
    mooring_proto_ssh::fuzz_sk_helper_reply(data);
}
