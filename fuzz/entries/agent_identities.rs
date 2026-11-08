//! Fuzz entry `agent_identities`: ssh-agent replies (identities answer, sign response) and `sk-*` signatures (ADR-0024 §2,
//! ADR-0027 PIV through the agent). Shared by
//! `fuzz/fuzz_targets/agent_identities.rs` and the stable replay in
//! `crates/mooring-proto-ssh/tests/fuzz_corpus.rs`.

/// Never panics. At most 64 identities are kept, blobs and signatures are capped.
pub fn run(data: &[u8]) {
    mooring_proto_ssh::fuzz_agent_identities(data);
}
