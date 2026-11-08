//! Stable replay of the `known_hosts_parse`, `socks5_handshake`, `agent_identities` and
//! `sk_helper_reply` fuzz corpora and crash regressions through the same entry points the
//! cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/agent_identities.rs"]
mod agent_identities;
#[path = "../../../fuzz/entries/known_hosts.rs"]
mod known_hosts;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/sk_helper_reply.rs"]
mod sk_helper_reply;
#[path = "../../../fuzz/entries/socks5.rs"]
mod socks5;

#[test]
fn known_hosts_parse_corpus() {
    assert!(replay::replay("known_hosts_parse", known_hosts::run) >= 8);
}

/// The plain and hashed seeds must keep parsing to one entry each, or the fuzzer starts from
/// nothing but the reject paths.
#[test]
fn known_hosts_seeds_have_entries() {
    let dir = replay::fuzz_dir().join("corpus/known_hosts_parse");
    for name in ["plain", "hashed", "bracketed-port"] {
        let seed = std::fs::read(dir.join(name)).expect("read seed");
        let store = mooring_proto_ssh::KnownHosts::parse_bytes(&seed);
        assert_eq!(store.len(), 1, "seed {name}");
    }
}

#[test]
fn socks5_handshake_corpus() {
    assert!(replay::replay("socks5_handshake", socks5::run) >= 8);
}

#[test]
fn agent_identities_corpus() {
    assert!(replay::replay("agent_identities", agent_identities::run) >= 8);
}

#[test]
fn sk_helper_reply_corpus() {
    assert!(replay::replay("sk_helper_reply", sk_helper_reply::run) >= 4);
}

/// The identities seed names the same `sk-ssh-ed25519` blob as the `sk_key_parse` blob seed, so
/// the agent path and the key parser start from one key (the wire parsers are crate-private;
/// their accept paths are covered by `sk_keys.rs` with the fake agent).
#[test]
fn agent_seed_carries_the_sk_blob() {
    let dir = replay::fuzz_dir().join("corpus");
    let answer = std::fs::read(dir.join("agent_identities/identities-answer")).expect("seed");
    let blob = std::fs::read(dir.join("sk_key_parse/ed25519-sk-blob")).expect("seed");
    assert_eq!(answer[0], 12, "SSH_AGENT_IDENTITIES_ANSWER");
    assert_eq!(&answer[1..5], &2u32.to_be_bytes());
    assert_eq!(&answer[9..9 + blob.len()], &blob[..]);
    mooring_core::credential::sk_key::parse_sk_public_blob(&blob).expect("blob parses");
}
