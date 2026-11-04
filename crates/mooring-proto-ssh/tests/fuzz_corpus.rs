//! Stable replay of the `known_hosts_parse` and `socks5_handshake` fuzz corpora and crash
//! regressions through the same entry points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/known_hosts.rs"]
mod known_hosts;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
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
