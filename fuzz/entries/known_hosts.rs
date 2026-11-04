//! Fuzz entry `known_hosts_parse`: hostile `known_hosts` bytes (ADR-0007 §Tests).
//! Shared by `fuzz/fuzz_targets/known_hosts_parse.rs` and the stable corpus replay in
//! `crates/mooring-proto-ssh/tests/fuzz_corpus.rs`.

use mooring_proto_ssh::known_hosts::KnownHosts;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::PrivateKey;

/// Hosts probed against every parsed store (fake names / RFC 5737 / RFC 3849 only).
const PROBES: &[(&str, u16)] =
    &[("example.test", 22), ("h.example.test", 2222), ("192.0.2.10", 22), ("2001:db8::1", 22)];

/// Never panics; the written form re-parses to the same trust decisions.
pub fn run(data: &[u8]) {
    let store = KnownHosts::parse_bytes(data);
    let written = store.to_file_string();
    let again = KnownHosts::parse_bytes(written.as_bytes());
    assert_eq!(store.len(), again.len(), "entry count changed across write + parse");
    // Byte fixed point (QA-F1 fixed: all trailing CRs are stripped on parse).
    assert_eq!(written, again.to_file_string(), "written form is not a fixed point");

    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32])).public_key().clone();
    for &(host, port) in PROBES {
        assert_eq!(
            store.check(host, port, &key),
            again.check(host, port, &key),
            "trust decision changed across write + parse"
        );
    }
}
