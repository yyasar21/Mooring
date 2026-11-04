//! Fuzz entry `socks5_handshake`: hostile SOCKS5 CONNECT requests from a local application
//! (ADR-0010, dynamic forwarding). Shared by `fuzz/fuzz_targets/socks5_handshake.rs` and
//! `crates/mooring-proto-ssh/tests/fuzz_corpus.rs`.
//!
//! The async greeting / request state machine (`socks::handshake`) is `pub(crate)`, so this
//! drives the pure request parser it delegates to; the greeting framing is covered by the
//! crate's own tests (see docs/handoff/a1-exit-qa.md, "Decision needed").

use std::net::{Ipv4Addr, Ipv6Addr};

use mooring_proto_ssh::socks::{parse_request, SocksTarget};

/// `VER CMD RSV ATYP` + longest address (1 + 255) + port.
const MAX_REQUEST: usize = 4 + 1 + 255 + 2;

/// Encode a parsed target back to a CONNECT request (IP literals as IP address types).
fn encode(t: &SocksTarget) -> Vec<u8> {
    let mut v = vec![5, 1, 0];
    if let Ok(ip) = t.host.parse::<Ipv4Addr>() {
        v.push(1);
        v.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = t.host.parse::<Ipv6Addr>() {
        v.push(4);
        v.extend_from_slice(&ip.octets());
    } else {
        v.push(3);
        v.push(u8::try_from(t.host.len()).expect("parsed domain fits a SOCKS length byte"));
        v.extend_from_slice(t.host.as_bytes());
    }
    v.extend_from_slice(&t.port.to_be_bytes());
    v
}

/// Never panics; an accepted request is bounded, has a port and a printable host, and its
/// re-encoding parses to the same target (the parser is idempotent).
pub fn run(data: &[u8]) {
    let Ok(target) = parse_request(data) else {
        return;
    };
    assert!(data.len() <= MAX_REQUEST, "accepted an over-long request");
    assert_ne!(target.port, 0, "accepted port 0");
    assert!(!target.host.is_empty(), "accepted an empty host");
    assert!(target.host.bytes().all(|b| b.is_ascii_graphic()), "host is not printable ASCII");
    let again = parse_request(&encode(&target)).expect("re-encoded target parses");
    assert_eq!(target, again, "re-encoded target differs");
}
