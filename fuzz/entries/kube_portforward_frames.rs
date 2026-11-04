//! Fuzz entry `kube_portforward_frames`: a sequence of port-forward WebSocket messages
//! `[port lo, port hi, (len, bytes)*]` through `PfDecoder` (ADR-0014 §5). Shared by
//! `fuzz/fuzz_targets/kube_portforward_frames.rs` and the stable replay in
//! `crates/mooring-proto-kube/tests/fuzz_corpus.rs`.

use mooring_proto_kube::{FrameError, PfDecoder, PfEvent};

/// Never panics. Data events borrow the payload (shorter than the message); error text is
/// clean and ≤ 256 chars (the crate entry asserts both); an empty message is `Empty`, a
/// message on channel ≥ 2 is refused.
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::fuzz_portforward_frame(data);
    let [lo, hi, rest @ ..] = data else { return };
    let port = u16::from_le_bytes([*lo, *hi]);
    let mut dec = PfDecoder::new(port);
    let mut rest: &[u8] = rest;
    while let [len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (msg, next) = tail.split_at(n);
        let r = dec.feed(msg);
        match msg {
            [] => assert_eq!(r, Err(FrameError::Empty)),
            [ch, ..] if *ch > 1 => assert_eq!(r, Err(FrameError::Channel)),
            _ => {
                if let Ok(PfEvent::Error(e)) = &r {
                    assert!(e.chars().count() <= 256);
                }
            }
        }
        rest = next;
    }
}
