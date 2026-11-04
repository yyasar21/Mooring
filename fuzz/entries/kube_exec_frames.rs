//! Fuzz entry `kube_exec_frames`: one server → client exec WebSocket message (channel byte +
//! payload; channel 3 carries a `metav1.Status` document) (ADR-0014 §5). Shared by
//! `fuzz/fuzz_targets/kube_exec_frames.rs` and the stable replay in
//! `crates/mooring-proto-kube/tests/fuzz_corpus.rs`.

use mooring_proto_kube::{decode_exec, ExecFrame, ExecStatus, FrameError};

/// Never panics. An empty message is `Empty`; stdout / stderr borrow the payload unchanged; a
/// status over 64 KiB is `Malformed`; a failure reason is clean text ≤ 256 chars (the crate
/// entry asserts that); decoding is deterministic.
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::fuzz_exec_frame(data);
    let first = decode_exec(data);
    assert_eq!(first, decode_exec(data), "decode_exec is not deterministic");
    match (data.split_first(), first) {
        (None, r) => assert_eq!(r, Err(FrameError::Empty)),
        (Some((1, rest)), Ok(ExecFrame::Stdout(p)))
        | (Some((2, rest)), Ok(ExecFrame::Stderr(p))) => {
            assert_eq!(p, rest, "payload was copied or trimmed");
        }
        (Some((3, rest)), r) => {
            if rest.len() > 64 * 1024 {
                assert_eq!(r, Err(FrameError::Malformed), "oversized status was parsed");
            }
            if let Ok(ExecFrame::Status(ExecStatus::Failure(s))) = r {
                assert!(s.chars().count() <= 256);
            }
        }
        (Some((255, rest)), r) => assert_eq!(r.is_ok(), rest.len() == 1),
        (Some((1 | 2, _)), _) => panic!("stdout / stderr message refused"),
        (Some(_), r) => assert!(matches!(r, Err(FrameError::Channel)), "unknown channel accepted"),
    }
}
