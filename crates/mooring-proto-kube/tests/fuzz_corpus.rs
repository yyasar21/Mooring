//! Stable replay of the Kubernetes fuzz corpora (`kube_exec_frames`, `kube_log_sanitize`,
//! `kube_portforward_frames`, `kube_guard_path`, `kube_pod_list_json`) and crash regressions through the same entry
//! points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/kube_exec_frames.rs"]
mod kube_exec_frames;
#[path = "../../../fuzz/entries/kube_guard_path.rs"]
mod kube_guard_path;
#[path = "../../../fuzz/entries/kube_log_sanitize.rs"]
mod kube_log_sanitize;
#[path = "../../../fuzz/entries/kube_pod_list_json.rs"]
mod kube_pod_list_json;
#[path = "../../../fuzz/entries/kube_portforward_frames.rs"]
mod kube_portforward_frames;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

use mooring_proto_kube::{decode_exec, sanitize_line, ExecFrame, ExecStatus, PfDecoder, PfEvent};

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn kube_exec_frames_corpus() {
    assert!(replay::replay("kube_exec_frames", kube_exec_frames::run) >= 4);
}

/// The status seeds must keep parsing, or the fuzzer only explores the refusal branch.
#[test]
fn exec_seeds_decode_to_their_status() {
    let s = seed("kube_exec_frames", "stdout-then-status");
    let status = s.iter().position(|b| *b == 3).expect("channel 3 in seed");
    assert_eq!(decode_exec(&s[status..]), Ok(ExecFrame::Status(ExecStatus::Exit(3))));
    let ok = seed("kube_exec_frames", "status-success");
    let status = ok.iter().position(|b| *b == 3).expect("channel 3 in seed");
    assert_eq!(decode_exec(&ok[status..]), Ok(ExecFrame::Status(ExecStatus::Success)));
    assert_eq!(decode_exec(&seed("kube_exec_frames", "close-stdout")), Ok(ExecFrame::Close(1)));
}

#[test]
fn kube_log_sanitize_corpus() {
    assert!(replay::replay("kube_log_sanitize", kube_log_sanitize::run) >= 1);
}

/// The seed carries an ESC sequence, a bidi override and a bell: none survives.
#[test]
fn log_seed_is_scrubbed() {
    let out = sanitize_line(&seed("kube_log_sanitize", "controls-and-bidi"));
    assert!(out.contains("line 1") && out.contains("red") && out.contains("evil"));
    assert!(!out.contains('\u{1b}') && !out.contains('\u{202e}') && !out.contains('\u{7}'));
}

#[test]
fn kube_portforward_frames_corpus() {
    assert!(replay::replay("kube_portforward_frames", kube_portforward_frames::run) >= 2);
}

/// The data seed must keep producing a data event, or the fuzzer never gets past the header.
#[test]
fn portforward_seed_reaches_data() {
    let s = seed("kube_portforward_frames", "data-and-error");
    let mut dec = PfDecoder::new(u16::from_le_bytes([s[0], s[1]]));
    assert_eq!(dec.feed(&[0, s[0], s[1]]), Ok(PfEvent::Header));
    assert_eq!(dec.feed(b"\x00hello"), Ok(PfEvent::Data(b"hello")));
}

#[test]
fn kube_guard_path_corpus() {
    assert!(replay::replay("kube_guard_path", kube_guard_path::run) >= 6);
}

#[test]
fn kube_pod_list_json_corpus() {
    assert!(replay::replay("kube_pod_list_json", kube_pod_list_json::run) >= 1);
}
