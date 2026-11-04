//! Fuzz entry `kube_log_sanitize`: `pods/log` bytes from a container (ADR-0014 §5). Shared by
//! `fuzz/fuzz_targets/kube_log_sanitize.rs` and the stable replay in
//! `crates/mooring-proto-kube/tests/fuzz_corpus.rs`.

use mooring_proto_kube::sanitize_line;

/// Never panics. The output carries no control character other than `\t` / `\n`, no bidi
/// control and no ESC (the crate entry asserts that, whole and split in two); it never grows
/// past a lossy UTF-8 replacement per input byte and is deterministic.
pub fn run(data: &[u8]) {
    mooring_proto_kube::fuzz::fuzz_log_line(data);
    let out = sanitize_line(data);
    assert_eq!(out, sanitize_line(data), "sanitize_line is not deterministic");
    assert!(out.len() <= data.len() * 4 + 4, "sanitizer output grew unboundedly");
    assert!(!out.contains('\u{1b}') && !out.contains('\r'), "ESC or CR survived");
}
