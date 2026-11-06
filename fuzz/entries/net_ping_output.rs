//! Fuzz entry `net_ping_output`: `ping` stdout + stderr of any OS and locale (ADR-0020 §3). Shared by
//! `fuzz/fuzz_targets/net_ping_output.rs` and the stable replay in
//! `crates/mooring-net/tests/fuzz_corpus.rs`.

/// Never panics; the caps hold and no control or format character survives in any line
/// (asserted inside the crate entry).
pub fn run(data: &[u8]) {
    mooring_net::fuzz::fuzz_ping_output(data);
}
