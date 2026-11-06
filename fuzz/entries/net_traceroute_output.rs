//! Fuzz entry `net_traceroute_output`: `traceroute` / `tracepath` / `tracert` output (ADR-0020 §3). Shared by
//! `fuzz/fuzz_targets/net_traceroute_output.rs` and the stable replay in
//! `crates/mooring-net/tests/fuzz_corpus.rs`.

/// Never panics; the caps hold and no control or format character survives in any line
/// (asserted inside the crate entry).
pub fn run(data: &[u8]) {
    mooring_net::fuzz::fuzz_traceroute_output(data);
}
