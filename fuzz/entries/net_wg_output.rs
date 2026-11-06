//! Fuzz entry `net_wg_output`: `wg show` output, first byte = query selector (ADR-0020 §4). Shared by
//! `fuzz/fuzz_targets/net_wg_output.rs` and the stable replay in
//! `crates/mooring-net/tests/fuzz_corpus.rs`.

/// Never panics; the caps hold and no control or format character survives in any line
/// (asserted inside the crate entry).
pub fn run(data: &[u8]) {
    mooring_net::fuzz::fuzz_wg_output(data);
}
