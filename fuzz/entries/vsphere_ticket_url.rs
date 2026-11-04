//! Fuzz entry `vsphere_ticket_url`: VMRC console ticket response against a fixed vCenter host
//! and VM (ADR-0015 §4). Shared by `fuzz/fuzz_targets/vsphere_ticket_url.rs` and the stable
//! replay in `crates/mooring-vsphere/tests/fuzz_corpus.rs`.

/// Never panics. An accepted ticket is a `vmrc:` URL ≤ 2 KiB (the crate entry asserts that);
/// nothing else is ever opened.
pub fn run(data: &[u8]) {
    mooring_vsphere::fuzz::fuzz_ticket_url(data);
}
