//! Fuzz entry `vsphere_inventory_json`: `[model selector, body…]` for the vCenter
//! `/api/vcenter/{datacenter,cluster,host,vm}` list bodies and the VM / guest / power detail
//! bodies (8 MiB cap) (ADR-0015 §1–2). Shared by `fuzz/fuzz_targets/vsphere_inventory_json.rs`
//! and the stable replay in `crates/mooring-vsphere/tests/fuzz_corpus.rs`.

/// Never panics. The crate entry asserts the caps: list lengths ≤ the model's maximum, every
/// VM id a valid managed-object id and every name within `MAX_NAME`.
pub fn run(data: &[u8]) {
    mooring_vsphere::fuzz::fuzz_inventory_json(data);
}
