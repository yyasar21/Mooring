//! Fuzz entry `sk_key_parse`: `sk-*` public lines / blobs / certificates and `id_*_sk` key-handle files (ADR-0024 §1). Shared by
//! `fuzz/fuzz_targets/sk_key_parse.rs` and the stable replay in
//! `crates/mooring-core/tests/fuzz_corpus.rs`.

/// Never panics; every parser of the module runs on the same bytes.
pub fn run(data: &[u8]) {
    mooring_core::credential::fuzz_sk_key_parse(data);
}
