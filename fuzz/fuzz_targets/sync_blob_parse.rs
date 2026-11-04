// cargo-fuzz target `sync_blob_parse`; the logic is in `entries/sync_blob_parse.rs`, shared with the stable
// corpus replay. PENDING: a no-op until the `s1` feature gate is enabled (docs/qa/fuzzing.md).
// `fuzz_target!` expands to a `#[no_mangle]` export, so the crate cannot carry the workspace's
// crate-level `forbid(unsafe_code)`; the entry module still does.
#![no_main]

#[forbid(unsafe_code)]
#[path = "../entries/sync_blob_parse.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::run(data));
