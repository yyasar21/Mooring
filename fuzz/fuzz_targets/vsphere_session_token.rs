// cargo-fuzz target `vsphere_session_token`; the logic is in `entries/vsphere_session_token.rs`, shared with the stable
// corpus replay. PENDING: a no-op until the `v1` feature gate is enabled (docs/qa/fuzzing.md).
// `fuzz_target!` expands to a `#[no_mangle]` export, so the crate cannot carry the workspace's
// crate-level `forbid(unsafe_code)`; the entry module still does.
#![no_main]

#[forbid(unsafe_code)]
#[path = "../entries/vsphere_session_token.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::run(data));
