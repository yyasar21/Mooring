// cargo-fuzz target `ldap_filter_escape`; the logic is in `entries/ldap_filter_escape.rs`, shared with the stable
// corpus replay.
// `fuzz_target!` expands to a `#[no_mangle]` export, so the crate cannot carry the workspace's
// crate-level `forbid(unsafe_code)`; the entry module still does.
#![no_main]

#[forbid(unsafe_code)]
#[path = "../entries/ldap_filter_escape.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::run(data));
