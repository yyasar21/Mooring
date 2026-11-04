// cargo-fuzz target `http_response_headers`; the logic is in `entries/http_response_headers.rs`, shared with the
// stable corpus replay test. `fuzz_target!` expands to a `#[no_mangle]` export, so the crate
// cannot carry the workspace's crate-level `forbid(unsafe_code)`; the entry module still does.
#![no_main]

#[forbid(unsafe_code)]
#[path = "../entries/http_response_headers.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::run(data));
