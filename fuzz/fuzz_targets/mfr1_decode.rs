// cargo-fuzz target `mfr1_decode`; the logic is in `entries/mfr1.rs`, shared with the stable
// corpus replay test. `fuzz_target!` expands to a `#[no_mangle]` export, so the crate cannot
// carry the workspace's crate-level `forbid(unsafe_code)`; the entry module still does.
// PENDING: a no-op until its feature gate is turned on (see the entry's module docs).
#![no_main]

#[forbid(unsafe_code)]
#[path = "../entries/mfr1.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::run(data));
