// cargo-fuzz target `agent_identities`; the logic is in `entries/agent_identities.rs`, shared with the stable
// corpus replay.
// `fuzz_target!` expands to a `#[no_mangle]` export, so the crate cannot carry the workspace's
// crate-level `forbid(unsafe_code)`; the entry module still does.
#![no_main]

#[forbid(unsafe_code)]
#[path = "../entries/agent_identities.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::run(data));
