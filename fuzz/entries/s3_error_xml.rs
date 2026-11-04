//! Fuzz entry `s3_error_xml`: S3 error / `ListObjectsV2` XML from the backend (ADR-0017 §4).
//! Shared by `fuzz/fuzz_targets/s3_error_xml.rs` and, once a parser exists, a stable corpus
//! replay in `crates/mooring-sync/tests/fuzz_corpus.rs`.
//!
//! PENDING(S1): `mooring-sync` parses no XML at all. `S3Backend` uses `rusty-s3` presigned
//! `PUT` / `GET` / `HEAD` / `DELETE` only, maps errors from the status code and the `ETag`
//! header, and never lists the bucket (`history/` is addressed by counter). The target stays
//! a gated no-op until a listing or error-body parser lands (Q2 handoff, "Decision needed").

/// Never panics. With a parser: bounded allocation; code and message length-capped; entity
/// expansion refused.
#[cfg(feature = "s1")]
pub fn run(data: &[u8]) {
    mooring_sync::fuzz::fuzz_s3_error_xml(data);
}

/// Stub until a parser exists (see the module docs).
#[cfg(not(feature = "s1"))]
pub fn run(data: &[u8]) {
    let _ = data;
}
