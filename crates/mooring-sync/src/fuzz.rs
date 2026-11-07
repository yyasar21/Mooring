//! Fuzz entries (ADR-0017 test plan: `sync_blob_parse`, `sync_snapshot_json`; ADR-0023:
//! `export_document_json`). They never panic on any input; QA wires them into `fuzz/`.

use uuid::Uuid;

use crate::blob::decode_msy1;
use crate::snapshot::Snapshot;

/// `MSY1` header parse; on success re-encodes the header and checks it is a prefix.
pub fn fuzz_msy1(data: &[u8]) {
    if let Ok(m) = decode_msy1(data) {
        assert_eq!(&m.header.to_bytes()[..], m.aad, "decoded header re-encodes to its AAD");
    }
}

/// Snapshot JSON decode + validation; on success the canonical encoding decodes again.
pub fn fuzz_snapshot_json(data: &[u8]) {
    let id = Uuid::from_u128(1);
    if let Ok(s) = Snapshot::decode(data, id) {
        let bytes = s.encode().expect("a valid snapshot encodes");
        let again = Snapshot::decode(&bytes, id).expect("canonical bytes decode");
        assert_eq!(again, s);
    }
}

/// Export document v2 parse + validation (the bytes after the age layer, ADR-0023); on success
/// the document re-serialises and parses again to the same value.
pub fn fuzz_export_document_json(data: &[u8]) {
    if let Ok(d) = crate::export::parse_document_json(data) {
        let bytes = serde_json::to_vec(&d).expect("a valid document serialises");
        let again = crate::export::parse_document_json(&bytes).expect("canonical bytes parse");
        assert_eq!(again, d);
    }
}
