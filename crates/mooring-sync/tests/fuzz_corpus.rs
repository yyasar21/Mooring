//! Stable replay of the sync fuzz corpora (`sync_blob_parse`, `sync_snapshot_json`,
//! `export_document_json`) and crash regressions through the same entry points the cargo-fuzz
//! targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/export_document_json.rs"]
mod export_document_json;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/sync_blob_parse.rs"]
mod sync_blob_parse;
#[path = "../../../fuzz/entries/sync_snapshot_json.rs"]
mod sync_snapshot_json;

use mooring_sync::{decode_msy1, Snapshot, SyncError};
use uuid::Uuid;

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn sync_blob_parse_corpus() {
    assert!(replay::replay("sync_blob_parse", sync_blob_parse::run) >= 2);
}

/// The committed vector must keep decoding (counter 7 on parent 6), or the fuzzer only
/// explores the refusal branch.
#[test]
fn blob_vector_seed_decodes() {
    let bytes = seed("sync_blob_parse", "vector-v1");
    let m = decode_msy1(&bytes).expect("vector decodes");
    assert_eq!((m.header.counter, m.header.parent_counter), (7, 6));
    assert_eq!(m.ciphertext.len(), 1637 - 125 - 24);
}

#[test]
fn sync_snapshot_json_corpus() {
    assert!(replay::replay("sync_snapshot_json", sync_snapshot_json::run) >= 2);
}

/// The empty snapshot seed decodes for the fuzz entry's vault id; the wrong-vault seed is
/// refused for that reason alone.
#[test]
fn snapshot_seeds_split_accept_and_refuse() {
    let id = Uuid::from_u128(1);
    let s = Snapshot::decode(&seed("sync_snapshot_json", "empty-snapshot"), id).expect("decodes");
    assert_eq!(s.device_name, "laptop");
    assert_eq!(s.trust["known_hosts"].len(), 1);
    assert!(matches!(
        Snapshot::decode(&seed("sync_snapshot_json", "wrong-vault"), id),
        Err(SyncError::WrongVault)
    ));
}

#[test]
fn export_document_json_corpus() {
    assert!(replay::replay("export_document_json", export_document_json::run) >= 6);
}

/// The v2 seed must keep parsing (or the fuzzer only explores refusals), and each hostile seed
/// must be refused for its own reason alone (every one is otherwise the valid document).
#[test]
fn export_document_seeds_split_accept_and_refuse() {
    use mooring_sync::export::parse_document_json;
    use mooring_sync::ExportError;
    let doc = parse_document_json(&seed("export_document_json", "v2-document")).expect("v2 seed");
    assert_eq!((doc.version, doc.app_version.as_str()), (2, "0.2.0"));
    assert_eq!((doc.snapshot.folders.len(), doc.snapshot.connections.len()), (2, 1));
    assert_eq!(doc.snapshot.credentials.len(), 1);
    for (name, want) in [
        ("folder-cycle", ExportError::Format("folder cycle")),
        ("version-3", ExportError::Version(3)),
        ("vault-id-mismatch", ExportError::Format("vault id")),
        ("duplicate-key", ExportError::Format("document")),
    ] {
        assert_eq!(parse_document_json(&seed("export_document_json", name)), Err(want), "{name}");
    }
    assert!(
        parse_document_json(&seed("export_document_json", "dangling-credential")).is_err(),
        "a connection naming a missing credential is refused"
    );
}
