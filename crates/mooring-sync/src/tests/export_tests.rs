//! ADR-0023 §1 document v2: round trip, v1 fallback, `keyring_wrap` stripped, foreign reseal,
//! and the hostile-file matrix (every case refused as a whole, never partially).

use std::collections::BTreeMap;

use mooring_store::{ConnectionRow, CredentialRow, FolderRow};
use mooring_vault::{KdfParams, MemoryWrapKeyStore, Sealed, Vault};
use secrecy::SecretString;
use uuid::Uuid;

use super::vaults;
use crate::export::{
    export_age_fast, import_age, parse_document_json, reseal_snapshot, validate, ExportDocument,
    ExportError, Imported, DOCUMENT_VERSION,
};
use crate::snapshot::Snapshot;

const ROOT: &str = "00000000-0000-4000-8000-000000000001";
const LAB: &str = "00000000-0000-4000-8000-000000000002";
const CONN: &str = "00000000-0000-4000-8000-000000000011";
const CRED: &str = "00000000-0000-4000-8000-000000000021";
const T0: &str = "2026-11-01T00:00:00Z";
const PASS: &str = "an export passphrase";

fn pass() -> SecretString {
    SecretString::from(PASS.to_owned())
}

fn folder(id: &str, parent: Option<&str>, name: &str) -> FolderRow {
    FolderRow {
        created_at: T0.into(),
        default_credential_id: None,
        id: id.into(),
        name: name.into(),
        parent_id: parent.map(Into::into),
        sort: 0,
        updated_at: T0.into(),
    }
}

fn conn(id: &str, folder: &str, cred: Option<&str>) -> ConnectionRow {
    ConnectionRow {
        created_at: T0.into(),
        credential_id: cred.map(Into::into),
        domain_override: None,
        folder_id: folder.into(),
        host: "web.example.test".into(),
        id: id.into(),
        name: "web".into(),
        options_json: "{}".into(),
        port: None,
        protocol: "ssh".into(),
        roles: BTreeMap::new(),
        tags: vec![],
        updated_at: T0.into(),
        username_override: None,
    }
}

fn cred(v: &Vault, id: &str, secret: &[u8]) -> CredentialRow {
    let sealed = v.seal(id, "password", secret).expect("seal");
    let mut secrets = BTreeMap::new();
    secrets.insert("password".to_owned(), serde_json::to_string(&sealed).expect("json"));
    CredentialRow {
        created_at: T0.into(),
        fields_json: r#"{"username":"ops"}"#.into(),
        id: id.into(),
        kind: "user_password".into(),
        name: "ops".into(),
        secrets,
        updated_at: T0.into(),
    }
}

/// A document of `v`: root → Lab, one connection using one credential, one trust line.
fn doc(v: &Vault) -> ExportDocument {
    let mut s = Snapshot::empty(v.vault_id(), "desk");
    s.folders.insert(ROOT.into(), folder(ROOT, None, "All connections"));
    s.folders.insert(LAB.into(), folder(LAB, Some(ROOT), "Lab"));
    s.connections.insert(CONN.into(), conn(CONN, LAB, Some(CRED)));
    s.credentials.insert(CRED.into(), cred(v, CRED, b"hunter2"));
    s.trust.insert("known_hosts".into(), ["|1|abc|def ssh-ed25519 AAAA".to_owned()].into());
    ExportDocument {
        version: DOCUMENT_VERSION,
        header: v.header().clone(),
        snapshot: s,
        exported_at: T0.into(),
        app_version: "0.2.0".into(),
    }
}

fn v2(i: Imported) -> ExportDocument {
    match i {
        Imported::V2(d) => d,
        Imported::V1 { .. } => panic!("expected a v2 document"),
    }
}

#[test]
fn round_trip_keeps_rows_and_opens_secrets() {
    let v = vaults(1).remove(0);
    let d = doc(&v);
    let bytes = export_age_fast(&d, &pass()).expect("export");
    let text = String::from_utf8(bytes.clone()).expect("armored");
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(!text.contains("hunter2") && !text.contains("example.test"));
    let back = v2(import_age(&bytes, &pass()).expect("import"));
    assert_eq!(back, d);
    let sealed: Sealed =
        serde_json::from_str(&back.snapshot.credentials[CRED].secrets["password"]).expect("s");
    assert_eq!(v.open(CRED, "password", &sealed).expect("open").as_slice(), b"hunter2");
}

#[test]
fn keyring_wrap_and_tombstones_never_reach_the_file() {
    let mut v = vaults(1).remove(0);
    let pw = SecretString::from(super::PASSWORD.to_owned());
    v.enable_keyring_unlock(&MemoryWrapKeyStore::new(), &pw).expect("enable");
    let mut d = doc(&v);
    d.snapshot.tombstones.insert(
        "connection:x".into(),
        crate::snapshot::Tombstone {
            deleted_at: T0.into(),
            id: "x".into(),
            kind: crate::RecordKind::Connection,
        },
    );
    assert!(d.header.keyring_wrap.is_some());
    let bytes = export_age_fast(&d, &pass()).expect("export");
    let back = v2(import_age(&bytes, &pass()).expect("import"));
    assert!(back.header.keyring_wrap.is_none(), "per-device wrap stripped");
    assert!(back.snapshot.tombstones.is_empty(), "a backup never deletes");
    // the stripped header still unlocks with the master password (wrap AAD is None-bound
    // only after the wrap is cleared by a password re-wrap; here the vault was enabled, so
    // the exporting side must strip and the importing side must not rely on unlocking it)
    assert_eq!(crate::export::exportable_header(&v).keyring_wrap, None);
}

#[test]
fn v1_document_imports_credentials_only() {
    let v = vaults(1).remove(0);
    let mut fields = BTreeMap::new();
    fields.insert("password".to_owned(), v.seal("c1", "password", b"legacy").expect("seal"));
    let v1 = mooring_vault::ExportDocument {
        header: v.header().clone(),
        credentials: vec![mooring_vault::ExportedRecord { record_id: "c1".into(), fields }],
        folders: serde_json::json!([{ "id": "f1" }]),
        connections: serde_json::json!([]),
    };
    let raw = serde_json::to_vec(&v1).expect("json");
    let bytes = mooring_vault::export_age_bytes_with_work_factor(&raw, &pass(), 10).expect("e");
    let Imported::V1 { header, credentials, note } = import_age(&bytes, &pass()).expect("v1")
    else {
        panic!("v1")
    };
    assert_eq!(header, *v.header());
    assert_eq!(credentials.len(), 1);
    assert!(note.contains("folders and connections"));
}

#[test]
fn foreign_document_reseals_under_our_vault() {
    let theirs = vaults(1).remove(0);
    let ours = Vault::create(&SecretString::from("another master pw!".to_owned()), KdfParams::TEST)
        .expect("ours");
    let mut d = doc(&theirs);
    reseal_snapshot(&mut d.snapshot, &theirs, &ours).expect("reseal");
    let sealed: Sealed =
        serde_json::from_str(&d.snapshot.credentials[CRED].secrets["password"]).expect("s");
    assert_eq!(ours.open(CRED, "password", &sealed).expect("open").as_slice(), b"hunter2");
    assert!(theirs.open(CRED, "password", &sealed).is_err(), "no longer theirs");
    // a wrong source vault refuses the whole snapshot
    let wrong = vaults(1).remove(0);
    let mut again = doc(&theirs);
    assert_eq!(reseal_snapshot(&mut again.snapshot, &wrong, &ours), Err(ExportError::Sealed));
}

type Mutation = Box<dyn FnOnce(&mut serde_json::Value)>;

fn hostile(mutate: impl FnOnce(&mut serde_json::Value)) -> Result<ExportDocument, ExportError> {
    let v = vaults(1).remove(0);
    let mut j = serde_json::to_value(doc(&v)).expect("json");
    mutate(&mut j);
    parse_document_json(&serde_json::to_vec(&j).expect("bytes"))
}

#[test]
fn hostile_documents_are_refused_as_a_whole() {
    let cases: Vec<(&str, Mutation, ExportError)> = vec![
        ("version 3", Box::new(|j| j["version"] = 3.into()), ExportError::Version(3)),
        ("unknown field", Box::new(|j| j["extra"] = 1.into()), ExportError::Format("document")),
        (
            "unknown snapshot field",
            Box::new(|j| j["snapshot"]["evil"] = 1.into()),
            ExportError::Format("document"),
        ),
        (
            "folder cycle",
            Box::new(|j| {
                j["snapshot"]["folders"][ROOT]["parent_id"] = LAB.into();
            }),
            ExportError::Format("folder cycle"),
        ),
        (
            "missing parent",
            Box::new(|j| {
                j["snapshot"]["folders"][LAB]["parent_id"] = CONN.into();
            }),
            ExportError::Format("folder parent missing"),
        ),
        (
            "second root",
            Box::new(|j| {
                j["snapshot"]["folders"][LAB]["parent_id"] = serde_json::Value::Null;
            }),
            ExportError::Format("several root folders"),
        ),
        (
            "unknown kind",
            Box::new(|j| j["snapshot"]["credentials"][CRED]["kind"] = "yubi_magic".into()),
            ExportError::Format("unknown credential kind"),
        ),
        (
            "unknown protocol",
            Box::new(|j| j["snapshot"]["connections"][CONN]["protocol"] = "telnet".into()),
            ExportError::Format("unknown connection protocol"),
        ),
        (
            "connection in missing folder",
            Box::new(|j| j["snapshot"]["connections"][CONN]["folder_id"] = CRED.into()),
            ExportError::Format("connection folder missing"),
        ),
        (
            "dangling credential",
            Box::new(|j| j["snapshot"]["connections"][CONN]["credential_id"] = LAB.into()),
            ExportError::Format("connection credential missing"),
        ),
        (
            "id used in two tables",
            Box::new(|j| {
                let row = j["snapshot"]["credentials"][CRED].clone();
                let mut row = row;
                row["id"] = LAB.into();
                j["snapshot"]["credentials"][LAB] = row;
                j["snapshot"]["connections"][CONN]["credential_id"] = LAB.into();
            }),
            ExportError::Format("duplicate id"),
        ),
        (
            "wrap in the file",
            Box::new(|j| {
                j["header"]["keyring_wrap"] =
                    serde_json::to_value(Sealed { nonce: vec![0; 24], ciphertext: vec![0; 48] })
                        .expect("sealed");
            }),
            ExportError::Format("document carries a keyring wrap"),
        ),
        (
            "vault id mismatch",
            Box::new(|j| j["snapshot"]["vault_id"] = Uuid::from_u128(9).to_string().into()),
            ExportError::Format("vault id"),
        ),
        (
            "hostile kdf cost",
            Box::new(|j| j["header"]["kdf_params"]["m_kib"] = u32::MAX.into()),
            ExportError::Format("vault header"),
        ),
        (
            "sealed secret not JSON",
            Box::new(|j| j["snapshot"]["credentials"][CRED]["secrets"]["password"] = "x".into()),
            ExportError::Format("sealed secret"),
        ),
        (
            "control char in metadata",
            Box::new(|j| j["app_version"] = "0.2\u{0}".into()),
            ExportError::Format("metadata"),
        ),
    ];
    for (name, mutate, want) in cases {
        assert_eq!(hostile(mutate).expect_err(name), want, "{name}");
    }
}

#[test]
fn duplicate_json_keys_are_refused_not_last_wins() {
    let v = vaults(1).remove(0);
    let text = serde_json::to_string(&doc(&v)).expect("json");
    // Duplicate the connection entry: serde would otherwise keep the last one silently.
    let needle = format!("\"connections\":{{\"{CONN}\":");
    let start = text.find(&needle).expect("connections map");
    let open = start + needle.len();
    let mut depth = 0usize;
    let mut end = open;
    for (i, ch) in text[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let row = &text[open..end];
    let dup = format!("{}{row},\"{CONN}\":{row}{}", &text[..open], &text[end..]);
    assert_eq!(parse_document_json(dup.as_bytes()), Err(ExportError::Format("document")));
    assert!(parse_document_json(text.as_bytes()).is_ok(), "the original parses");
}

#[test]
fn age_layer_refusals_map_to_fixed_errors() {
    let v = vaults(1).remove(0);
    let d = doc(&v);
    let min = mooring_vault::MIN_EXPORT_PASSPHRASE_CHARS;
    assert_eq!(
        export_age_fast(&d, &SecretString::from("short".to_owned())),
        Err(ExportError::WeakPassphrase { min })
    );
    let bytes = export_age_fast(&d, &pass()).expect("export");
    assert_eq!(
        import_age(&bytes, &SecretString::from("not the passphrase".to_owned())),
        Err(ExportError::Passphrase)
    );
    let mut t = bytes.clone();
    let i = t.len() / 2;
    t[i] = if t[i] == b'A' { b'B' } else { b'A' };
    assert!(matches!(
        import_age(&t, &pass()),
        Err(ExportError::Passphrase | ExportError::Format(_))
    ));
    let big = vec![b'a'; mooring_vault::MAX_EXPORT_BYTES + 1];
    assert_eq!(import_age(&big, &pass()), Err(ExportError::TooLarge));
    assert_eq!(import_age(b"garbage", &pass()), Err(ExportError::Format("not an age file")));
    assert!(validate(&d).is_ok());
    let err = ExportError::Passphrase.to_string();
    assert!(!err.contains(PASS));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

    /// The decrypted-payload parser never panics (stand-in for the `export_document_json`
    /// fuzz target).
    #[test]
    fn arbitrary_payload_never_panics(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024),
        prefix in proptest::sample::select(vec![
            &b""[..],
            b"{\"version\":2,\"header\":{",
            b"{\"version\":2,\"snapshot\":{\"folders\":{",
        ]),
    ) {
        let mut input = prefix.to_vec();
        input.extend_from_slice(&bytes);
        let _ = parse_document_json(&input);
        crate::fuzz::fuzz_export_document_json(&input);
    }
}
