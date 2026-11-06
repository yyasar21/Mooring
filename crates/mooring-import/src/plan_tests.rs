use mooring_core::{CredentialKind, Protocol};
use serde_json::json;

use super::*;
use crate::creds;

fn conn(name: &str, host: &str) -> NewConnection {
    NewConnection {
        name: name.into(),
        protocol: Some(Protocol::Ssh),
        host: host.into(),
        ..NewConnection::default()
    }
}

#[test]
fn folders_dedupe_by_parent_and_name_and_paths_nest() {
    let mut b = PlanBuilder::new(&Limits::DEFAULT);
    let a = b.folder(None, " A ", "x").expect("ok").expect("key");
    assert_eq!(b.folder(None, "A", "x").expect("ok").as_deref(), Some(a.as_str()));
    let ab = b.folder_path(["A", "", "B"], "x").expect("ok").expect("key");
    assert_ne!(a, ab);
    assert_eq!(b.folder_path(["A", "B"], "x").expect("ok").as_deref(), Some(ab.as_str()));
    // An invalid segment stops the descent at the last valid one.
    assert_eq!(b.folder_path(["A", "\u{7}", "C"], "x").expect("ok").as_deref(), Some(a.as_str()));
    assert_eq!(b.folder(None, "", "y").expect("ok"), None);
    let plan = b.finish();
    assert_eq!(plan.folders.len(), 2);
    assert_eq!(plan.folders[1].parent.as_deref(), Some(a.as_str()));
    assert_eq!(plan.skipped.len(), 2);
    assert!(plan.skipped.iter().all(|s| s.reason == SkipReason::Invalid));
}

#[test]
fn connections_validate_and_normalise() {
    let mut b = PlanBuilder::new(&Limits::DEFAULT);
    let mut c = conn(" web ", " h.example.test ");
    c.port = b.port(Some("22"), "x");
    c.user = Some(" alice ".into());
    c.domain = Some("bad\u{200E}".into());
    c.tags = (0..60).map(|i| format!("t{i}")).chain(["t0".into(), " ".into()]).collect();
    let key = b.connection(c, "x").expect("ok").expect("key");
    assert!(b.connection(conn("x", "bad host"), "y").expect("ok").is_none());
    assert!(b.connection(conn("", "h"), "z").expect("ok").is_none());
    let mut no_proto = conn("n", "h");
    no_proto.protocol = None;
    assert!(b.connection(no_proto, "w").expect("ok").is_none());
    assert_eq!(b.port(Some("0"), "p"), None);
    assert_eq!(b.port(Some("65536"), "p"), None);
    assert_eq!(b.port(Some(" 443 "), "p"), Some(443));
    assert_eq!(b.port(Some(""), "p"), None);
    let plan = b.finish();
    let c = &plan.connections[0];
    assert_eq!(
        (c.key.as_str(), c.name.as_str(), c.host.as_str(), c.port),
        (key.as_str(), "web", "h.example.test", Some(22))
    );
    assert_eq!(c.user.as_deref(), Some("alice"));
    assert_eq!(c.domain, None);
    assert_eq!(c.tags.len(), mooring_core::MAX_TAGS);
    let codes: Vec<WarningCode> = plan.warnings.iter().map(|w| w.code).collect();
    assert_eq!(
        codes,
        vec![
            WarningCode::UserIgnored,
            WarningCode::TagsTruncated,
            WarningCode::PortIgnored,
            WarningCode::PortIgnored
        ]
    );
    assert_eq!(plan.skipped.len(), 3);
}

#[test]
fn credentials_dedupe_on_kind_fields_and_secrets() {
    let mut b = PlanBuilder::new(&Limits::DEFAULT);
    let p1 = b.credential(creds::prompt("alice", Some("CORP")), "a").expect("ok").expect("k");
    let p2 = b.credential(creds::prompt("alice", Some("CORP")), "b").expect("ok").expect("k");
    assert_eq!(p1, p2);
    let u1 =
        b.credential(creds::user_password("alice", None, b"one"), "c").expect("ok").expect("k");
    let u2 =
        b.credential(creds::user_password("alice", None, b"two"), "d").expect("ok").expect("k");
    let u3 =
        b.credential(creds::user_password("alice", None, b"one"), "e").expect("ok").expect("k");
    assert_ne!(u1, u2);
    assert_eq!(u1, u3);
    let a1 = b.credential(creds::ssh_agent("bob", Some("k1")), "f").expect("ok").expect("k");
    let a2 = b.credential(creds::ssh_agent("bob", Some("k2")), "g").expect("ok").expect("k");
    assert_ne!(a1, a2);
    // Invalid fields, an empty secret or a secret of the wrong kind are skipped.
    let bad_fields = NewCredential {
        name: "x".into(),
        kind: CredentialKind::Prompt,
        fields: json!({"nope": 1}),
        secrets: None,
        key_file: None,
    };
    assert!(b.credential(bad_fields, "h").expect("ok").is_none());
    let mut wrong = SecretBundle::default();
    wrong.push(mooring_core::SecretName::Token, zeroize::Zeroizing::new(b"t".to_vec()));
    let wrong_secret = NewCredential {
        name: "x".into(),
        kind: CredentialKind::Prompt,
        fields: json!({"username": "a"}),
        secrets: Some(wrong),
        key_file: None,
    };
    assert!(b.credential(wrong_secret, "i").expect("ok").is_none());
    assert!(b.credential(creds::user_password("alice", None, b""), "j").expect("ok").is_none());
    let plan = b.finish();
    assert_eq!(plan.credentials.len(), 5);
    assert_eq!(plan.counts().secrets, 2);
    assert_eq!(plan.skipped.len(), 3);
    assert!(plan.is_consistent());
    assert_eq!(
        format!("{:?}", plan.credentials[2].secrets),
        "Some(SecretBundle { names: [\"password\"] })"
    );
}

#[test]
fn item_caps_are_errors_and_note_caps_count() {
    let limits = Limits {
        max_folders: 1,
        max_connections: 1,
        max_credentials: 1,
        max_notes: 2,
        ..Limits::DEFAULT
    };
    let mut b = PlanBuilder::new(&limits);
    assert!(b.folder(None, "a", "x").is_ok());
    assert_eq!(b.folder(None, "b", "x"), Err(ImportError::limits("folders")));
    assert!(b.connection(conn("a", "h"), "x").is_ok());
    assert_eq!(b.connection(conn("b", "h"), "x").err(), Some(ImportError::limits("connections")));
    assert!(b.credential(creds::prompt("a", None), "x").is_ok());
    assert_eq!(
        b.credential(creds::prompt("b", None), "x").err(),
        Some(ImportError::limits("credentials"))
    );
    for i in 0..5 {
        b.skip(format!("s{i}"), SkipReason::Unsupported);
        b.warn(WarningCode::PpkKey, format!("w{i}"));
    }
    let plan = b.finish();
    assert_eq!(plan.skipped.len(), 2);
    assert_eq!(plan.warnings.len(), 2);
    assert_eq!(plan.warnings[1].code, WarningCode::NotesTruncated);
    assert_eq!(plan.counts().skipped, 5);
    assert_eq!(plan.counts().warnings, 5);
}

#[test]
fn consistency_oracle_catches_dangling_keys() {
    let mut plan = ImportPlan::default();
    plan.connections.push(PlanConnection {
        key: "c1".into(),
        folder: Some("f9".into()),
        name: "n".into(),
        protocol: Protocol::Ssh,
        host: "h".into(),
        port: None,
        user: None,
        domain: None,
        credential: None,
        tags: vec![],
    });
    assert!(!plan.is_consistent());
    plan.connections[0].folder = None;
    plan.connections[0].credential = Some("k9".into());
    assert!(!plan.is_consistent());
    plan.connections[0].credential = None;
    assert!(plan.is_consistent());
    assert_eq!(serde_json::to_value(&plan.connections[0]).expect("json")["protocol"], "ssh");
}
