use mooring_core::{CredentialKind, Protocol, SecretName};
use mooring_vault::{KdfParams, Vault};
use secrecy::SecretString;
use serde_json::json;

use super::*;

fn vault() -> Vault {
    Vault::create(&SecretString::from("test-only master pw".to_owned()), KdfParams::TEST)
        .expect("vault")
}

fn store() -> Store {
    let s = Store::open_in_memory().expect("open");
    s.create_folder(None, "All connections").expect("root");
    s
}

fn conn(folder: Option<&str>, name: &str, credential: Option<&str>) -> ImportConnection {
    ImportConnection {
        folder: folder.map(str::to_owned),
        name: name.into(),
        protocol: Protocol::Ssh,
        host: "192.0.2.10".into(),
        port: Some(2222),
        credential: credential.map(str::to_owned),
        tags: vec!["lab".into()],
    }
}

fn batch(pw: &[u8]) -> ImportBatch<'_> {
    let mut secrets = Secrets::new();
    secrets.insert(SecretName::Password, pw);
    ImportBatch {
        root_name: "Imported from Termius (2026-11-06)".into(),
        folders: vec![
            ImportFolder { key: "f1".into(), parent: None, name: "Prod".into() },
            ImportFolder { key: "f2".into(), parent: Some("f1".into()), name: "Web".into() },
        ],
        connections: vec![conn(Some("f2"), "web01", Some("k1")), conn(None, "bastion", Some("k2"))],
        credentials: vec![
            ImportCredential {
                key: "k1".into(),
                name: "deploy".into(),
                kind: CredentialKind::UserPassword,
                fields: json!({ "username": "deploy" }),
                secrets,
            },
            ImportCredential {
                key: "k2".into(),
                name: "ops".into(),
                kind: CredentialKind::Prompt,
                fields: json!({ "username": "ops" }),
                secrets: Secrets::new(),
            },
        ],
    }
}

fn totals(s: &Store) -> (usize, usize, usize) {
    let folders = s.list_folders().expect("folders");
    let conns: usize = folders.iter().map(|f| s.list_connections(f.id).expect("c").len()).sum();
    (folders.len(), conns, s.list_credentials().expect("creds").len())
}

#[test]
fn applies_everything_under_a_new_root_subfolder() {
    let s = store();
    let v = vault();
    let out = s.import_apply(&v, &batch(b"test-only pw")).expect("apply");
    assert_eq!((out.folders, out.connections, out.credentials, out.secrets), (2, 2, 2, 1));
    let root = s.root_folder().expect("root").expect("exists");
    let import_root = s.get_folder(out.root).expect("import root");
    assert_eq!(import_root.parent, Some(root.id));
    assert_eq!(import_root.name, "Imported from Termius (2026-11-06)");
    assert_eq!(totals(&s), (4, 2, 2));
    let web = s.child_folders(out.root).expect("children");
    assert_eq!(web.len(), 1);
    let sub = s.child_folders(web[0].id).expect("sub");
    assert_eq!(sub[0].name, "Web");
    let c = &s.list_connections(sub[0].id).expect("conns")[0];
    assert_eq!(
        (c.name.as_str(), c.port, c.tags.as_slice()),
        ("web01", Some(2222), &["lab".to_owned()][..])
    );
    let cred = s.get_credential(c.credential.expect("linked")).expect("cred");
    assert_eq!(cred.name, "deploy");
    assert_eq!(cred.secret_names, vec![SecretName::Password]);
    let plain = s.open_secret(&v, cred.id, SecretName::Password).expect("open");
    assert_eq!(plain.as_slice(), b"test-only pw");
    let bastion = &s.list_connections(out.root).expect("root conns")[0];
    assert_eq!(bastion.name, "bastion");
}

#[test]
fn a_failure_mid_transaction_writes_nothing() {
    let s = store();
    let v = vault();
    let before = totals(&s);
    // 1: a connection whose folder key is unknown, after valid rows were inserted.
    let mut b = batch(b"pw");
    b.connections.push(conn(Some("f9"), "dangling", None));
    assert!(s.import_apply(&v, &b).is_err());
    assert_eq!(totals(&s), before);
    // 2: an invalid host in the last connection.
    let mut b = batch(b"pw");
    b.connections[1].host = "bad host".into();
    assert!(s.import_apply(&v, &b).is_err());
    assert_eq!(totals(&s), before);
    // 3: a credential that cannot fill the connection's protocol.
    let mut b = batch(b"pw");
    b.connections[0].protocol = Protocol::Kubernetes;
    b.connections[0].host = "ctx".into();
    assert!(s.import_apply(&v, &b).is_err());
    assert_eq!(totals(&s), before);
    // 4: a required secret missing, a bad name, an unknown credential key.
    let mut b = batch(b"pw");
    b.credentials[0].secrets.clear();
    assert!(s.import_apply(&v, &b).is_err());
    let mut b = batch(b"pw");
    b.folders[1].name = "\u{7}".into();
    assert!(s.import_apply(&v, &b).is_err());
    let mut b = batch(b"pw");
    b.connections[0].credential = Some("k9".into());
    assert!(s.import_apply(&v, &b).is_err());
    assert_eq!(totals(&s), before);
}

#[test]
fn two_applies_never_merge() {
    let s = store();
    let v = vault();
    let a = s.import_apply(&v, &batch(b"pw")).expect("first");
    let b = s.import_apply(&v, &batch(b"pw")).expect("second");
    assert_ne!(a.root, b.root);
    assert_eq!(totals(&s), (7, 4, 4));
}
