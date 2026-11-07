//! Typed credentials (ADR-0009 §4): per-secret sealing and binding, kind rules on write and
//! read, metadata-only listing, inheritance, roles, overrides, and a proptest seal/open.

#![allow(clippy::many_single_char_names)] // s = store, v = vault, l = lab, f = fixture, as in the other store tests

mod common;

use common::{conn, lab, password, secrets, ssh_key, vault};
use mooring_core::credential::testdata::{CERT_FP, CERT_PEM, KUBECONFIG};
use mooring_core::credential::CredentialError;
use mooring_core::{Connection, ConnectionId, CredentialFields, CredentialId, Protocol, Role};
use mooring_store::{CredentialKind, SecretName, Store, StoreError};
use mooring_vault::VaultError;
use proptest::prelude::*;
use serde_json::json;

#[test]
fn create_open_and_meta_only_listing() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let (m, pem) = ssh_key(&s, &v, "lab key", b"test-passphrase");
    assert_eq!(m.kind, CredentialKind::SshKey);
    assert_eq!(m.secret_names, [SecretName::PrivateKey, SecretName::Passphrase]);
    assert_eq!(
        s.open_secret(&v, m.id, SecretName::PrivateKey).expect("key").as_slice(),
        pem.as_bytes()
    );
    assert_eq!(
        s.open_secret(&v, m.id, SecretName::Passphrase).expect("pp").as_slice(),
        b"test-passphrase"
    );
    let list = s.list_credentials().expect("list");
    assert_eq!(list, vec![m.clone()]);
    assert!(!format!("{list:?}").contains("test-passphrase"));

    let upd =
        s.update_credential_fields(m.id, "renamed", &json!({"username": "admin"})).expect("upd");
    assert_eq!((upd.name.as_str(), upd.fields.account().0.as_deref()), ("renamed", Some("admin")));
    assert_eq!(upd.kind, m.kind, "kind is immutable");
}

#[test]
fn required_secrets_unknown_names_and_kind_rules() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let f = json!({"username": "ops"});
    let e = s
        .create_credential(&v, "x", CredentialKind::UserPassword, &f, &secrets(&[]))
        .expect_err("pw");
    assert!(matches!(e, StoreError::Invalid { field: "password", .. }));
    let wrong = secrets(&[(SecretName::Password, b"p"), (SecretName::Token, b"t")]);
    assert!(s.create_credential(&v, "x", CredentialKind::UserPassword, &f, &wrong).is_err());
    let vnc = secrets(&[(SecretName::Password, b"123456789")]);
    let e =
        s.create_credential(&v, "v", CredentialKind::VncPassword, &json!({}), &vnc).expect_err("9");
    assert!(e.to_string().contains("not truncated") && !e.to_string().contains("123456789"));
    let m = password(&s, &v, "pw");
    assert!(matches!(s.open_secret(&v, m.id, SecretName::Token), Err(StoreError::Invalid { .. })));
    assert!(matches!(
        s.open_secret(&v, m.id, SecretName::OtpSeed),
        Err(StoreError::NotFound { kind: "secret", .. })
    ));
    assert!(matches!(
        s.open_secret(&v, CredentialId::new(), SecretName::Password),
        Err(StoreError::NotFound { kind: "credential", .. })
    ));
}

#[test]
fn replace_secrets_set_clear_and_otp_follows_the_seed() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let m = password(&s, &v, "pw");
    let seed = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let after =
        s.replace_secrets(&v, m.id, &secrets(&[(SecretName::OtpSeed, seed)]), &[]).expect("seed");
    assert!(after.secret_names.contains(&SecretName::OtpSeed));
    assert!(after.fields.otp().is_some(), "default otp params attached with the seed");
    let upd = s
        .update_credential_fields(
            m.id,
            "pw",
            &json!({"username": "ops", "otp": {"digits": 8, "period": 60, "algorithm": "sha256"}}),
        )
        .expect("otp params");
    assert_eq!(upd.fields.otp().map(|o| o.digits), Some(8));
    assert!(
        s.replace_secrets(&v, m.id, &secrets(&[]), &[SecretName::Password]).is_err(),
        "required"
    );
    let both = secrets(&[(SecretName::OtpSeed, seed)]);
    assert!(s.replace_secrets(&v, m.id, &both, &[SecretName::OtpSeed]).is_err(), "set and clear");
    let cleared =
        s.replace_secrets(&v, m.id, &secrets(&[]), &[SecretName::OtpSeed]).expect("clear");
    assert!(!cleared.secret_names.contains(&SecretName::OtpSeed) && cleared.fields.otp().is_none());
    s.replace_secrets(&v, m.id, &secrets(&[(SecretName::Password, b"test-new")]), &[])
        .expect("rotate");
    assert_eq!(s.open_secret(&v, m.id, SecretName::Password).expect("o").as_slice(), b"test-new");
}

#[test]
fn derived_values_x509_and_kubeconfig() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let key = mooring_core::credential::testdata::placeholder_key_pem();
    let x = s
        .create_credential(
            &v,
            "mtls",
            CredentialKind::X509,
            &json!({"cert_pem": CERT_PEM}),
            &secrets(&[(SecretName::KeyPem, key.as_bytes())]),
        )
        .expect("x509");
    assert_eq!(x.fingerprint(), Some(CERT_FP));
    let k = s
        .create_credential(
            &v,
            "kube",
            CredentialKind::Kubeconfig,
            &json!({"context": "lab-admin"}),
            &secrets(&[(SecretName::KubeconfigYaml, KUBECONFIG.as_bytes())]),
        )
        .expect("kubeconfig");
    let CredentialFields::Kubeconfig(kf) = &k.fields else { panic!("kind") };
    assert_eq!(kf.contexts, ["lab", "lab-admin"]);
    let bad = KUBECONFIG.replace("token: test-only-token", "exec: {command: /bin/sh}");
    let e = s
        .create_credential(
            &v,
            "evil",
            CredentialKind::Kubeconfig,
            &json!({}),
            &secrets(&[(SecretName::KubeconfigYaml, bad.as_bytes())]),
        )
        .expect_err("exec");
    assert!(matches!(e, StoreError::Credential(CredentialError::KubeconfigRejected(_))));
    assert_eq!(s.list_credentials().expect("list").len(), 2, "nothing stored on rejection");
}

#[test]
fn sealed_value_cannot_be_moved_between_credentials_or_names() {
    let v = vault();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let fs = Store::open(&path).expect("file store");
    let (a, _) = ssh_key(&fs, &v, "a", b"test-pp-a");
    let (b, _) = ssh_key(&fs, &v, "b", b"test-pp-b");
    drop(fs);
    let raw = rusqlite::Connection::open(&path).expect("raw");
    raw.execute(
        "UPDATE credential_secret SET sealed = (SELECT sealed FROM credential_secret
           WHERE credential_id = ?2 AND name = 'passphrase')
         WHERE credential_id = ?1 AND name = 'passphrase'",
        [a.id.to_string(), b.id.to_string()],
    )
    .expect("row swap");
    raw.execute(
        "UPDATE credential_secret SET sealed = (SELECT sealed FROM credential_secret
           WHERE credential_id = ?1 AND name = 'private_key')
         WHERE credential_id = ?1 AND name = 'passphrase'",
        [b.id.to_string()],
    )
    .expect("name swap");
    drop(raw);
    let fs = Store::open(&path).expect("reopen");
    for (id, n) in [(a.id, SecretName::Passphrase), (b.id, SecretName::Passphrase)] {
        let e = fs.open_secret(&v, id, n).expect_err("moved");
        assert!(matches!(e, StoreError::Vault(VaultError::Tampered)));
        assert!(!e.to_string().contains("test-pp"));
    }
    assert!(fs.open_secret(&v, b.id, SecretName::PrivateKey).is_ok(), "untouched row opens");
}

#[test]
fn corrupt_rows_are_refused_not_partially_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let v = vault();
    let fs = Store::open(&path).expect("open");
    let m = password(&fs, &v, "pw");
    drop(fs);
    let raw = rusqlite::Connection::open(&path).expect("raw");
    raw.execute(
        "UPDATE credential SET fields_json = '{\"username\":\"a\",\"x\":1}' WHERE id = ?1",
        [m.id.to_string()],
    )
    .expect("tamper fields");
    drop(raw);
    let fs = Store::open(&path).expect("reopen");
    assert!(matches!(fs.get_credential(m.id), Err(StoreError::Corrupt { .. })));
    let raw = rusqlite::Connection::open(&path).expect("raw");
    raw.execute(
        "UPDATE credential SET fields_json = '{\"username\":\"a\"}' WHERE id = ?1",
        [m.id.to_string()],
    )
    .expect("fix");
    raw.execute("INSERT INTO credential_secret VALUES (?1, 'token', x'00')", [m.id.to_string()])
        .expect("bad name");
    drop(raw);
    assert!(matches!(fs.get_credential(m.id), Err(StoreError::Corrupt { what: "secret name" })));
}

#[test]
fn locked_vault_refuses_secrets_but_not_metadata() {
    let s = Store::open_in_memory().expect("open");
    let mut v = vault();
    let m = password(&s, &v, "pw");
    v.lock();
    assert!(matches!(
        s.open_secret(&v, m.id, SecretName::Password),
        Err(StoreError::Vault(VaultError::Locked))
    ));
    let f = json!({"username": "a"});
    let e = s.create_credential(
        &v,
        "x",
        CredentialKind::UserPassword,
        &f,
        &secrets(&[(SecretName::Password, b"p")]),
    );
    assert!(matches!(e, Err(StoreError::Vault(VaultError::Locked))));
    assert_eq!(s.list_credentials().expect("meta").len(), 1);
}

#[test]
fn cascade_delete_removes_secrets_and_roles() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let login = password(s, &v, "login");
    let become_ = s
        .create_credential(
            &v,
            "sudo",
            CredentialKind::SudoBecome,
            &json!({"method": "sudo"}),
            &secrets(&[]),
        )
        .expect("become");
    let mut c = Connection::new(l.kube.id, "x", Protocol::Ssh, "h.example.test").expect("valid");
    c.credential = Some(login.id);
    c.become_credential = Some(become_.id);
    let c = s.create_connection(&c).expect("create");
    assert_eq!(c.become_credential, Some(become_.id));
    s.delete_credential(become_.id).expect("delete");
    assert_eq!(s.get_connection(c.id).expect("c").become_credential, None);
    s.delete_credential(login.id).expect("delete");
    assert_eq!(s.get_connection(c.id).expect("c").credential, None);
}

#[test]
fn roles_overrides_and_incompatibility() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let shared = password(s, &v, "shared");
    let (key, _) = ssh_key(s, &v, "key", b"pp");
    let sudo = s
        .create_credential(
            &v,
            "sudo",
            CredentialKind::SudoBecome,
            &json!({"method": "su"}),
            &secrets(&[]),
        )
        .expect("become");
    s.set_folder_default_credential(l.servers.id, Some(key.id)).expect("default");
    let mut rdp =
        Connection::new(l.kube.id, "win", Protocol::Rdp, "w.example.test").expect("valid");
    // explicit incompatible links are refused at write time with the UI sentence
    rdp.credential = Some(key.id);
    let e = s.create_connection(&rdp).expect_err("ssh key on rdp");
    assert_eq!(e.to_string(), "SSH key is for SSH, not RDP sign-in.");
    rdp.credential = None;
    rdp.become_credential = Some(sudo.id);
    assert!(matches!(
        s.create_connection(&rdp),
        Err(StoreError::Credential(CredentialError::Incompatible(_)))
    ));
    rdp.become_credential = None;
    // an incompatible inherited credential is not skipped: resolving reports it
    let rdp = s.create_connection(&rdp).expect("inherits");
    let e = s.resolve_credential(rdp.id, Role::Primary).expect_err("inherited ssh key");
    assert!(matches!(e, StoreError::Credential(CredentialError::Incompatible(_))));
    s.set_connection_role_credential(rdp.id, Role::Gateway, Some(shared.id)).expect("gateway");
    assert!(s.set_connection_role_credential(rdp.id, Role::Primary, Some(shared.id)).is_err());
    let r = s.resolve_credential(rdp.id, Role::Gateway).expect("ok").expect("some");
    assert_eq!((r.id, r.inherited), (shared.id, false));

    // overrides replace the username / domain without duplicating the secret
    let mut ssh = conn(s, &l.kube, "db01", "db.example.test", &[]);
    ssh.credential = Some(shared.id);
    ssh.username_override = Some(" dba ".into());
    ssh.domain_override = Some("CORP".into());
    let ssh = s.update_connection(&ssh).expect("overrides");
    assert_eq!(ssh.username_override.as_deref(), Some("dba"));
    let r = s.resolve_credential(ssh.id, Role::Primary).expect("ok").expect("some");
    assert_eq!(r.fields.account(), (Some("dba".into()), Some("CORP".into())));
    assert_eq!(s.get_credential(shared.id).expect("m").fields.account().0.as_deref(), Some("ops"));
    // a domain override on a kind without a domain is a validation error
    let mut bad = ssh.clone();
    bad.credential = Some(key.id);
    assert!(matches!(
        s.update_connection(&bad),
        Err(StoreError::Invalid { field: "domainOverride", .. })
    ));
    assert!(matches!(
        s.resolve_credential(ConnectionId::new(), Role::Primary),
        Err(StoreError::NotFound { .. })
    ));
}

#[test]
fn inheritance_resolution_is_unchanged() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let root_cred = password(s, &v, "root default");
    let servers_cred = password(s, &v, "servers default");
    let c = conn(s, &l.kube, "okd-master", "192.0.2.10", &[]);
    assert_eq!(s.effective_credential(c.id).expect("none"), None);
    s.set_folder_default_credential(l.root.id, Some(root_cred.id)).expect("root");
    assert_eq!(s.effective_credential(c.id).expect("root"), Some(root_cred.id));
    s.set_folder_default_credential(l.servers.id, Some(servers_cred.id)).expect("servers");
    assert_eq!(s.effective_credential(c.id).expect("nearest"), Some(servers_cred.id));
    let r = s.resolve_credential(c.id, Role::Primary).expect("ok").expect("some");
    assert!(r.inherited);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn seal_open_through_store_round_trips(pw in "[ -~]{1,200}", pp in proptest::option::of("[ -~]{1,100}")) {
        let s = Store::open_in_memory().expect("open");
        let v = vault();
        let mut sec = secrets(&[(SecretName::Password, pw.as_bytes())]);
        if let Some(pp) = &pp {
            sec.insert(SecretName::OtpSeed, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
            let _ = pp;
        }
        let m = s.create_credential(&v, "p", CredentialKind::UserPassword, &json!({"username": "u"}), &sec).expect("create");
        let got = s.open_secret(&v, m.id, SecretName::Password).expect("open");
        prop_assert_eq!(got.as_slice(), pw.as_bytes());
        prop_assert_eq!(m.secret_names.contains(&SecretName::OtpSeed), pp.is_some());
    }
}

/// ADR-0026 §1 (migration 0009): the `certificate` role takes a Vault `ssh_sign` reference on
/// SSH only, round-trips, and that reference is refused as a primary credential.
#[test]
fn certificate_role_holds_an_ssh_sign_reference() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let (key, _) = ssh_key(s, &v, "key", b"pp");
    let src = s
        .create_credential(
            &v,
            "vault token",
            CredentialKind::ApiToken,
            &json!({}),
            &secrets(&[(SecretName::Token, b"test-only-token")]),
        )
        .expect("token");
    let source: mooring_core::secret_source::SecretSourceInput = serde_json::from_value(json!({
        "name": "Vault", "address": "https://vault.example.test", "authMethod": "token",
        "credentialId": src.id}))
    .expect("input");
    let source = s.create_secret_source(&source).expect("source");
    let sign = s
        .create_credential(
            &v,
            "ssh ca",
            CredentialKind::ExternalRef,
            &json!({"provider": "vault", "reference": "ssh/deploy", "target_kind": "ssh_key",
                    "engine": "ssh_sign", "principals": ["deploy"], "ttl": 600, "source": source.id}),
            &secrets(&[]),
        )
        .expect("ssh_sign ref");
    let mut c = Connection::new(l.kube.id, "x", Protocol::Ssh, "h.example.test").expect("valid");
    c.credential = Some(key.id);
    c.certificate_credential = Some(sign.id);
    let c = s.create_connection(&c).expect("create");
    assert_eq!(s.get_connection(c.id).expect("c").certificate_credential, Some(sign.id));
    let r = s.resolve_credential(c.id, Role::Certificate).expect("ok").expect("some");
    assert_eq!(r.id, sign.id);
    let mut primary = Connection::new(l.kube.id, "y", Protocol::Ssh, "h.example.test").expect("v");
    primary.credential = Some(sign.id);
    let e = s.create_connection(&primary).expect_err("modifier only");
    assert!(e.to_string().contains("certificate role"), "{e}");
    let mut rdp = Connection::new(l.kube.id, "w", Protocol::Rdp, "w.example.test").expect("v");
    rdp.certificate_credential = Some(sign.id);
    assert!(s.create_connection(&rdp).is_err(), "SSH only");
    assert!(s.set_connection_role_credential(c.id, Role::Certificate, Some(key.id)).is_err());
    s.set_connection_role_credential(c.id, Role::Certificate, None).expect("clear");
    assert_eq!(s.get_connection(c.id).expect("c").certificate_credential, None);
}
