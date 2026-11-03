//! Sealed credential columns: round trip, row/column binding, metadata-only listing,
//! inheritance resolution, and a proptest seal/open through the store.

mod common;

use common::{conn, lab, password, vault};
use mooring_core::{ConnectionId, CredentialId};
use mooring_store::{CredentialKind, CredentialMeta, SecretField, Store, StoreError};
use mooring_vault::VaultError;
use proptest::prelude::*;

#[test]
fn seal_open_round_trip_and_meta_only_listing() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let meta = CredentialMeta::new("lab key", CredentialKind::SshKey, Some("root")).expect("meta");
    let stored = s
        .create_credential(&v, &meta, b"test-private-key", Some(b"test-passphrase"))
        .expect("create");
    assert_eq!(stored.id, meta.id);
    assert_eq!(stored.kind, CredentialKind::SshKey);
    assert_eq!(stored.username.as_deref(), Some("root"));

    let k = s.open_credential_secret(&v, meta.id, SecretField::Secret).expect("open");
    assert_eq!(k.as_slice(), b"test-private-key");
    let p = s.open_credential_secret(&v, meta.id, SecretField::Secret2).expect("open2");
    assert_eq!(p.as_slice(), b"test-passphrase");

    let list = s.list_credentials().expect("list");
    assert_eq!(list, vec![stored.clone()]);
    let shown = format!("{list:?}");
    assert!(!shown.contains("test-private-key") && !shown.contains("test-passphrase"));

    let updated = s.update_credential_meta(meta.id, "renamed", None).expect("update");
    assert_eq!(updated.name, "renamed");
    assert_eq!(updated.username, None);
}

#[test]
fn missing_secret2_and_unknown_id_are_not_found() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let c = password(&s, &v, "pw");
    assert!(matches!(
        s.open_credential_secret(&v, c.id, SecretField::Secret2),
        Err(StoreError::NotFound { kind: "secret", .. })
    ));
    assert!(matches!(
        s.open_credential_secret(&v, CredentialId::new(), SecretField::Secret),
        Err(StoreError::NotFound { kind: "credential", .. })
    ));
}

#[test]
fn sealed_value_cannot_be_moved_between_rows_or_columns() {
    let v = vault();
    let a = CredentialMeta::new("a", CredentialKind::Certificate, None).expect("a");
    let b = CredentialMeta::new("b", CredentialKind::Certificate, None).expect("b");

    // Simulate an attacker with write access to mooring.db copying sealed blobs around.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let fs = Store::open(&path).expect("file store");
    fs.create_credential(&v, &a, b"test-cert-a", Some(b"test-key-a")).expect("a");
    fs.create_credential(&v, &b, b"test-cert-b", Some(b"test-key-b")).expect("b");
    drop(fs);

    let raw = rusqlite::Connection::open(&path).expect("raw");
    // row swap: a.secret := b.secret
    raw.execute(
        "UPDATE credential SET secret = (SELECT secret FROM credential WHERE id = ?2) WHERE id = ?1",
        [a.id.to_string(), b.id.to_string()],
    )
    .expect("row swap");
    // column swap on b: secret2 := secret
    raw.execute("UPDATE credential SET secret2 = secret WHERE id = ?1", [b.id.to_string()])
        .expect("column swap");
    drop(raw);

    let fs = Store::open(&path).expect("reopen");
    assert!(matches!(
        fs.open_credential_secret(&v, a.id, SecretField::Secret),
        Err(StoreError::Vault(VaultError::Tampered))
    ));
    assert!(matches!(
        fs.open_credential_secret(&v, b.id, SecretField::Secret2),
        Err(StoreError::Vault(VaultError::Tampered))
    ));
    // untouched columns still open
    assert_eq!(
        fs.open_credential_secret(&v, b.id, SecretField::Secret).expect("b").as_slice(),
        b"test-cert-b"
    );
    // errors never carry plaintext
    let e = fs.open_credential_secret(&v, a.id, SecretField::Secret).expect_err("tampered");
    assert!(!e.to_string().contains("test-cert"));
}

#[test]
fn locked_vault_and_secret_replacement() {
    let s = Store::open_in_memory().expect("open");
    let mut v = vault();
    let c = password(&s, &v, "pw");
    s.replace_credential_secret(&v, c.id, SecretField::Secret, Some(b"test-new")).expect("rotate");
    assert_eq!(
        s.open_credential_secret(&v, c.id, SecretField::Secret).expect("open").as_slice(),
        b"test-new"
    );
    assert!(s.replace_credential_secret(&v, c.id, SecretField::Secret, None).is_err());
    s.replace_credential_secret(&v, c.id, SecretField::Secret2, Some(b"x")).expect("set2");
    s.replace_credential_secret(&v, c.id, SecretField::Secret2, None).expect("clear2");

    v.lock();
    assert!(matches!(
        s.open_credential_secret(&v, c.id, SecretField::Secret),
        Err(StoreError::Vault(VaultError::Locked))
    ));
    let meta = CredentialMeta::new("x", CredentialKind::Password, None).expect("meta");
    assert!(matches!(
        s.create_credential(&v, &meta, b"x", None),
        Err(StoreError::Vault(VaultError::Locked))
    ));
    assert!(matches!(s.get_credential(meta.id), Err(StoreError::NotFound { .. })));
}

#[test]
fn inheritance_resolution() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let root_cred = password(s, &v, "root default");
    let servers_cred = password(s, &v, "servers default");
    let own = password(s, &v, "own");
    let c = conn(s, &l.okd, "okd-master", "10.10.30.10", &[]);

    // nothing set anywhere → None
    assert_eq!(s.effective_credential(c.id).expect("none"), None);

    // root fallback
    s.set_folder_default_credential(l.root.id, Some(root_cred.id)).expect("root");
    assert_eq!(s.effective_credential(c.id).expect("root"), Some(root_cred.id));

    // nearest folder wins
    s.set_folder_default_credential(l.servers.id, Some(servers_cred.id)).expect("servers");
    assert_eq!(s.effective_credential(c.id).expect("nearest"), Some(servers_cred.id));

    // connection override beats folders
    let mut with_override = c.clone();
    with_override.credential = Some(own.id);
    s.update_connection(&with_override).expect("override");
    assert_eq!(s.effective_credential(c.id).expect("override"), Some(own.id));

    // deleting the override credential falls back to inheritance (ON DELETE SET NULL)
    s.delete_credential(own.id).expect("delete");
    assert_eq!(s.effective_credential(c.id).expect("fallback"), Some(servers_cred.id));
    s.set_folder_default_credential(l.servers.id, None).expect("clear");
    assert_eq!(s.effective_credential(c.id).expect("root again"), Some(root_cred.id));

    assert!(matches!(
        s.effective_credential(ConnectionId::new()),
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        s.set_folder_default_credential(l.root.id, Some(CredentialId::new())),
        Err(StoreError::NotFound { .. })
    ));
}

#[test]
fn oversized_secret_is_rejected_without_echo() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let meta = CredentialMeta::new("big", CredentialKind::Certificate, None).expect("meta");
    let big = vec![b'z'; 64 * 1024 + 1];
    let e = s.create_credential(&v, &meta, &big, None).expect_err("too big");
    assert!(matches!(e, StoreError::Invalid { field: "secret", .. }));
    assert!(!e.to_string().contains("zzzz"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn seal_open_through_store_round_trips(
        secret in proptest::collection::vec(any::<u8>(), 0..512),
        secret2 in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..256)),
    ) {
        let s = Store::open_in_memory().expect("open");
        let v = vault();
        let meta = CredentialMeta::new("p", CredentialKind::SshKey, None).expect("meta");
        s.create_credential(&v, &meta, &secret, secret2.as_deref()).expect("create");
        let got = s.open_credential_secret(&v, meta.id, SecretField::Secret).expect("open");
        prop_assert_eq!(got.as_slice(), secret.as_slice());
        match secret2 {
            Some(s2) => {
                let got2 = s.open_credential_secret(&v, meta.id, SecretField::Secret2).expect("open2");
                prop_assert_eq!(got2.as_slice(), s2.as_slice());
            }
            None => prop_assert!(s.open_credential_secret(&v, meta.id, SecretField::Secret2).is_err()),
        }
    }
}
