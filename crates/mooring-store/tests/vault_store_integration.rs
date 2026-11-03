//! Cross-crate integration: `mooring-vault` lifecycle driving `mooring-store` sealed columns
//! (ADR-0005 + ADR-0006). Every secret is a synthetic test string.

use std::collections::BTreeMap;

use mooring_core::{Connection, Protocol};
use mooring_store::{CredentialKind, CredentialMeta, SecretField, Store, StoreError};
use mooring_vault::{
    export_age, import_age, ExportDocument, ExportedRecord, KdfParams, MemoryWrapKeyStore, Sealed,
    Vault, VaultError, VaultState,
};
use secrecy::SecretString;

const MASTER: &str = "integration master pw";

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn new_vault() -> Vault {
    Vault::create(&pw(MASTER), KdfParams::TEST).expect("create vault")
}

fn ssh(folder: mooring_core::FolderId, name: &str, host: &str) -> Connection {
    Connection::new(folder, name, Protocol::Ssh, host).expect("valid connection")
}

#[test]
fn full_lifecycle_create_store_lock_unlock() {
    let mut v = new_vault();
    let s = Store::open_in_memory().expect("store");
    s.set_vault_id(&v.vault_id().to_string()).expect("bind store to vault");

    let root = s.create_folder(None, "Home lab").expect("root");
    let servers = s.create_folder(Some(root.id), "servers").expect("servers");

    let pw_meta = CredentialMeta::new("ops pw", CredentialKind::Password, Some("ops")).expect("m");
    s.create_credential(&v, &pw_meta, b"test-ops-password", None).expect("password cred");
    let key_meta = CredentialMeta::new("ops key", CredentialKind::SshKey, Some("root")).expect("m");
    s.create_credential(&v, &key_meta, b"test-private-key", Some(b"test-key-passphrase"))
        .expect("ssh key cred");

    s.set_folder_default_credential(root.id, Some(pw_meta.id)).expect("root default");
    let inherited = s.create_connection(&ssh(servers.id, "xinfra01", "10.10.20.5")).expect("c1");
    let mut own = ssh(servers.id, "xmon01", "10.10.20.30");
    own.credential = Some(key_meta.id);
    let own = s.create_connection(&own).expect("c2");

    assert_eq!(s.effective_credential(inherited.id).expect("eff"), Some(pw_meta.id));
    assert_eq!(s.effective_credential(own.id).expect("eff"), Some(key_meta.id));

    let open = |v: &Vault, id, f| s.open_credential_secret(v, id, f);
    let eff = s.effective_credential(inherited.id).expect("eff").expect("some");
    assert_eq!(open(&v, eff, SecretField::Secret).expect("open").as_slice(), b"test-ops-password");

    // Lock: metadata and resolution still work, secrets do not.
    v.lock();
    assert_eq!(v.state(), VaultState::Locked);
    assert_eq!(s.effective_credential(own.id).expect("eff while locked"), Some(key_meta.id));
    assert_eq!(s.list_credentials().expect("meta while locked").len(), 2);
    for (id, f) in [
        (pw_meta.id, SecretField::Secret),
        (key_meta.id, SecretField::Secret),
        (key_meta.id, SecretField::Secret2),
    ] {
        assert!(matches!(open(&v, id, f), Err(StoreError::Vault(VaultError::Locked))));
    }
    assert!(matches!(
        s.replace_credential_secret(&v, pw_meta.id, SecretField::Secret, Some(b"x")),
        Err(StoreError::Vault(VaultError::Locked))
    ));

    // Wrong password keeps it locked; the right one restores access.
    assert_eq!(v.unlock(&pw("not the master password")), Err(VaultError::Unlock));
    assert_eq!(v.state(), VaultState::Locked);
    v.unlock(&pw(MASTER)).expect("unlock");
    assert_eq!(
        open(&v, key_meta.id, SecretField::Secret2).expect("open").as_slice(),
        b"test-key-passphrase"
    );
}

#[test]
fn header_v2_round_trip_binds_store_and_rejects_other_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("mooring.db");
    let header_path = dir.path().join("vault.header.json");

    let cred = {
        let v = new_vault();
        std::fs::write(&header_path, v.header().to_bytes().expect("header bytes")).expect("w");
        let s = Store::open(&db).expect("store");
        s.set_vault_id(&v.header().vault_id.to_string()).expect("first bind");
        let meta = CredentialMeta::new("lab", CredentialKind::Password, None).expect("meta");
        s.create_credential(&v, &meta, b"test-persisted", None).expect("cred");
        meta.id
    };

    // "Restart": header from disk, vault locked, store reopened.
    let mut v = Vault::from_header_bytes(&std::fs::read(&header_path).expect("r")).expect("parse");
    assert_eq!(v.header().version, mooring_vault::FORMAT_VERSION);
    assert_eq!(v.state(), VaultState::Locked);
    let s = Store::open(&db).expect("reopen");
    assert_eq!(s.vault_id().expect("id"), Some(v.header().vault_id.to_string()));
    s.set_vault_id(&v.header().vault_id.to_string()).expect("same vault is idempotent");
    assert!(matches!(
        s.open_credential_secret(&v, cred, SecretField::Secret),
        Err(StoreError::Vault(VaultError::Locked))
    ));
    v.unlock(&pw(MASTER)).expect("unlock");
    assert_eq!(
        s.open_credential_secret(&v, cred, SecretField::Secret).expect("open").as_slice(),
        b"test-persisted"
    );

    // A different vault: the store refuses the binding and cannot read the secrets.
    let other = new_vault();
    assert_ne!(other.vault_id(), v.vault_id());
    assert!(matches!(
        s.set_vault_id(&other.header().vault_id.to_string()),
        Err(StoreError::VaultIdMismatch)
    ));
    assert_eq!(s.vault_id().expect("id"), Some(v.vault_id().to_string()), "binding unchanged");
    assert!(matches!(
        s.open_credential_secret(&other, cred, SecretField::Secret),
        Err(StoreError::Vault(VaultError::Tampered))
    ));
}

#[test]
fn password_change_keeps_store_secrets_readable() {
    let mut v = new_vault();
    let s = Store::open_in_memory().expect("store");
    let meta = CredentialMeta::new("c", CredentialKind::Certificate, None).expect("meta");
    s.create_credential(&v, &meta, b"test-cert", Some(b"test-cert-key")).expect("cred");

    v.change_password(&pw(MASTER), &pw("a brand new master pw"), KdfParams::TEST).expect("chg");
    let mut reloaded = Vault::from_header_bytes(&v.header().to_bytes().expect("b")).expect("p");
    assert_eq!(reloaded.unlock(&pw(MASTER)), Err(VaultError::Unlock));
    reloaded.unlock(&pw("a brand new master pw")).expect("unlock new");
    assert_eq!(reloaded.vault_id(), v.vault_id(), "vault_id survives a password change");
    assert_eq!(
        s.open_credential_secret(&reloaded, meta.id, SecretField::Secret2).expect("o").as_slice(),
        b"test-cert-key"
    );
}

#[test]
fn keyring_unlock_opens_store_secrets() {
    let keyring = MemoryWrapKeyStore::new();
    let mut v = new_vault();
    let s = Store::open_in_memory().expect("store");
    let meta = CredentialMeta::new("k", CredentialKind::Password, None).expect("meta");
    s.create_credential(&v, &meta, b"test-keyring-path", None).expect("cred");
    v.enable_keyring_unlock(&keyring, &pw(MASTER)).expect("enable");

    let mut reloaded = Vault::from_header_bytes(&v.header().to_bytes().expect("b")).expect("p");
    reloaded.unlock_with_keyring(&keyring).expect("keyring unlock");
    assert_eq!(
        s.open_credential_secret(&reloaded, meta.id, SecretField::Secret).expect("o").as_slice(),
        b"test-keyring-path"
    );

    // A password change drops the wrap: keyring unlock must fail, password still works.
    reloaded
        .change_password(&pw(MASTER), &pw("rotated master password"), KdfParams::TEST)
        .expect("change");
    let mut after = Vault::from_header_bytes(&reloaded.header().to_bytes().expect("b")).expect("p");
    assert_eq!(after.unlock_with_keyring(&keyring), Err(VaultError::KeyringUnavailable));
    after.unlock(&pw("rotated master password")).expect("unlock");
}

/// Export the store's sealed columns (read raw, as the export command would) and import them
/// into a fresh process: the fields still open under the imported header.
#[test]
fn export_import_of_store_credentials_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("mooring.db");
    let v = new_vault();
    let s = Store::open(&db).expect("store");
    let meta = CredentialMeta::new("e", CredentialKind::SshKey, None).expect("meta");
    s.create_credential(&v, &meta, b"test-export-key", Some(b"test-export-pp")).expect("cred");
    drop(s);

    let raw = rusqlite::Connection::open(&db).expect("raw");
    let (secret, secret2): (Vec<u8>, Vec<u8>) = raw
        .query_row(
            "SELECT secret, secret2 FROM credential WHERE id = ?1",
            [meta.id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("row");
    let mut fields = BTreeMap::new();
    fields.insert("secret".to_owned(), serde_json::from_slice::<Sealed>(&secret).expect("json"));
    fields.insert("secret2".to_owned(), serde_json::from_slice::<Sealed>(&secret2).expect("json"));
    let doc = ExportDocument {
        header: v.header().clone(),
        credentials: vec![ExportedRecord { record_id: meta.id.to_string(), fields }],
        folders: serde_json::json!([]),
        connections: serde_json::json!([]),
    };

    let passphrase = pw("separate export passphrase");
    let file = export_age(&doc, &passphrase).expect("export");
    assert!(!String::from_utf8_lossy(&file).contains("test-export"));
    let back = import_age(&file, &passphrase).expect("import");
    assert_eq!(back, doc);

    let mut restored = Vault::from_header(back.header.clone());
    restored.unlock(&pw(MASTER)).expect("unlock imported header");
    let rec = &back.credentials[0];
    let opened = restored.open(&rec.record_id, "secret2", &rec.fields["secret2"]).expect("open");
    assert_eq!(opened.as_slice(), b"test-export-pp");
    // the master password is not the export passphrase
    assert!(import_age(&file, &pw(MASTER)).is_err());
}

/// Regression for A1-QA-2: a v1 vault header reports `vault_id = nil` until its first
/// password unlock upgrades it to v2 with a fresh random id (`Vault::unlock`). If the app
/// bound the store before that unlock, the store would be pinned to nil and every later bind
/// with the real id would fail with `VaultIdMismatch`. Nil is refused as `Invalid`.
#[test]
fn nil_vault_id_is_refused() {
    let s = Store::open_in_memory().expect("store");
    assert!(matches!(
        s.set_vault_id(&mooring_vault::Uuid::nil().to_string()),
        Err(StoreError::Invalid { .. })
    ));
    assert_eq!(s.vault_id().expect("id"), None);
}
