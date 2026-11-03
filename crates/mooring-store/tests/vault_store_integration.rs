//! Cross-crate integration: `mooring-vault` lifecycle driving `mooring-store` sealed columns
//! (ADR-0005 + ADR-0006). Every secret is a synthetic test string.

use std::collections::BTreeMap;

use mooring_core::{Connection, Protocol};
use mooring_store::{CredentialKind, CredentialMeta, SecretName, Secrets, Store, StoreError};
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

fn pw_cred(s: &Store, v: &Vault, name: &str, user: &str, secret: &[u8]) -> CredentialMeta {
    let sec: Secrets<'_> = [(SecretName::Password, secret)].into_iter().collect();
    s.create_credential(
        v,
        name,
        CredentialKind::UserPassword,
        &serde_json::json!({"username": user}),
        &sec,
    )
    .expect("password credential")
}

fn key_cred(s: &Store, v: &Vault, name: &str, pp: &[u8]) -> CredentialMeta {
    let pem = mooring_core::credential::testdata::placeholder_key_pem();
    let sec: Secrets<'_> = [(SecretName::PrivateKey, pem.as_bytes()), (SecretName::Passphrase, pp)]
        .into_iter()
        .collect();
    s.create_credential(
        v,
        name,
        CredentialKind::SshKey,
        &serde_json::json!({"username": "root"}),
        &sec,
    )
    .expect("ssh key credential")
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

    let pw_meta = pw_cred(&s, &v, "ops pw", "ops", b"test-ops-password");
    let key_meta = key_cred(&s, &v, "ops key", b"test-key-passphrase");

    s.set_folder_default_credential(root.id, Some(pw_meta.id)).expect("root default");
    let inherited = s.create_connection(&ssh(servers.id, "web01", "192.0.2.5")).expect("c1");
    let mut own = ssh(servers.id, "mon01", "192.0.2.30");
    own.credential = Some(key_meta.id);
    let own = s.create_connection(&own).expect("c2");

    assert_eq!(s.effective_credential(inherited.id).expect("eff"), Some(pw_meta.id));
    assert_eq!(s.effective_credential(own.id).expect("eff"), Some(key_meta.id));

    let open = |v: &Vault, id, f| s.open_secret(v, id, f);
    let eff = s.effective_credential(inherited.id).expect("eff").expect("some");
    assert_eq!(open(&v, eff, SecretName::Password).expect("open").as_slice(), b"test-ops-password");

    // Lock: metadata and resolution still work, secrets do not.
    v.lock();
    assert_eq!(v.state(), VaultState::Locked);
    assert_eq!(s.effective_credential(own.id).expect("eff while locked"), Some(key_meta.id));
    assert_eq!(s.list_credentials().expect("meta while locked").len(), 2);
    for (id, f) in [
        (pw_meta.id, SecretName::Password),
        (key_meta.id, SecretName::PrivateKey),
        (key_meta.id, SecretName::Passphrase),
    ] {
        assert!(matches!(open(&v, id, f), Err(StoreError::Vault(VaultError::Locked))));
    }
    assert!(matches!(
        s.replace_secrets(
            &v,
            pw_meta.id,
            &[(SecretName::Password, &b"x"[..])].into_iter().collect(),
            &[]
        ),
        Err(StoreError::Vault(VaultError::Locked))
    ));

    // Wrong password keeps it locked; the right one restores access.
    assert_eq!(v.unlock(&pw("not the master password")), Err(VaultError::Unlock));
    assert_eq!(v.state(), VaultState::Locked);
    v.unlock(&pw(MASTER)).expect("unlock");
    assert_eq!(
        open(&v, key_meta.id, SecretName::Passphrase).expect("open").as_slice(),
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
        pw_cred(&s, &v, "lab", "ops", b"test-persisted").id
    };

    // "Restart": header from disk, vault locked, store reopened.
    let mut v = Vault::from_header_bytes(&std::fs::read(&header_path).expect("r")).expect("parse");
    assert_eq!(v.header().version, mooring_vault::FORMAT_VERSION);
    assert_eq!(v.state(), VaultState::Locked);
    let s = Store::open(&db).expect("reopen");
    assert_eq!(s.vault_id().expect("id"), Some(v.header().vault_id.to_string()));
    s.set_vault_id(&v.header().vault_id.to_string()).expect("same vault is idempotent");
    assert!(matches!(
        s.open_secret(&v, cred, SecretName::Password),
        Err(StoreError::Vault(VaultError::Locked))
    ));
    v.unlock(&pw(MASTER)).expect("unlock");
    assert_eq!(
        s.open_secret(&v, cred, SecretName::Password).expect("open").as_slice(),
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
        s.open_secret(&other, cred, SecretName::Password),
        Err(StoreError::Vault(VaultError::Tampered))
    ));
}

#[test]
fn password_change_keeps_store_secrets_readable() {
    let mut v = new_vault();
    let s = Store::open_in_memory().expect("store");
    let meta = key_cred(&s, &v, "c", b"test-cert-key");

    v.change_password(&pw(MASTER), &pw("a brand new master pw"), KdfParams::TEST).expect("chg");
    let mut reloaded = Vault::from_header_bytes(&v.header().to_bytes().expect("b")).expect("p");
    assert_eq!(reloaded.unlock(&pw(MASTER)), Err(VaultError::Unlock));
    reloaded.unlock(&pw("a brand new master pw")).expect("unlock new");
    assert_eq!(reloaded.vault_id(), v.vault_id(), "vault_id survives a password change");
    assert_eq!(
        s.open_secret(&reloaded, meta.id, SecretName::Passphrase).expect("o").as_slice(),
        b"test-cert-key"
    );
}

#[test]
fn keyring_unlock_opens_store_secrets() {
    let keyring = MemoryWrapKeyStore::new();
    let mut v = new_vault();
    let s = Store::open_in_memory().expect("store");
    let meta = pw_cred(&s, &v, "k", "ops", b"test-keyring-path");
    v.enable_keyring_unlock(&keyring, &pw(MASTER)).expect("enable");

    let mut reloaded = Vault::from_header_bytes(&v.header().to_bytes().expect("b")).expect("p");
    reloaded.unlock_with_keyring(&keyring).expect("keyring unlock");
    assert_eq!(
        s.open_secret(&reloaded, meta.id, SecretName::Password).expect("o").as_slice(),
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
    let meta = key_cred(&s, &v, "e", b"test-export-pp");
    drop(s);

    let raw = rusqlite::Connection::open(&db).expect("raw");
    let mut fields = BTreeMap::new();
    let mut stmt = raw
        .prepare("SELECT name, sealed FROM credential_secret WHERE credential_id = ?1")
        .expect("stmt");
    let rows = stmt
        .query_map([meta.id.to_string()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .expect("rows");
    for row in rows {
        let (name, blob) = row.expect("row");
        fields.insert(name, serde_json::from_slice::<Sealed>(&blob).expect("json"));
    }
    assert_eq!(fields.len(), 2);
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
    let opened =
        restored.open(&rec.record_id, "passphrase", &rec.fields["passphrase"]).expect("open");
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
