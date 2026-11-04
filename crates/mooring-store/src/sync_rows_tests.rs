use mooring_core::{Connection, Protocol, Role, SecretName};
use mooring_vault::{KdfParams, Vault};
use secrecy::SecretString;

use crate::{CredentialKind, Store, StoreError};

fn vault() -> Vault {
    Vault::create(&SecretString::from("test-only master pw".to_owned()), KdfParams::TEST)
        .expect("vault")
}

fn populated(v: &Vault) -> Store {
    let s = Store::open_in_memory().expect("open");
    let root = s.create_folder(None, "Root").expect("root");
    let sub = s.create_folder(Some(root.id), "servers").expect("sub");
    let secrets: crate::Secrets<'_> =
        [(SecretName::Password, b"test-secret".as_slice())].into_iter().collect();
    let cred = s
        .create_credential(
            v,
            "ops",
            CredentialKind::UserPassword,
            &serde_json::json!({ "username": "ops" }),
            &secrets,
        )
        .expect("cred");
    let mut c = Connection::new(sub.id, "web", Protocol::Rdp, "web.example.test").expect("conn");
    c.tags = vec!["prod".to_owned(), "a".to_owned()];
    c.credential = Some(cred.id);
    let c = s.create_connection(&c).expect("insert");
    s.set_connection_role_credential(c.id, Role::Gateway, Some(cred.id)).expect("role");
    s
}

#[test]
fn rows_round_trip_into_another_store_and_secrets_still_open() {
    let v = vault();
    let a = populated(&v);
    let rows = a.export_sync_rows().expect("export");
    assert_eq!((rows.folders.len(), rows.connections.len(), rows.credentials.len()), (2, 1, 1));
    let conn = rows.connections.values().next().expect("conn");
    assert_eq!(conn.tags, ["a", "prod"]);
    assert_eq!(conn.roles.keys().collect::<Vec<_>>(), ["gateway"]);

    let b = Store::open_in_memory().expect("open b");
    b.replace_sync_rows(&rows).expect("replace");
    assert_eq!(b.export_sync_rows().expect("export b"), rows);
    let cred = b.list_credentials().expect("list")[0].id;
    let pw = b.open_secret(&v, cred, SecretName::Password).expect("open");
    assert_eq!(pw.as_slice(), b"test-secret");
    assert_eq!(b.search("web", 10).expect("search").len(), 1, "FTS triggers ran");

    b.replace_sync_rows(&crate::SyncRows::default()).expect("empty");
    assert!(b.list_folders().expect("folders").is_empty());
    assert!(b.search("web", 10).expect("search").is_empty());
}

#[test]
fn invalid_rows_are_refused_and_nothing_changes() {
    let v = vault();
    let a = populated(&v);
    let good = a.export_sync_rows().expect("export");
    let mut bad = good.clone();
    bad.connections.values_mut().for_each(|c| c.protocol = "telnet".to_owned());
    assert!(a.replace_sync_rows(&bad).is_err());
    let mut dangling = good.clone();
    dangling.connections.values_mut().for_each(|c| {
        c.folder_id = uuid::Uuid::new_v4().to_string();
    });
    assert!(matches!(a.replace_sync_rows(&dangling), Err(StoreError::Sqlite(_))), "FK at commit");
    let mut kind = good.clone();
    kind.credentials.values_mut().for_each(|c| c.kind = "nope".to_owned());
    assert!(a.replace_sync_rows(&kind).is_err());
    assert_eq!(a.export_sync_rows().expect("export"), good, "rolled back");
}

#[test]
fn sync_settings_are_namespaced() {
    let s = Store::open_in_memory().expect("open");
    assert!(s.sync_setting("vault_id").is_err());
    assert!(s.set_sync_setting("app.x", Some("1")).is_err());
    s.set_sync_setting("sync.state", Some("{}")).expect("set");
    assert_eq!(s.sync_setting("sync.state").expect("get").as_deref(), Some("{}"));
    s.set_sync_setting("sync.state", None).expect("delete");
    assert_eq!(s.sync_setting("sync.state").expect("get"), None);
}

/// E1 × S2: `secret_source.credential_id` is `ON DELETE RESTRICT`, which fires immediately even
/// with deferred foreign keys. Applying a snapshot must not delete-and-reinsert a credential a
/// local (unsynced) secret source logs in with, and must keep it when the snapshot lacks it.
#[test]
fn replace_keeps_credentials_of_local_secret_sources() {
    let v = vault();
    let a = populated(&v);
    let secrets: crate::Secrets<'_> =
        [(SecretName::Token, b"test-only-token".as_slice())].into_iter().collect();
    let token = a
        .create_credential(
            &v,
            "vault token",
            CredentialKind::ApiToken,
            &serde_json::json!({}),
            &secrets,
        )
        .expect("token")
        .id;
    let input: mooring_core::secret_source::SecretSourceInput = serde_json::from_value(
        serde_json::json!({"name": "vault", "address": "https://v.example.test",
                           "authMethod": "token", "credentialId": token}),
    )
    .expect("input");
    a.create_secret_source(&input).expect("source");

    let rows = a.export_sync_rows().expect("export");
    a.replace_sync_rows(&rows).expect("re-apply the same rows");
    assert_eq!(a.export_sync_rows().expect("again"), rows);

    let mut without = rows.clone();
    without.credentials.remove(&token.to_string());
    a.replace_sync_rows(&without).expect("apply without the source's credential");
    assert!(a.get_credential(token).is_ok(), "the source's login credential is kept");
    assert_eq!(a.list_secret_sources().expect("sources").len(), 1);
}
