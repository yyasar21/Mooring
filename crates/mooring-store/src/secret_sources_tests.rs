use mooring_core::credential::testdata::CERT_PEM;
use mooring_core::secret_source::OIDC_REDIRECT_URI;
use mooring_core::SecretName;
use mooring_vault::{KdfParams, Vault};
use rusqlite::Connection as Raw;
use secrecy::SecretString;
use serde_json::json;

use super::*;
use crate::schema;

fn vault() -> Vault {
    Vault::create(&SecretString::from("test-only master pw".to_owned()), KdfParams::TEST)
        .expect("vault")
}

fn token_cred(s: &Store, v: &Vault) -> CredentialId {
    let secrets = [(SecretName::Token, &b"test-only-token"[..])].into_iter().collect();
    s.create_credential(v, "vault token", CredentialKind::ApiToken, &json!({}), &secrets)
        .expect("token")
        .id
}

fn approle_cred(s: &Store, v: &Vault) -> CredentialId {
    let secrets =
        [(SecretName::RoleId, &b"test-role"[..]), (SecretName::SecretId, &b"test-secret"[..])]
            .into_iter()
            .collect();
    s.create_credential(v, "ci approle", CredentialKind::VaultApprole, &json!({}), &secrets)
        .expect("approle")
        .id
}

fn input(v: serde_json::Value) -> SecretSourceInput {
    serde_json::from_value(v).expect("input shape")
}

fn ext_ref(s: &Store, v: &Vault, source: SecretSourceId) -> CredentialId {
    let fields = json!({"provider": "vault", "reference": "secret/db", "target_kind": "user_password",
                        "source": source});
    s.create_credential(v, "db", CredentialKind::ExternalRef, &fields, &crate::Secrets::new())
        .expect("external_ref")
        .id
}

#[test]
fn crud_round_trip_holds_no_secret_material() {
    let (s, v) = (Store::open_in_memory().expect("open"), vault());
    let cred = token_cred(&s, &v);
    let created = s
        .create_secret_source(&input(json!({
            "name": "Vault", "address": "https://vault.example.test:8200/", "namespace": "team",
            "authMethod": "token", "credentialId": cred, "options": {"caPem": CERT_PEM}})))
        .expect("create");
    assert_eq!(created.address, "https://vault.example.test:8200");
    assert_eq!(created.auth, SecretSourceAuth::Token { credential_id: cred });
    assert_eq!(s.get_secret_source(created.id).expect("get"), created);
    assert_eq!(s.list_secret_sources().expect("list"), std::slice::from_ref(&created));

    let row: String = s
        .conn
        .query_row(
            "SELECT name || address || coalesce(namespace,'') || auth_method || auth_mount ||
                    coalesce(credential_id,'') || options_json FROM secret_source",
            [],
            |r| r.get(0),
        )
        .expect("row");
    assert!(!row.contains("test-only-token"), "no secret in the table");

    let approle = approle_cred(&s, &v);
    let (updated, changed) = s
        .update_secret_source(
            created.id,
            &input(json!({"name": "Vault", "address": "https://vault.example.test:8200",
                          "namespace": "team", "authMethod": "approle", "authMount": "ci",
                          "credentialId": approle, "options": {}})),
        )
        .expect("update");
    assert_eq!(
        updated.auth,
        SecretSourceAuth::AppRole { mount: "ci".into(), credential_id: approle }
    );
    assert_eq!(changed, ["auth", "caPem"]);
    assert_eq!(updated.created_at, created.created_at);

    s.delete_secret_source(created.id).expect("delete");
    assert!(matches!(s.get_secret_source(created.id), Err(StoreError::NotFound { .. })));
    assert!(matches!(s.delete_secret_source(created.id), Err(StoreError::NotFound { .. })));
}

#[test]
fn login_credential_kind_is_checked() {
    let (s, v) = (Store::open_in_memory().expect("open"), vault());
    let token = token_cred(&s, &v);
    let approle = approle_cred(&s, &v);
    let pw = [(SecretName::Password, &b"pw"[..])].into_iter().collect();
    let up = s
        .create_credential(&v, "up", CredentialKind::UserPassword, &json!({"username": "u"}), &pw)
        .expect("up")
        .id;
    let src = |method: &str, cred: CredentialId| {
        s.create_secret_source(&input(json!({"name": "x", "address": "https://v.example.test",
                                            "authMethod": method, "credentialId": cred})))
    };
    assert!(src("token", token).is_ok());
    assert!(src("approle", approle).is_ok());
    assert!(matches!(
        src("token", approle),
        Err(StoreError::Invalid { field: "credentialId", .. })
    ));
    assert!(matches!(
        src("approle", token),
        Err(StoreError::Invalid { field: "credentialId", .. })
    ));
    assert!(matches!(src("token", up), Err(StoreError::Credential(_))), "not a source consumer");
    assert!(matches!(src("token", CredentialId::new()), Err(StoreError::NotFound { .. })));
    let oidc = s
        .create_secret_source(&input(json!({"name": "sso", "address": "https://v.example.test",
                                            "authMethod": "oidc", "oidcRole": "mooring"})))
        .expect("oidc");
    assert_eq!(oidc.auth.credential_id(), None);
    assert!(OIDC_REDIRECT_URI.starts_with("http://localhost:"));
}

#[test]
fn in_use_rules() {
    let (s, v) = (Store::open_in_memory().expect("open"), vault());
    let token = token_cred(&s, &v);
    let src = s
        .create_secret_source(&input(json!({"name": "x", "address": "https://v.example.test",
                                            "authMethod": "token", "credentialId": token})))
        .expect("src");
    assert!(matches!(
        s.delete_credential(token),
        Err(StoreError::InUse { kind: "credential", .. })
    ));
    let r = ext_ref(&s, &v, src.id);
    assert_eq!(s.external_refs_of(src.id).expect("refs"), [r]);
    let meta = s.get_credential(r).expect("ref");
    assert_eq!(s.source_of(&meta.fields).expect("source").map(|x| x.id), Some(src.id));
    assert!(matches!(
        s.delete_secret_source(src.id),
        Err(StoreError::InUse { kind: "secret_source", .. })
    ));
    s.delete_credential(r).expect("drop the reference");
    s.delete_secret_source(src.id).expect("now free");
    s.delete_credential(token).expect("token free");
}

#[test]
fn a_corrupt_row_is_refused() {
    let s = Store::open_in_memory().expect("open");
    let id = SecretSourceId::new();
    s.conn
        .execute(
            "INSERT INTO secret_source (id, name, kind, address, auth_method, auth_mount, oidc_role,
                                        created_at, updated_at)
             VALUES (?1, 'x', 'vault', 'http://vault.example.test', 'oidc', 'oidc', 'r',
                     '2026-11-04T10:00:00Z', '2026-11-04T10:00:00Z')",
            [id.to_string()],
        )
        .expect("raw insert");
    assert!(matches!(s.get_secret_source(id), Err(StoreError::Corrupt { .. })));
    assert!(
        s.conn
            .execute(
                "INSERT INTO secret_source (id, name, kind, address, auth_method, auth_mount,
                                        created_at, updated_at)
             VALUES ('y', 'x', 'vault', 'https://v.example.test', 'oidc', 'oidc', 't', 't')",
                [],
            )
            .is_err(),
        "oidc needs a role (CHECK)"
    );
}

const UP_TO_V5: [&str; 5] = [
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_fts_secure_delete.sql"),
    include_str!("../migrations/0003_typed_credentials.sql"),
    include_str!("../migrations/0004_migrated_username.sql"),
    include_str!("../migrations/0005_connection_options.sql"),
];

#[test]
fn migration_0007_upgrades_a_v5_database_and_keeps_links() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let v = vault();
    let (cred, conn_id) = (CredentialId::new(), mooring_core::ConnectionId::new());
    let folder = mooring_core::FolderId::new();
    {
        let raw = Raw::open(&path).expect("raw");
        for sql in UP_TO_V5 {
            raw.execute_batch(sql).expect("v1..v5");
        }
        let ts = "2026-11-01T10:00:00Z";
        raw.execute_batch(&format!(
            "INSERT INTO setting (key, value) VALUES ('schema_version', '5');
             INSERT INTO credential (id, name, kind, fields_json, created_at, updated_at)
             VALUES ('{cred}', 'tok', 'api_token', '{{}}', '{ts}', '{ts}');
             INSERT INTO folder (id, parent_id, name, default_credential_id, created_at, updated_at)
             VALUES ('{folder}', NULL, 'root', '{cred}', '{ts}', '{ts}');
             INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id,
                                     created_at, updated_at)
             VALUES ('{conn_id}', '{folder}', 'web', 'web', 'https://w.example.test', NULL,
                     '{cred}', '{ts}', '{ts}');"
        ))
        .expect("v5 rows");
        let blob = crate::credentials::seal(&v, cred, "token", b"test-only-token").expect("seal");
        crate::credentials::put_secret(&raw, cred, "token", &blob).expect("secret");
    }
    let s = Store::open(&path).expect("migrates");
    assert_eq!(s.schema_version().expect("v"), schema::LATEST);
    assert_eq!(s.get_credential(cred).expect("kept").kind, CredentialKind::ApiToken);
    assert_eq!(s.get_connection(conn_id).expect("conn").credential, Some(cred));
    assert_eq!(s.get_folder(folder).expect("folder").default_credential, Some(cred));
    assert_eq!(
        s.open_secret(&v, cred, SecretName::Token).expect("secret").as_slice(),
        b"test-only-token"
    );
    approle_cred(&s, &v);
    let fk: bool = s.conn.pragma_query_value(None, "foreign_keys", |r| r.get(0)).expect("fk");
    assert!(fk);
}

/// ADR-0026: 1Password Connect and Bitwarden sources round-trip, check their login kind and
/// keep their kind on update.
#[test]
fn onepassword_and_bitwarden_sources_round_trip() {
    use mooring_core::secret_source::SourceKind;
    let (s, v) = (Store::open_in_memory().expect("open"), vault());
    let api = token_cred(&s, &v);
    let secrets = [(SecretName::AccessToken, &b"0.test-only.machine"[..])].into_iter().collect();
    let bwt = s
        .create_credential(&v, "bws", CredentialKind::BitwardenAccessToken, &json!({}), &secrets)
        .expect("bws")
        .id;
    let op = |cred: mooring_core::CredentialId| {
        input(
            json!({"kind": "onepassword", "name": "Connect", "address": "https://connect.example.test:8080",
                     "authMethod": "token", "credentialId": cred}),
        )
    };
    let src = s.create_secret_source(&op(api)).expect("connect");
    assert_eq!(s.get_secret_source(src.id).expect("get").kind, SourceKind::Onepassword);
    assert!(s.create_secret_source(&op(bwt)).is_err(), "Connect logs in with an api_token");
    let bw = |cred: mooring_core::CredentialId| {
        input(json!({"kind": "bitwarden", "name": "SM", "address": "https://bw.example.test",
                     "authMethod": "token", "credentialId": cred,
                     "options": {"bwsPath": "/usr/local/bin/bws"}}))
    };
    assert!(s.create_secret_source(&bw(api)).is_err(), "bws needs a bitwarden_access_token");
    let b = s.create_secret_source(&bw(bwt)).expect("bitwarden");
    let got = s.get_secret_source(b.id).expect("get");
    assert_eq!(
        (got.kind, got.options.bws_path.as_deref()),
        (SourceKind::Bitwarden, Some("/usr/local/bin/bws"))
    );
    let e = s.update_secret_source(src.id, &bw(bwt)).expect_err("kind is fixed");
    assert!(e.to_string().contains("kind"), "{e}");
    let mut moved = bw(bwt);
    moved.options.bws_path = Some("/opt/homebrew/bin/bws".into());
    let (_, changed) = s.update_secret_source(b.id, &moved).expect("update");
    assert_eq!(changed, ["bwsPath"]);
}
