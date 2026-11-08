//! ADR-0026 at connect, through the real plan and the command layer: a database lease owned
//! by the session (a reconnect revokes the old lease first, lock revokes all), the SSH
//! `certificate` role signing the key credential's public key, SSH OTP, and 1Password /
//! Bitwarden sources created through the commands.

use mooring_core::credential::testdata as td;
use mooring_core::session::{ConnectSecret, Size};
use mooring_testsrv::vault::{DynamicConfig, VaultConfig};
use secrecy::ExposeSecret as _;
use serde_json::json;

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::{secret_sources as cmd, tree, vault};
use crate::state::testing::unlocked;
use crate::state::AppState;
use crate::test_secrets::{self as fx, audit_rows};

const SIZE: Size = Size { width: 80, height: 24 };

fn credential(st: &AppState, kind: &str, fields: serde_json::Value, secrets: &[(&str, &str)]) -> String {
    let c = NewCredential {
        name: kind.to_owned(),
        kind: kind.to_owned(),
        fields,
        secrets: WireSecrets::of(secrets),
    };
    credentials::create(st, c).expect("credential").id
}

fn ssh_connection(st: &AppState, host: &str, credential: Option<String>) -> String {
    let root = st.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let mut fields = tree::ConnectionFields::basic(&root, "box", "ssh", host);
    fields.credential_id = credential;
    tree::create_connection(st, fields).expect("connection").id
}

fn dynamic_ref(st: &AppState, source: &str, fields: serde_json::Value) -> String {
    let mut f = json!({ "provider": "vault", "source": source });
    for (k, v) in fields.as_object().expect("obj") {
        f[k] = v.clone();
    }
    credential(st, "external_ref", f, &[])
}

#[tokio::test]
async fn database_lease_belongs_to_the_session() {
    let v = fx::start(VaultConfig { dynamic: DynamicConfig::default(), ..VaultConfig::default() }).await;
    let f = unlocked();
    let st = &f.state;
    let src = fx::token_source(st, &v, "hvs.test-token");
    let db = dynamic_ref(st, &src.id, json!({"reference": "database/app-ro", "engine": "database",
                                                 "target_kind": "user_password"}));
    let conn = ssh_connection(st, "db.example.test", Some(db));
    let plan = super::plan(&st.ready(), &conn, SIZE, "sess-1").await.expect("plan");
    let ConnectSecret::Password(pw) = &plan.params.secret else { panic!("password") };
    assert!(pw.expose_secret().starts_with("A1a-"));
    assert!(plan.params.username.as_deref().is_some_and(|u| u.starts_with("v-mooring-")));
    let status = st.secrets.lease_status("sess-1");
    assert_eq!((status.len(), status[0].state), (1, "active"));
    // The wire row carries the full TTL next to the time left (U4 "renews in").
    let wire = serde_json::to_value(crate::commands::sessions::LeaseInfoDto::from(&status[0]))
        .expect("json");
    assert_eq!(wire["ttlSeconds"], 3600);
    assert!(wire["expiresInSeconds"].as_u64().is_some_and(|s| s <= 3600));
    assert_eq!(v.srv.live_leases(), 1);
    // A reconnect resolves a new lease and revokes the old one first.
    super::plan(&st.ready(), &conn, SIZE, "sess-1").await.expect("reconnect");
    assert_eq!((v.srv.live_leases(), st.secrets.lease_status("sess-1").len()), (1, 1));
    assert!(audit_rows(st, "secret_lease_revoked").iter().any(|r| r["reason"] == "reconnect"));
    st.secrets.release_session("sess-1", "closed");
    st.secrets.flush().await;
    assert_eq!(v.srv.live_leases(), 0, "session end revokes");
    super::plan(&st.ready(), &conn, SIZE, "sess-2").await.expect("again");
    vault::lock(st, Some("user")).expect("lock");
    st.secrets.flush().await;
    assert_eq!(v.srv.live_leases(), 0, "lock revokes");
    assert!(audit_rows(st, "secret_lease_revoked").iter().any(|r| r["reason"] == "locked"));
    let resolved = audit_rows(st, "secret_resolved");
    assert_eq!((resolved[0]["engine"].clone(), resolved[0]["provider"].clone()), (json!("database"), json!("vault")));
    for row in audit_rows(st, "secret_lease_issued") {
        assert!(!row.to_string().contains("database/creds/app-ro/"), "no lease id in the audit: {row}");
    }
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn certificate_role_signs_the_key_credentials_public_key() {
    let dynamic = DynamicConfig { ssh_signed_key: td::SSH_CA_CERT.to_owned(), ..DynamicConfig::default() };
    let v = fx::start(VaultConfig { dynamic, ..VaultConfig::default() }).await;
    let f = unlocked();
    let st = &f.state;
    let src = fx::token_source(st, &v, "hvs.test-token");
    let pem = td::placeholder_key_pem();
    let key = credential(st, "ssh_key", json!({"username": "deploy", "public_key": td::SSH_CA_SUBJECT_PUB}),
                         &[("private_key", &pem)]);
    let sign = dynamic_ref(st, &src.id, json!({"reference": "ssh/deploy", "engine": "ssh_sign",
                                                   "target_kind": "ssh_key", "principals": ["deploy"]}));
    let conn = ssh_connection(st, "box.example.test", Some(key.clone()));
    tree::set_role_credential(st, &conn, "certificate", Some(&sign)).expect("certificate role");
    let plan = super::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    let ConnectSecret::PrivateKey { certificate, .. } = &plan.params.secret else { panic!("key") };
    assert_eq!(certificate.as_deref(), Some(td::SSH_CA_CERT));
    assert!(plan.used.contains(&sign));
    assert_eq!(v.srv.sign_requests()[0]["public_key"], td::SSH_CA_SUBJECT_PUB);
    v.srv.set_dynamic(DynamicConfig { ssh_signed_key: td::SSH_CA_CERT_OTHER_KEY.to_owned(), ..DynamicConfig::default() });
    let e = super::plan(&st.ready(), &conn, SIZE, "s").await.expect_err("wrong key");
    assert_eq!(e.code, "credential.external_shape");
    // The role needs a key as sign-in credential, and the reference is no login of its own.
    let pw = credential(st, "user_password", json!({"username": "u"}), &[("password", "p")]);
    let other = ssh_connection(st, "pw.example.test", Some(pw));
    tree::set_role_credential(st, &other, "certificate", Some(&sign)).expect("role");
    let e = super::plan(&st.ready(), &other, SIZE, "s").await.expect_err("no key");
    assert_eq!(e.code, "credential.external_engine");
    let root = st.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let mut fields = tree::ConnectionFields::basic(&root, "bad", "ssh", "x.example.test");
    fields.credential_id = Some(sign);
    assert_eq!(tree::create_connection(st, fields).expect_err("modifier").code, "credential.incompatible");
}

#[tokio::test]
async fn ssh_otp_uses_the_target_address() {
    let v = fx::start(VaultConfig::default()).await;
    let f = unlocked();
    let st = &f.state;
    let src = fx::token_source(st, &v, "hvs.test-token");
    let otp = dynamic_ref(st, &src.id, json!({"reference": "ssh/otp", "engine": "ssh_otp",
                                                  "target_kind": "user_password", "username": "deploy"}));
    let conn = ssh_connection(st, "192.0.2.15", Some(otp));
    let plan = super::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    assert_eq!(plan.params.username.as_deref(), Some("deploy"));
    assert!(st.secrets.lease_status("s").is_empty(), "an OTP leaves no lease");
    let req = v.srv.recorder().requests();
    assert!(req.iter().any(|r| r.line().contains("/v1/ssh/creds/otp")), "issued");
}

#[tokio::test]
async fn connect_and_bitwarden_sources_through_the_commands() {
    let f = unlocked();
    let st = &f.state;
    let api = credential(st, "api_token", json!({}), &[("token", "t")]);
    let bwt = credential(st, "bitwarden_access_token", json!({}), &[("access_token", "0.test-only")]);
    let op = cmd::create(st, &json!({"kind": "onepassword", "name": "Connect", "address": "https://connect.example.test:8080",
                                     "authMethod": "token", "credentialId": api})).expect("connect");
    assert_eq!(op.kind, "onepassword");
    let bw = json!({"kind": "bitwarden", "name": "SM", "address": "https://bw.example.test",
                    "authMethod": "token", "credentialId": bwt, "options": {"bwsPath": "/usr/local/bin/bws"}});
    let b = cmd::create(st, &bw).expect("bitwarden");
    assert_eq!((b.kind, b.options.bws_path.as_deref()), ("bitwarden", Some("/usr/local/bin/bws")));
    let changed = audit_rows(st, "secret_source_changed");
    assert!(changed.last().is_some_and(|r| r["warning"] == true), "a bws path is a trust decision");
    let mut wrong = bw.clone();
    wrong["credentialId"] = json!(api);
    assert_eq!(cmd::create(st, &wrong).expect_err("kind").code, "input.invalid");
    wrong["credentialId"] = json!(bwt);
    wrong["options"] = json!({"bwsPath": "/tmp/bws"});
    assert_eq!(cmd::create(st, &wrong).expect_err("path").code, "input.invalid");
    // An update without `kind` (the A3 payload) keeps the stored kind.
    let upd = json!({"name": "Connect 2", "address": "https://connect.example.test:8080", "authMethod": "token",
                     "credentialId": api});
    assert_eq!(cmd::update(st, &op.id, &upd).await.expect("update").kind, "onepassword");
}
