//! ADR-0024 in the app: the plan of an `ssh_sk_key`, the pre-flight codes, the `certificate`
//! role for an sk key, the helper setting and the unlock-time conversion audit.

use mooring_core::credential::testdata as td;
use mooring_core::session::{ConnectSecret, Size};
use mooring_testsrv::vault::{DynamicConfig, VaultConfig};
use serde_json::json;

use super::*;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::tree;
use crate::state::testing::unlocked;
use crate::test_secrets::{self as fx, audit_rows};

const SIZE: Size = Size { width: 80, height: 24 };

fn sk_line() -> String {
    td::public_line(&td::sk_ed25519_public([7; 32], "ssh:"))
}

fn credential(st: &AppState, kind: &str, fields: serde_json::Value, secrets: &[(&str, &str)]) -> String {
    let c = NewCredential { name: kind.to_owned(), kind: kind.to_owned(), fields, secrets: WireSecrets::of(secrets) };
    credentials::create(st, c).expect("credential").id
}

fn ssh_connection(st: &AppState, credential: Option<String>) -> String {
    let root = st.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let mut fields = tree::ConnectionFields::basic(&root, "yk", "ssh", "box.example.test");
    fields.credential_id = credential;
    tree::create_connection(st, fields).expect("connection").id
}

#[tokio::test]
async fn plan_maps_the_kind_and_opens_the_handle_for_the_helper_only() {
    let f = unlocked();
    let st = &f.state;
    let handle = td::sk_key_handle_pem(&td::sk_ed25519_public([7; 32], "ssh:"), 0x21, b"h");
    for (backend, has_handle) in [("agent", false), ("helper", true)] {
        let id = credential(st, "ssh_sk_key", json!({"username": "root", "public_key": sk_line(), "backend": backend}),
                            &[("private_key", &handle)]);
        let meta = credentials::list(st).expect("list").into_iter().find(|c| c.id == id).expect("meta");
        assert_eq!(meta.fields["resident"], json!(true), "from the handle flags");
        let conn = ssh_connection(st, Some(id));
        let plan = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
        let ConnectSecret::SecurityKey(login) = &plan.params.secret else { panic!("security key") };
        assert_eq!(plan.params.username.as_deref(), Some("root"));
        assert_eq!(login.public_key, sk_line());
        assert!(login.fingerprint.starts_with("SHA256:"));
        assert_eq!(login.key_handle.is_some(), has_handle, "{backend}");
    }
}

#[tokio::test]
async fn preflight_refuses_before_any_network_io() {
    let f = unlocked();
    let st = &f.state;
    let id = credential(st, "ssh_sk_key", json!({"username": "root", "public_key": sk_line()}), &[]);
    let conn = ssh_connection(st, Some(id));
    let plan = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    let dir = tempfile::tempdir().expect("dir");
    let nowhere = dir.path().join("no-agent.sock");
    let e = preflight(&[&plan.params], Some(&nowhere), false, None).await.expect_err("no agent");
    assert_eq!(e.code, "ssh.sk_key_not_in_agent");
    let helper_id = credential(st, "ssh_sk_key", json!({"username": "r", "public_key": sk_line(), "backend": "helper"}), &[]);
    let conn = ssh_connection(st, Some(helper_id));
    let plan = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    let e = preflight(&[&plan.params], None, false, None).await.expect_err("off");
    assert_eq!(e.code, "ssh.sk_helper_disabled");
    let e = preflight(&[&plan.params], None, true, None).await.expect_err("missing");
    assert_eq!(e.code, "ssh.sk_helper_missing");
    assert!(preflight(&[&plan.params], None, true, Some(&nowhere)).await.is_ok());
    let pw = credential(st, "user_password", json!({"username": "u"}), &[("password", "p")]);
    let conn = ssh_connection(st, Some(pw));
    let plan = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    assert!(preflight(&[&plan.params], Some(&nowhere), false, None).await.is_ok(), "other kinds pass");
}

#[test]
fn helper_setting_is_off_by_default() {
    let f = unlocked();
    assert!(!helper_setting_on(&f.state));
    assert!(sk_helper(&f.state).is_none());
    f.state.with_ready(|_, s| Ok(s.set_app_setting(KEY_SK_HELPER, "true")?)).expect("on");
    assert!(helper_setting_on(&f.state));
}

#[test]
fn ssh_key_with_sk_material_gets_the_convert_code() {
    let f = unlocked();
    let c = NewCredential {
        name: "yk".into(),
        kind: "ssh_key".into(),
        fields: json!({"username": "u", "public_key": sk_line()}),
        secrets: WireSecrets::default(),
    };
    assert_eq!(credentials::create(&f.state, c).expect_err("refused").code, "credential.use_sk_kind");
}

fn sk_certificate() -> (String, String) {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let ca = russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[6; 32]));
    let key = td::sk_ed25519_public([7; 32], "ssh:");
    let mut b = Builder::new([2; 16], key.key_data().clone(), 0, u64::MAX).expect("builder");
    b.cert_type(CertType::User).expect("type");
    b.valid_principal("root").expect("principal");
    (b.sign(&ca).expect("sign").to_openssh().expect("line"), td::public_line(&key))
}

/// The R3 `certificate` role signs the sk key's public line (`sk-ssh-ed25519-cert-v01`).
#[tokio::test]
async fn certificate_role_signs_the_sk_public_key() {
    let (cert, line) = sk_certificate();
    let dynamic = DynamicConfig { ssh_signed_key: cert.clone(), ..DynamicConfig::default() };
    let v = fx::start(VaultConfig { dynamic, ..VaultConfig::default() }).await;
    let f = unlocked();
    let st = &f.state;
    let src = fx::token_source(st, &v, "hvs.test-token");
    let key = credential(st, "ssh_sk_key", json!({"username": "root", "public_key": line}), &[]);
    let sign = credential(st, "external_ref", json!({"provider": "vault", "source": src.id, "reference": "ssh/deploy",
                                                   "engine": "ssh_sign", "target_kind": "ssh_key",
                                                   "principals": ["deploy"]}), &[]);
    let conn = ssh_connection(st, Some(key));
    tree::set_role_credential(st, &conn, "certificate", Some(&sign)).expect("role");
    let plan = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    let ConnectSecret::SecurityKey(login) = &plan.params.secret else { panic!("security key") };
    assert!(login.certificate.as_deref().is_some_and(|c| c.starts_with("sk-ssh-ed25519-cert-v01@openssh.com ")));
    assert_eq!(v.srv.sign_requests()[0]["public_key"], json!(line));
}

#[test]
fn unlock_converts_and_audits() {
    let f = unlocked();
    convert_on_unlock(&f.state);
    assert!(audit_rows(&f.state, "credential.sk_converted").is_empty(), "nothing to convert");
}

/// ADR-0027 §2: `smart_card` maps to the agent-held PIV key; without a key or an agent it is
/// refused before any network I/O (`ssh.piv_key_not_in_agent`), and RDP is refused by the
/// matrix ("needs Kerberos PKINIT").
#[tokio::test]
async fn smart_card_plan_and_preflight() {
    let f = unlocked();
    let st = &f.state;
    let id = credential(st, "smart_card", json!({"username": "alice", "public_key": td::ED25519_PUB,
                                                "reader_hint": "YubiKey"}), &[]);
    let conn = ssh_connection(st, Some(id));
    let plan = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect("plan");
    let ConnectSecret::SmartCard(card) = &plan.params.secret else { panic!("smart card") };
    assert_eq!((card.fingerprint.as_str(), card.module, card.reader_hint.as_deref()), (td::ED25519_FP, None, Some("YubiKey")));
    assert_eq!(plan.params.username.as_deref(), Some("alice"));
    let dir = tempfile::tempdir().expect("dir");
    let nowhere = dir.path().join("no-agent.sock");
    let e = preflight(&[&plan.params], Some(&nowhere), false, None).await.expect_err("no agent");
    assert_eq!(e.code, "ssh.piv_key_not_in_agent");
    let bare = credential(st, "smart_card", json!({"username": "alice"}), &[]);
    let conn = ssh_connection(st, Some(bare));
    let e = crate::commands::connect_plan::plan(&st.ready(), &conn, SIZE, "s").await.expect_err("no key");
    assert_eq!(e.code, "ssh.piv_key_not_in_agent");
    let reason = mooring_core::credential::incompatibility_reason(
        mooring_core::CredentialKind::SmartCard,
        mooring_core::Protocol::Rdp,
        mooring_core::Role::Primary,
    );
    assert!(reason.is_some_and(|r| r.contains("PKINIT")));
}
