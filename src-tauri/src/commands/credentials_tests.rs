use serde_json::json;

use super::*;
use crate::state::testing::*;
use mooring_core::credential::testdata::{CERT_FP, CERT_PEM, KUBECONFIG};

type Case<'a> = (&'a str, serde_json::Value, Vec<(&'a str, &'a str)>);

fn new(kind: &str, fields: serde_json::Value, secrets: &[(&str, &str)]) -> NewCredential {
    NewCredential { name: "ops".into(), kind: kind.into(), fields, secrets: WireSecrets::of(secrets) }
}

#[test]
fn round_trip_metadata_only() {
    let f = unlocked();
    let c = create(&f.state, new("user_password", json!({"username": " admin "}), &[("password", "test-only pw 1")]))
        .expect("create");
    assert_eq!((c.kind, c.fields["username"].as_str()), ("user_password", Some("admin")));
    assert_eq!(c.secret_names, ["password"]);
    let json = serde_json::to_string(&list(&f.state).expect("list")).expect("json");
    assert!(!json.contains("test-only pw 1"), "no secret outward: {json}");
    let u = update_fields(&f.state, &c.id, "ops2", &json!({"username": "root", "domain": "CORP"})).expect("update");
    assert_eq!((u.name.as_str(), u.fields["domain"].as_str()), ("ops2", Some("CORP")));
    replace_secrets(&f.state, &c.id, &WireSecrets::of(&[("password", "test-only pw 2")]), &[]).expect("re");
    f.state
        .with_ready(|v, s| {
            let got = s.open_secret(v, c.id.parse().expect("id"), SecretName::Password)?;
            assert_eq!(got.as_slice(), b"test-only pw 2");
            Ok(())
        })
        .expect("open");
    delete(&f.state, &c.id).expect("delete");
    assert_eq!(delete(&f.state, &c.id).expect_err("gone").code, "credential.not_found");
}

#[test]
fn every_kind_can_be_created_from_its_schema() {
    let f = unlocked();
    let key = mooring_core::credential::testdata::placeholder_key_pem();
    let cases: Vec<Case<'_>> = vec![
        ("user_password", json!({"username": "u"}), vec![("password", "p")]),
        ("domain_user", json!({"user": "alice", "domain": "CORP", "form": "netbios"}), vec![("password", "p")]),
        ("ssh_key", json!({"username": "u"}), vec![("private_key", &key)]),
        ("ssh_agent", json!({"username": "u"}), vec![]),
        ("x509", json!({"cert_pem": CERT_PEM}), vec![("key_pem", &key)]),
        ("api_token", json!({}), vec![("token", "t")]),
        ("oauth_client", json!({"token_url": "https://id.example.test/token", "client_id": "c"}), vec![("client_secret", "s")]),
        ("kubeconfig", json!({}), vec![("kubeconfig_yaml", KUBECONFIG)]),
        ("kube_token", json!({}), vec![("token", "t")]),
        ("vsphere_user", json!({"upn": "administrator@vsphere.local"}), vec![("password", "p")]),
        ("vnc_password", json!({}), vec![("password", "12345678")]),
        ("vnc_user_password", json!({"username": "u"}), vec![("password", "p")]),
        ("prompt", json!({}), vec![]),
        // ADR-0016 / ADR-0026: every reference names a source (resolution tests cover it).
        ("external_ref", json!({"provider": "onepassword", "reference": "op://vault/app", "target_kind": "api_token",
                                "source": mooring_core::SecretSourceId::new().to_string()}), vec![]),
        ("sudo_become", json!({"method": "sudo"}), vec![]),
        ("vault_approle", json!({}), vec![("role_id", "r"), ("secret_id", "s")]),
        ("s3_access_key", json!({"access_key_id": "AKIAEXAMPLETEST"}), vec![("secret_access_key", "k")]),
        ("bitwarden_access_token", json!({}), vec![("access_token", "0.test-only.machine")]),
    ];
    assert_eq!(cases.len(), kinds().len());
    for (kind, fields, secrets) in cases {
        let c = create(&f.state, new(kind, fields, &secrets)).unwrap_or_else(|e| panic!("{kind}: {e:?}"));
        assert_eq!(c.kind, kind);
    }
    let all = list(&f.state).expect("list");
    let x = all.iter().find(|c| c.kind == "x509").expect("x509");
    assert_eq!(x.fingerprint.as_deref(), Some(CERT_FP));
    let k = all.iter().find(|c| c.kind == "kubeconfig").expect("kube");
    assert_eq!(k.fields["contexts"], json!(["lab", "lab-admin"]));
}

#[test]
fn validation_and_new_error_codes() {
    let f = unlocked();
    let st = &f.state;
    let pw = |p: &str| new("user_password", json!({"username": "u"}), &[("password", p)]);
    assert_eq!(create(st, new("password", json!({}), &[])).expect_err("kind").code, "input.invalid");
    assert_eq!(create(st, pw("")).expect_err("empty").code, "input.invalid", "required secret");
    let big = "x".repeat(MAX_SECRET_BYTES + 1);
    assert_eq!(create(st, pw(&big)).expect_err("big").code, "input.invalid");
    let mut long_user = pw("p");
    long_user.fields = json!({"username": "u".repeat(257)});
    assert_eq!(create(st, long_user).expect_err("user").code, "input.invalid");
    let mut unknown = pw("p");
    unknown.fields = json!({"username": "u", "colour": "red"});
    assert_eq!(create(st, unknown).expect_err("unknown").code, "input.invalid");
    let mut bad_name = pw("p");
    bad_name.name = String::new();
    assert_eq!(create(st, bad_name).expect_err("name").code, "input.invalid");
    let evil = KUBECONFIG.replace("token: test-only-token", "exec: {command: /bin/sh}");
    let e = create(st, new("kubeconfig", json!({}), &[("kubeconfig_yaml", &evil)])).expect_err("exec");
    assert_eq!(e.code, "credential.kubeconfig_rejected");
    assert!(!e.message.contains("/bin/sh"));
    let e = create(st, new("vnc_password", json!({}), &[("password", "123456789")])).expect_err("vnc");
    assert!(e.message.contains("not truncated") && !e.message.contains("123456789"));
    let missing = mooring_core::CredentialId::new().to_string();
    let e = replace_secrets(st, &missing, &WireSecrets::of(&[("password", "s")]), &[]).expect_err("nf");
    assert_eq!(e.code, "credential.not_found");
    let c = create(st, pw("p")).expect("ok");
    let e = replace_secrets(st, &c.id, &WireSecrets::default(), &["password".into()]).expect_err("required");
    assert_eq!(e.code, "input.invalid");
    let e = replace_secrets(st, &c.id, &WireSecrets::of(&[("secret", "x")]), &[]).expect_err("legacy name");
    assert_eq!(e.code, "input.invalid");
    assert_eq!(update_fields(st, "nope", "n", &json!({})).expect_err("id").code, "input.invalid");
    assert_eq!(update_fields(st, &c.id, "n", &json!([1])).expect_err("obj").code, "input.invalid");
    crate::commands::vault::lock(st, None).expect("lock");
    assert_eq!(create(st, pw("s")).expect_err("lock").code, "vault.locked");
}

#[test]
fn otp_attach_is_audited() {
    let f = unlocked();
    let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let c = create(&f.state, new("user_password", json!({"username": "u"}), &[("password", "p"), ("otp_seed", seed)]))
        .expect("create");
    assert_eq!(c.fields["otp"], json!({"digits": 6, "period": 30, "algorithm": "sha1"}));
    assert!(audit_events(&f.state).iter().any(|e| e == "credential_otp_attached"));
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(!log.contains(seed));
}

#[test]
fn parse_account_vectors() {
    let a = parse_account_input("CORP\\alice").expect("netbios");
    assert_eq!(serde_json::to_value(&a).expect("json"), json!({"form": "netbios", "user": "alice", "domain": "CORP"}));
    let u = parse_account_input("alice@corp.example").expect("upn");
    assert_eq!(serde_json::to_value(&u).expect("json")["form"], "upn");
    for bad in ["alice", "ABCDEFGHIJKLMNOP\\bob", "", &"a".repeat(600)] {
        assert_eq!(parse_account_input(bad).expect_err(bad).code, "input.invalid");
    }
}

/// `credential_kinds()` snapshot: the JSON the UI renders its forms from must equal the UI's
/// own copy (`apps/desktop/src/lib/ipc.kinds.ts`), dumped to `kinds.snapshot.json`.
#[test]
fn credential_kinds_snapshot_matches_the_ui_table() {
    let ours = serde_json::to_value(kinds()).expect("json");
    let snapshot: serde_json::Value =
        serde_json::from_str(include_str!("kinds.snapshot.json")).expect("snapshot json");
    assert_eq!(ours, snapshot, "credential_kinds() drifted from the UI table");
}

#[tokio::test]
async fn large_inputs_run_off_the_calling_thread_and_keep_ipc_errors() {
    let caller = std::thread::current().id();
    let inline = offload((), OFFLOAD_BYTES - 1, |()| Ok(std::thread::current().id())).await.expect("ok");
    assert_eq!(inline, caller, "small inputs stay inline");
    let moved = offload((), OFFLOAD_BYTES, |()| Ok(std::thread::current().id())).await.expect("ok");
    assert_ne!(moved, caller, ">= 64 KiB runs on the blocking pool");
    // the command's own IpcError passes through unchanged
    let e = offload((), OFFLOAD_BYTES, |()| -> IpcResult<()> { Err(IpcError::invalid("kubeconfig_yaml", "x")) })
        .await
        .expect_err("err");
    assert_eq!(e.code, "input.invalid");
    // a panic becomes a detail-free internal error
    let e = offload((), OFFLOAD_BYTES, |()| -> IpcResult<()> { panic!("test-only panic detail") })
        .await
        .expect_err("panic");
    assert_eq!((e.code, e.message.as_str()), ("internal", "internal error"));
}

#[tokio::test]
async fn a_large_kubeconfig_is_created_through_the_offload_path() {
    let f = std::sync::Arc::new(unlocked());
    let mut yaml = String::from(KUBECONFIG);
    while yaml.len() < OFFLOAD_BYTES {
        yaml.push_str("# padding comment line to cross the offload threshold\n");
    }
    let bytes = yaml.len();
    let c = new("kubeconfig", json!({}), &[("kubeconfig_yaml", &yaml)]);
    let dto = offload(f.clone(), bytes, move |f| create(&f.state, c)).await.expect("create");
    assert_eq!(dto.kind, "kubeconfig");
    assert!(!serde_json::to_string(&dto).expect("json").contains("test-only-token"));
}
