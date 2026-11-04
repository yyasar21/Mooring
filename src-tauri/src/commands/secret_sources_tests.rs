//! ADR-0016 E2: source CRUD, `secret_source_test`, `credential_external_test`, refusals and
//! hostile inputs, against `mooring-testsrv::vault`.


#![allow(clippy::many_single_char_names)]
use mooring_testsrv::vault::{KvSecret, KvVersion, VaultKnobs};
use serde_json::json;

use super::*;
use crate::commands::credentials;
use crate::state::testing::unlocked;
use crate::test_secrets::{self as fx, audit_rows};

#[tokio::test]
async fn token_source_crud_and_test_never_return_the_token() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let s = fx::token_source(st, &v, "hvs.test-token");
    assert_eq!((s.kind, s.auth_method, s.auth_mount.as_str()), ("vault", "token", "token"));
    assert_eq!(list(st).expect("list"), vec![s.clone()]);
    assert_eq!(get(st, &s.id).expect("get"), s);
    let t = test(st, &s.id).await.expect("test");
    assert!(t.ok, "{t:?}");
    assert_eq!((t.method, t.renewable, t.policies_count), ("token", true, 2));
    assert!(t.ttl_seconds.is_some_and(|x| x > 3000 && x <= 3600), "{t:?}");
    let wire = serde_json::to_string(&(list(st).expect("list"), &t)).expect("json");
    assert!(!wire.contains("hvs.test-token"), "{wire}");

    // Update: changed names audited (trust change is a warning), cached token forgotten.
    let mut input = fx::source_json(&v, "token", s.credential_id.as_deref(), None);
    input["name"] = json!("renamed");
    input["options"]["caPem"] = json!(v.ca.clone() + "\n");
    let u = update(st, &s.id, &input).await.expect("update");
    assert_eq!(u.name, "renamed");
    assert_eq!(st.secrets.engine().cache().len(), 0, "token forgotten on update");
    let changed = audit_rows(st, "secret_source_changed");
    assert_eq!(changed[0]["changed"], json!(["created", "caPem", "allowHttp"]));
    assert_eq!(changed[1]["changed"], json!(["name", "caPem"]));
    assert_eq!(changed[1]["warning"], true);
    assert_eq!(audit_rows(st, "secret_login")[0]["method"], "token");

    delete(st, &s.id).await.expect("delete");
    assert_eq!(get(st, &s.id).expect_err("gone").code, "source.not_found");
    let raw = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("log");
    assert!(!raw.contains("hvs.test-token"), "no token in the audit log");
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn approle_and_root_refusal() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let a = fx::approle_source(st, &v);
    let t = test(st, &a.id).await.expect("test");
    assert!(t.ok && t.method == "approle" && t.ttl_seconds.is_some_and(|x| x > 1150), "{t:?}");
    assert_eq!(v.srv.live_issued_tokens(), 1);
    revoke(st, &a.id).await.expect("revoke");
    assert_eq!(v.srv.live_issued_tokens(), 0, "an AppRole token is revoked server-side");

    let bad = fx::approle_credential(st, "test-role-id", "wrong");
    let b = create(st, &fx::source_json(&v, "approle", Some(&bad), None)).expect("source");
    let t = test(st, &b.id).await.expect("test");
    assert_eq!((t.ok, t.error, t.category), (false, Some("credential.external_unavailable"), Some("auth_failed")));

    let root = fx::token_source(st, &v, "hvs.root-token");
    let t = test(st, &root.id).await.expect("test");
    assert_eq!(t.error, Some("credential.external_root_token"), "{t:?}");
    assert_eq!(st.secrets.engine().cache().len(), 0, "a root token is never cached");
    v.srv.set_knobs(VaultKnobs { root_token: true, ..VaultKnobs::default() });
    let ok = fx::token_source(st, &v, "hvs.test-token");
    assert_eq!(test(st, &ok.id).await.expect("t").error, Some("credential.external_root_token"));
    assert!(audit_rows(st, "secret_failed").len() >= 3);
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn sealed_vault_is_unavailable_without_fallback() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let s = fx::token_source(st, &v, "hvs.test-token");
    assert!(test(st, &s.id).await.expect("t").ok);
    v.srv.set_knobs(VaultKnobs { sealed: true, ..VaultKnobs::default() });
    let t = test(st, &s.id).await.expect("t");
    assert_eq!((t.error, t.category), (Some("credential.external_unavailable"), Some("network")));
    let r = fx::external_ref(st, &s.id, "secret/servers/web", "user_password");
    let e = external_test(st, &r).await.expect("ref test");
    assert_eq!((e.ok, e.category), (false, Some("network")), "{e:?}");
    v.srv.set_knobs(VaultKnobs { standby: true, ..VaultKnobs::default() });
    let e = external_test(st, &r).await.expect("ref test");
    assert!(!e.ok && e.error == Some("credential.external_unavailable"), "a 307 is not followed: {e:?}");
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn external_test_reports_names_and_delete_is_refused_while_in_use() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let s = fx::token_source(st, &v, "hvs.test-token");
    let mut kv = mooring_testsrv::vault::default_kv();
    kv.push(KvSecret {
        mount: "secret".into(),
        path: "servers/dom".into(),
        versions: vec![KvVersion::new(
            json!({ "user": "alice", "domain": "EXAMPLE", "form": "netbios", "password": "testpass" }),
        )],
    });
    v.srv.set_kv(kv);
    let r = fx::external_ref(st, &s.id, "secret/servers/dom", "domain_user");
    let t = external_test(st, &r).await.expect("ref test");
    assert!(t.ok && t.version == Some(1), "{t:?}");
    assert_eq!(t.present, ["user", "domain", "form", "password"]);
    let wire = serde_json::to_string(&t).expect("json");
    assert!(!wire.contains("testpass") && !wire.contains("alice"), "names only: {wire}");
    let partial = fx::external_ref(st, &s.id, "secret/servers/web", "domain_user");
    let t = external_test(st, &partial).await.expect("ref test");
    assert!(!t.ok && t.missing.contains(&"user".to_owned()), "{t:?}");
    let up = fx::external_ref(st, &s.id, "secret/servers/web", "user_password");
    let t = external_test(st, &up).await.expect("ref test");
    assert!(t.ok && t.version == Some(2), "username, password and the optional domain: {t:?}");
    let mis = fx::external_ref(st, &s.id, "secret/servers/dom", "user_password");
    let t = external_test(st, &mis).await.expect("ref test");
    assert!(!t.ok && (t.extra == ["user", "form"] || t.extra == ["form", "user"]), "{t:?}");
    assert_eq!(t.missing, ["username"], "extra keys refused, missing named");
    let gone = fx::external_ref(st, &s.id, "secret/servers/deleted", "user_password");
    assert_eq!(external_test(st, &gone).await.expect("t").error, Some("credential.external_not_found"));
    v.srv.set_kv(vec![KvSecret {
        mount: "secret".into(),
        path: "servers/web".into(),
        versions: vec![KvVersion::new(json!({ "password": 7 }))],
    }]);
    let t = external_test(st, &up).await.expect("t");
    assert_eq!(t.error, Some("credential.external_shape"), "{t:?}");

    let e = delete(st, &s.id).await.expect_err("in use");
    assert_eq!(e.code, "source.in_use");
    let login = s.credential_id.clone().expect("cred");
    assert_eq!(credentials::delete(st, &login).expect_err("login in use").code, "credential.in_use");
    let refused = audit_rows(st, "secret_refused");
    assert_eq!((refused[0]["action"].clone(), refused[0]["detail"].clone()), (json!("delete"), json!("source.in_use")));
    let plain = credentials::create(st, credentials::NewCredential::password_for_tests("p")).expect("c");
    assert_eq!(external_test(st, &plain.id).await.expect_err("kind").code, "input.invalid");
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn hostile_inputs_are_refused_before_any_request() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let cred = fx::token_credential(st, "hvs.test-token");
    let base = fx::source_json(&v, "token", Some(&cred), None);
    let with = |k: &str, val: serde_json::Value| {
        let mut x = base.clone();
        x[k] = val;
        x
    };
    let cases = [
        with("address", json!("http://vault.example.test")),
        with("address", json!("https://u:p@vault.example.test")),
        with("address", json!("ftp://vault.example.test")),
        with("address", json!(format!("https://{}", "a".repeat(3000)))),
        with("authMethod", json!("kerberos")),
        with("credentialId", json!("not-a-uuid")),
        with("namespace", json!("../../sys")),
        with("unknown", json!(1)),
        with("oidcRole", json!("r")),
        with("options", json!({ "caPem": "x".repeat(100 * 1024) })),
        json!("not an object"),
    ];
    for c in &cases {
        let e = create(st, c).expect_err("refused");
        assert_eq!(e.code, "input.invalid", "{c}");
        assert!(!e.message.contains("hvs.") && !e.message.contains("kerberos"), "{}", e.message);
    }
    let login_kind = credentials::create(st, credentials::NewCredential::password_for_tests("p")).expect("c");
    let e = create(st, &with("credentialId", json!(login_kind.id))).expect_err("kind");
    assert_eq!(e.code, "credential.incompatible", "{e:?}");
    for id in ["", "x", &"9".repeat(100)] {
        assert_eq!(get(st, id).expect_err("id").code, "input.invalid");
        assert_eq!(test(st, id).await.expect_err("id").code, "input.invalid");
    }
    assert_eq!(v.srv.recorder().len(), 0, "nothing reached the server");
    crate::commands::vault::lock(st, None).expect("lock");
    assert_eq!(list(st).expect_err("locked").code, "vault.locked");
    assert_eq!(create(st, &base).expect_err("locked").code, "vault.locked");
    v.srv.recorder().assert_no_violations();
}
