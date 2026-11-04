//! ADR-0016 E2 runtime: renew / revoke timing on a fake clock, lock revokes, OIDC through the
//! navigation hook (fake `IdP` of `mooring-testsrv::vault`), audit mapping.


#![allow(clippy::many_single_char_names)]
use std::sync::Arc;
use std::time::Duration;

use mooring_secrets::{FakeClock, Maintenance};
use serde_json::json;

use super::*;
use crate::commands::secret_sources as cmd;
use crate::commands::secret_sources_oidc as oidc_cmd;
use crate::commands::vault;
use crate::oidc_window::{navigate, window_destroyed};
use crate::state::testing::{unlocked, Fixture};
use crate::state::AppState;
use crate::test_secrets::{self as fx, audit_rows};

fn with_fake_clock(f: &mut Fixture) -> Arc<FakeClock> {
    let clock = Arc::new(FakeClock::default());
    let rt = SecretsRuntime::with_clock(&f.state.data_dir, Arc::clone(&f.state.audit), clock.clone());
    f.state.secrets = Arc::new(rt);
    clock
}

#[tokio::test]
async fn renew_at_ten_percent_then_lock_revokes() {
    let v = fx::start_default().await;
    let mut f = unlocked();
    let clock = with_fake_clock(&mut f);
    let st = &f.state;
    let a = fx::approle_source(st, &v);
    assert!(cmd::test(st, &a.id).await.expect("test").ok);
    let cache = Arc::clone(st.secrets.engine().cache());
    assert!(cache.maintain().await.is_empty(), "fresh token: nothing due");
    clock.advance(Duration::from_secs(1200 - 119)); // 119 s of 1200 left: < 10 %
    let done = cache.maintain().await;
    assert_eq!(done.iter().map(|(_, m)| *m).collect::<Vec<_>>(), [Maintenance::Renewed]);
    assert!(v.srv.token_events().iter().any(|e| e.kind == "renew"));
    assert_eq!(audit_rows(st, "secret_login").last().expect("row")["method"], "renew");
    clock.advance(Duration::from_secs(100));
    assert!(cache.maintain().await.is_empty(), "renewed lifetime counts from the renewal");

    vault::lock(st, Some("user")).expect("lock");
    st.secrets.flush().await;
    assert!(cache.is_empty(), "lock forgets every token");
    assert_eq!(v.srv.live_issued_tokens(), 0, "lock revokes the AppRole token");
    assert_eq!(audit_rows(st, "secret_revoked").len(), 1);
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn user_token_is_forgotten_not_revoked_and_shutdown_drops_all() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let s = fx::token_source(st, &v, "hvs.test-token");
    let a = fx::approle_source(st, &v);
    assert!(cmd::test(st, &s.id).await.expect("t").ok && cmd::test(st, &a.id).await.expect("t").ok);
    assert_eq!(st.secrets.engine().cache().len(), 2);
    st.secrets.shutdown();
    st.secrets.flush().await;
    assert!(st.secrets.engine().cache().is_empty());
    let revokes = v.srv.token_events().iter().filter(|e| e.kind == "revoke").count();
    assert_eq!(revokes, 1, "only the AppRole token is ours to revoke");
    // The stored user token still works server-side.
    assert!(cmd::test(st, &s.id).await.expect("t").ok);
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn oidc_flow_intercepts_the_redirect_and_lock_revokes() {
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let w = fx::windows(st);
    let o = fx::oidc_source(st, &v);
    let t = cmd::test(st, &o.id).await.expect("t");
    assert_eq!(t.category, Some("auth_failed"), "no sign-in yet: {t:?}");
    let begun = oidc_cmd::begin(st, &o.id).await.expect("begin");
    assert_eq!(begun.window_label, format!("oidc-{}", o.id));
    let again = oidc_cmd::begin(st, &o.id).await.expect("again");
    assert_eq!(again.session_id, begun.session_id, "one flow per source");
    let (label, url, session) = w.opened.lock().expect("m")[0].clone();
    assert_eq!((label.as_str(), session.as_str()), (begun.window_label.as_str(), begun.session_id.as_str()));
    assert_eq!(w.opened.lock().expect("m").len(), 1);
    let sid = &begun.session_id;
    let status = |st: &AppState| oidc_cmd::status(st, sid).expect("status");
    assert_eq!(status(st).state, "pending");

    let rt = &st.secrets;
    assert!(navigate(rt, sid, "https://idp.example.test/login?step=2"), "IdP origin loads");
    for evil in ["https://evil.example.test/", "https://idp.example.test.evil.test/", "file:///etc/passwd",
                 "javascript:alert(1)", "http://localhost:8251/oidc/callback?code=x&state=y"] {
        assert!(!navigate(rt, sid, evil), "{evil}");
    }
    assert_eq!(status(st).state, "pending", "blocked navigations do not end the flow");
    assert!(audit_rows(st, "secret_refused").iter().any(|r| r["detail"] == "https://evil.example.test"));

    let redirect = v.srv.idp_redirect(&url).expect("fake IdP redirect");
    assert!(!navigate(rt, sid, &redirect), "the redirect is never loaded");
    assert_eq!(w.closed.lock().expect("m").as_slice(), std::slice::from_ref(&label));
    st.secrets.flush().await;
    assert_eq!(status(st), crate::oidc_window::OidcStatus { state: "done", source_id: o.id.clone(), error: None });
    assert!(!navigate(rt, sid, "https://idp.example.test/"), "a finished flow loads nothing");
    let t = cmd::test(st, &o.id).await.expect("t");
    assert!(t.ok && t.method == "oidc", "{t:?}");
    assert_eq!(v.srv.live_issued_tokens(), 1);
    let ev: Vec<String> = audit_rows(st, "secret_login").iter().map(|r| r["method"].to_string()).collect();
    assert!(ev.contains(&"\"oidc\"".to_owned()), "{ev:?}");

    let second = oidc_cmd::begin(st, &o.id).await.expect("begin");
    vault::lock(st, None).expect("lock");
    st.secrets.flush().await;
    assert_eq!(v.srv.live_issued_tokens(), 0, "the OIDC token is revoked on lock");
    let s2 = oidc_cmd::status(st, &second.session_id).expect("status");
    assert_eq!((s2.state, s2.error.as_deref()), ("failed", Some("locked")), "open windows close on lock");
    assert_eq!(oidc_cmd::begin(st, &o.id).await.expect_err("locked").code, "vault.locked");
    v.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn oidc_state_mismatch_close_and_timeout_fail_the_flow() {
    let v = fx::start_default().await;
    let mut f = unlocked();
    let clock = with_fake_clock(&mut f);
    let st = &f.state;
    let w = fx::windows(st);
    let o = fx::oidc_source(st, &v);
    let rt = &st.secrets;

    let b = oidc_cmd::begin(st, &o.id).await.expect("begin");
    let url = w.opened.lock().expect("m")[0].1.clone();
    let good = v.srv.idp_redirect(&url).expect("redirect");
    let forged = format!("{good}x");
    assert!(!navigate(rt, &b.session_id, &forged));
    let s = oidc_cmd::status(st, &b.session_id).expect("s");
    assert_eq!((s.state, s.error.as_deref()), ("failed", Some("state_mismatch")));
    assert!(!navigate(rt, &b.session_id, &good), "a failed flow never exchanges a code");
    st.secrets.flush().await;
    assert_eq!(v.srv.live_issued_tokens(), 0);

    let b = oidc_cmd::begin(st, &o.id).await.expect("begin");
    window_destroyed(rt, &b.session_id);
    assert_eq!(oidc_cmd::status(st, &b.session_id).expect("s").error.as_deref(), Some("closed"));

    let b = oidc_cmd::begin(st, &o.id).await.expect("begin");
    clock.advance(mooring_secrets::OIDC_TIMEOUT + Duration::from_secs(1));
    let s = oidc_cmd::status(st, &b.session_id).expect("s");
    assert_eq!((s.state, s.error.as_deref()), ("failed", Some("timeout")));
    assert_eq!(oidc_cmd::status(st, "nope").expect_err("unknown").code, "session.not_found");
    assert_eq!(oidc_cmd::status(st, &"x".repeat(80)).expect_err("long").code, "input.invalid");
    let tok = fx::token_source(st, &v, "hvs.test-token");
    assert_eq!(oidc_cmd::begin(st, &tok.id).await.expect_err("not oidc").code, "input.invalid");
    assert_eq!(rt.oidc.pending(), 0);
    v.srv.recorder().assert_no_violations();
}

#[test]
fn audit_mapping_carries_names_and_the_connection() {
    use mooring_core::{CredentialId, CredentialKind, SecretSourceId};
    let src = SecretSourceId::new();
    let e = audit_event(
        SecretEvent::Resolved {
            credential: CredentialId::new(),
            source: src,
            reference: "secret/servers/web".into(),
            version: 2,
            target_kind: CredentialKind::UserPassword,
            fields: vec!["password", "username"],
        },
        Some("conn-1".into()),
    );
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(v["event"], "secret_resolved");
    assert_eq!((v["connection"].clone(), v["target_kind"].clone()), (json!("conn-1"), json!("user_password")));
    assert_eq!(v["fields"], json!(["password", "username"]));
    let f = audit_event(SecretEvent::Failed { source: src, category: Category::Locked }, None);
    assert_eq!(serde_json::to_value(&f).expect("json")["category"], "locked");
    assert_eq!(locked().code(), "credential.external_unavailable");
}

/// Every `SecretsError` variant maps to the code `SecretsError::code()` names, and every
/// such code is in the checked-in `ipc-codes.json` (the golden scanner reads only literals
/// in this crate, so the mapping must spell them out).
#[test]
fn every_secrets_error_code_is_in_the_golden_list() {
    use mooring_http::{CertProtocol, CertTrust, CertificateInfo, TrustDecision, TrustVerdict};
    let trust = TrustDecision {
        protocol: CertProtocol::Vault,
        host: "vault.example.test".into(),
        port: 8200,
        fingerprint: [7; 32],
        trust: CertTrust::Unknown,
        verdict: TrustVerdict::Prompt,
        info: CertificateInfo {
            subject: "CN=vault.example.test".into(),
            issuer: "CN=vault.example.test".into(),
            not_before: time::OffsetDateTime::UNIX_EPOCH,
            not_after: time::OffsetDateTime::UNIX_EPOCH,
            sha256: "07".repeat(32),
            san: vec![],
            problems: vec![],
        },
    };
    let variants = [
        SecretsError::Unavailable { category: Category::Network, detail: "x" },
        SecretsError::Trust(Box::new(trust)),
        SecretsError::RootToken,
        SecretsError::NotFound,
        SecretsError::Shape { missing: vec!["password".into()], extra: vec![], invalid: None },
        SecretsError::Invalid("x"),
    ];
    let golden = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ipc-codes.json"))
        .expect("ipc-codes.json");
    let golden: Vec<String> = serde_json::from_str(&golden).expect("json list");
    let mut seen = std::collections::BTreeSet::new();
    for e in &variants {
        let ipc = ipc_error(e);
        assert_eq!(ipc.code, e.code(), "{e:?}");
        assert!(golden.iter().any(|c| c == ipc.code), "{} missing from ipc-codes.json", ipc.code);
        seen.insert(ipc.code);
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "credential.external_not_found",
            "credential.external_root_token",
            "credential.external_shape",
            "credential.external_unavailable",
            "input.invalid",
        ]
    );
}

/// Review 6 L-34: the vault locks while the mock Vault is still answering a login — the fresh
/// token is never cached and `revoke-self` is sent; a lock while `oidc_begin` waits for the
/// auth URL opens no window.
#[tokio::test]
async fn a_lock_during_a_login_or_an_oidc_begin_leaves_nothing_behind() {
    use mooring_testsrv::http::HttpKnobs;
    let v = fx::start_default().await;
    let f = unlocked();
    let st = &f.state;
    let w = fx::windows(st);
    let a = fx::approle_source(st, &v);
    let o = fx::oidc_source(st, &v);
    let cache = Arc::clone(st.secrets.engine().cache());
    v.srv.set_http_knobs(HttpKnobs { response_delay: Some(Duration::from_millis(400)), ..HttpKnobs::default() });

    let lock_soon = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        vault::lock(st, Some("user")).expect("lock");
        assert!(cache.is_empty(), "on_lock drains synchronously");
    };
    let (r, ()) = tokio::join!(cmd::test(st, &a.id), lock_soon);
    let r = r.expect("test reports, never errors");
    assert_eq!(r.category, Some("locked"), "{r:?}");
    st.secrets.flush().await;
    assert!(cache.is_empty(), "the post-lock token is not cached");
    assert_eq!(v.srv.live_issued_tokens(), 0, "revoke-self was sent for it");
    assert!(v.srv.token_events().iter().any(|e| e.kind == "revoke"));

    vault::unlock(st, secrecy::SecretString::from(crate::state::testing::MASTER.to_owned())).expect("unlock");
    let lock_soon = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        vault::lock(st, Some("user")).expect("lock");
    };
    let (r, ()) = tokio::join!(oidc_cmd::begin(st, &o.id), lock_soon);
    assert_eq!(r.expect_err("no window over the lock screen").code, "vault.locked");
    assert!(w.opened.lock().expect("m").is_empty(), "no OIDC window was opened");
    assert_eq!(st.secrets.oidc.pending(), 0);
    assert!(audit_rows(st, "secret_refused").iter().any(|r| r["detail"] == "locked"));
}
