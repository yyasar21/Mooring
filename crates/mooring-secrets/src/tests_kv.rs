//! KV v2 shapes, hostile bodies, no-disk rule, `*_test` results and the OIDC flow.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use mooring_core::credential::{ExternalRefFields, RefProvider};
use mooring_core::secret_source::{SecretSource, SecretSourceAuth};
use mooring_core::{CredentialId, CredentialKind, SecretName};
use serde_json::json;
use zeroize::Zeroizing;

use crate::mock::{State, Ver, GOOD_CODE, IDP_STATE};
use crate::tests::{env, source, tok};
use crate::*;

#[allow(clippy::unnecessary_wraps)] // the LoginProvider signature
fn login(_: &SecretSource) -> Result<LoginMaterial, SecretsError> {
    Ok(LoginMaterial::Token(Zeroizing::new("hvs.user".to_owned())))
}

fn st() -> State {
    let mut s = State::default();
    s.tokens.insert("hvs.user".into(), tok(&["app"], 3600));
    let v = |data, deleted, destroyed| Ver { data, deleted, destroyed };
    s.kv.insert(
        "secret/app/api".into(),
        vec![
            v(json!({"token": "t-1"}), false, true),
            v(json!({"token": "t-2"}), true, false),
            v(json!({"api_key": "t-3", "owner": "ops"}), false, false),
        ],
    );
    s
}

fn ext(src: &SecretSource, reference: &str, kind: CredentialKind) -> ExternalRefFields {
    let mut f = ExternalRefFields::new(RefProvider::Vault, reference.into(), kind);
    f.source = Some(src.id);
    f
}

fn token_src(e: &crate::tests::Env) -> SecretSource {
    source(&e.mock, SecretSourceAuth::Token { credential_id: CredentialId::new() }, None)
}

#[tokio::test]
async fn versions_deleted_destroyed_and_field_map() {
    let e = env(st()).await;
    let src = token_src(&e);
    let mut f = ext(&src, "secret/app/api", CredentialKind::ApiToken);
    f.field_map = Some(BTreeMap::from([("token".to_owned(), "api_key".to_owned())]));
    let err =
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect_err("extra owner");
    let SecretsError::Shape { extra, missing, .. } = &err else { panic!("{err}") };
    assert_eq!((extra.as_slice(), missing.len()), (&["owner".to_owned()][..], 0));
    let t = e.engine.test_ref(&src, &f, &login).await.expect("test_ref");
    assert_eq!(
        (t.version, t.present, t.extra),
        (3, vec!["token".to_owned()], vec!["owner".to_owned()])
    );
    e.mock
        .with(|s| s.kv.get_mut("secret/app/api").expect("kv")[2].data = json!({"api_key": "t-3"}));
    let r = e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect("mapped");
    assert_eq!(r.secret(SecretName::Token), Some(&b"t-3"[..]));
    for (version, what) in [(1, "destroyed"), (2, "deleted"), (9, "absent")] {
        f.version = Some(version);
        let err = e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect_err(what);
        assert!(matches!(err, SecretsError::NotFound), "{what}: {err}");
        assert_eq!(err.code(), "credential.external_not_found");
    }
    let missing = ext(&src, "secret/app/nothing", CredentialKind::ApiToken);
    assert!(matches!(
        e.engine.resolve(&src, CredentialId::new(), &missing, &login).await,
        Err(SecretsError::NotFound)
    ));
}

#[tokio::test]
async fn hostile_bodies_fail_as_shape() {
    let e = env(st()).await;
    let src = token_src(&e);
    let f = ext(&src, "secret/app/api", CredentialKind::ApiToken);
    let path = "/v1/secret/data/app/api";
    let huge = format!(r#"{{"data":{{"data":{{"token":"{}"}}}}}}"#, "x".repeat(MAX_RESPONSE + 1));
    for (body, what) in [
        (huge, "over the 1 MiB cap"),
        (r#"{"data":{"data":{"token":12345}}}"#.to_owned(), "number"),
        (r#"{"data":{"data":{"token":["a"]}}}"#.to_owned(), "array"),
        (r#"{"data":{"data":{"token":"a","token":"b"}}}"#.to_owned(), "duplicate"),
        (r#"{"data":"nope"}"#.to_owned(), "data string"),
        ("not json".to_owned(), "garbage"),
        (
            r#"{"data":{"data":{"token":"a"},"metadata":{"version":"7"}}}"#.to_owned(),
            "version type",
        ),
    ] {
        e.mock.with(|s| s.raw.insert(path.into(), (200, body)));
        let err = e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect_err(what);
        assert_eq!(err.code(), "credential.external_shape", "{what}: {err}");
        assert!(!err.to_string().contains("12345"));
    }
    e.mock.with(|s| s.raw.insert(path.into(), (200, r#"{"data":null}"#.into())));
    assert!(matches!(
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await,
        Err(SecretsError::NotFound)
    ));
    let lookup = "/v1/auth/token/lookup-self";
    e.engine.cache().revoke_all().await;
    e.mock.with(|s| s.raw.insert(lookup.into(), (200, r#"{"data":{"policies":"root"}}"#.into())));
    let err =
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect_err("bad lookup");
    assert_eq!(err.code(), "credential.external_shape");
}

fn snapshot(dir: &Path) -> Vec<(String, u64, Option<SystemTime>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| {
            let e = e.expect("entry");
            let m = e.metadata().expect("meta");
            (e.file_name().to_string_lossy().into_owned(), m.len(), m.modified().ok())
        })
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn resolve_writes_nothing_to_the_data_dir() {
    let e = env(st()).await;
    std::fs::write(e.dir.path().join("known_vault_certs"), b"").expect("seed store file");
    let before = snapshot(e.dir.path());
    let src = token_src(&e);
    e.mock.with(|s| s.kv.get_mut("secret/app/api").expect("kv")[2].data = json!({"token": "t-3"}));
    let f = ext(&src, "secret/app/api", CredentialKind::ApiToken);
    for _ in 0..3 {
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect("resolve");
    }
    e.engine.cache().revoke_all().await;
    assert_eq!(snapshot(e.dir.path()), before, "no file created or modified");
}

#[tokio::test]
async fn source_test_reports_counts_only() {
    let e = env(st()).await;
    let src = token_src(&e);
    let t = e.engine.test_source(&src, &login).await.expect("test");
    assert_eq!(
        (t.method, t.renewable, t.policies_count, t.ttl_seconds),
        ("token", true, 1, Some(3600))
    );
    let oidc =
        source(&e.mock, SecretSourceAuth::Oidc { mount: "oidc".into(), role: "r".into() }, None);
    let err = e.engine.test_source(&oidc, &login).await.expect_err("no sign-in yet");
    assert_eq!(err.category(), Category::AuthFailed);
    assert!(e.engine.logout(src.id).await);
    assert!(!e.engine.logout(src.id).await);
}

#[tokio::test]
async fn oidc_flow_is_bound_to_state_nonce_and_time() {
    let e = env(st()).await;
    let mut src = source(
        &e.mock,
        SecretSourceAuth::Oidc { mount: "oidc".into(), role: "mooring".into() },
        None,
    );
    src.options.allowed_origins = vec!["https://login.example.test".into()];
    let f = ext(&src, "secret/app/api", CredentialKind::ApiToken);
    let err =
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect_err("sign-in first");
    assert_eq!(err.category(), Category::AuthFailed);

    let flow = e.engine.begin_oidc(&src).await.expect("auth_url");
    assert!(flow.auth_url.starts_with("https://idp.example.test/"));
    assert_eq!(flow.allowed_origins, ["https://idp.example.test", "https://login.example.test"]);
    assert_eq!(e.mock.with(|s| s.oidc_nonce.as_ref().map(String::len)), Some(64));
    assert_eq!(flow.navigation("https://login.example.test/mfa"), Navigation::Allow);
    let wrong = format!("http://localhost:8250/oidc/callback?code={GOOD_CODE}&state=other");
    let err = e.engine.complete_oidc(&src, flow, &wrong).await.expect_err("state");
    assert_eq!(err.category(), Category::AuthFailed);
    assert_eq!(e.mock.hits("/v1/auth/oidc/oidc/callback"), 0, "never sent");

    let flow = e.engine.begin_oidc(&src).await.expect("again");
    e.clock.advance(OIDC_TIMEOUT + Duration::from_secs(1));
    let ok = format!("http://localhost:8250/oidc/callback?code={GOOD_CODE}&state={IDP_STATE}");
    assert!(e.engine.complete_oidc(&src, flow, &ok).await.is_err(), "timed out");

    let flow = e.engine.begin_oidc(&src).await.expect("third");
    e.engine.complete_oidc(&src, flow, &ok).await.expect("signed in");
    e.mock.with(|s| s.kv.get_mut("secret/app/api").expect("kv")[2].data = json!({"token": "t-3"}));
    e.engine.resolve(&src, CredentialId::new(), &f, &login).await.expect("resolve with OIDC token");
    assert_eq!(e.engine.cache().revoke_all().await, 1);
    assert_eq!(e.mock.with(|s| s.revoked.len()), 1, "OIDC tokens are ours: revoked on lock");
    let other =
        source(&e.mock, SecretSourceAuth::Oidc { mount: "oidc".into(), role: "x".into() }, None);
    let flow = e.engine.begin_oidc(&src).await.expect("fourth");
    assert!(matches!(
        e.engine.complete_oidc(&other, flow, &ok).await,
        Err(SecretsError::Invalid(_))
    ));
}

#[tokio::test]
async fn references_must_match_the_source() {
    let e = env(st()).await;
    let src = token_src(&e);
    let mut f = ext(&src, "secret/app/api", CredentialKind::ApiToken);
    f.source = Some(mooring_core::SecretSourceId::new());
    assert!(matches!(
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await,
        Err(SecretsError::Invalid("source"))
    ));
    let mut f = ext(&src, "secret/../x", CredentialKind::ApiToken);
    assert!(matches!(
        e.engine.resolve(&src, CredentialId::new(), &f, &login).await,
        Err(SecretsError::Invalid(_))
    ));
    f.reference = "secret/app/api".into();
    f.provider = RefProvider::Onepassword;
    assert!(e.engine.resolve(&src, CredentialId::new(), &f, &login).await.is_err());
    assert_eq!(e.mock.with(|s| s.hits.len()), 0, "refused before any request");
    let dbg = format!(
        "{:?}",
        VaultClient::new(&src, &ClientConfig::new(e.dir.path().join("k"))).expect("c")
    );
    assert!(!dbg.contains("hvs."));
}
