//! Loopback tests against the in-process Vault mock ([`crate::mock`]).

use std::sync::Arc;
use std::time::Duration;

use mooring_core::credential::{ExternalRefFields, RefProvider};
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, SourceKind, SourceOptions};
use mooring_core::{CredentialId, CredentialKind, SecretName, SecretSourceId};
use serde_json::json;
use zeroize::Zeroizing;

use crate::mock::{start, Mock, State, Tok, Ver};
use crate::*;

pub(crate) struct Env {
    pub mock: Mock,
    pub engine: SecretsEngine,
    pub clock: Arc<FakeClock>,
    pub audit: Arc<MemoryAudit>,
    pub dir: tempfile::TempDir,
}

pub(crate) fn source(mock: &Mock, auth: SecretSourceAuth, ns: Option<&str>) -> SecretSource {
    SecretSource {
        id: SecretSourceId::new(),
        name: "mock".into(),
        kind: SourceKind::Vault,
        address: mock.url(),
        namespace: ns.map(str::to_owned),
        auth,
        options: SourceOptions { allow_http: true, ..SourceOptions::default() },
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

pub(crate) async fn env(state: State) -> Env {
    let mock = start(state).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = Arc::new(FakeClock::default());
    let audit = Arc::new(MemoryAudit::default());
    let cache = Arc::new(TokenCache::new(clock.clone(), audit.clone()));
    let mut cfg = ClientConfig::new(dir.path().join("known_vault_certs"));
    cfg.retry.max_attempts = 1;
    Env { mock, engine: SecretsEngine::new(cache, audit.clone(), cfg), clock, audit, dir }
}

pub(crate) fn tok(policies: &[&'static str], ttl: u64) -> Tok {
    Tok { policies: policies.to_vec(), ttl, renewable: true, kv: true }
}

fn token_login(t: &'static str) -> impl LoginProvider {
    move |_: &SecretSource| Ok(LoginMaterial::Token(Zeroizing::new(t.to_owned())))
}

fn approle_login(r: &'static str, s: &'static str) -> impl LoginProvider {
    move |_: &SecretSource| {
        Ok(LoginMaterial::AppRole {
            role_id: Zeroizing::new(r.to_owned()),
            secret_id: Zeroizing::new(s.to_owned()),
        })
    }
}

fn ext(source: &SecretSource, reference: &str, kind: CredentialKind) -> ExternalRefFields {
    ExternalRefFields {
        provider: RefProvider::Vault,
        reference: reference.into(),
        target_kind: kind,
        source: Some(source.id),
        version: None,
        field_map: None,
    }
}

fn state_with_db() -> State {
    let mut s = State::default();
    s.tokens.insert("hvs.user".into(), tok(&["default", "app"], 3600));
    s.tokens.insert("hvs.root".into(), tok(&["root"], 0));
    s.kv.insert(
        "secret/db".into(),
        vec![
            Ver {
                data: json!({"username": "v1", "password": "pw-1"}),
                deleted: false,
                destroyed: false,
            },
            Ver {
                data: json!({"username": "v2", "password": "pw-2"}),
                deleted: false,
                destroyed: false,
            },
        ],
    );
    s
}

#[tokio::test]
async fn token_login_reads_kv_and_audits_names_only() {
    let e = env(state_with_db()).await;
    let src = source(
        &e.mock,
        SecretSourceAuth::Token { credential_id: CredentialId::new() },
        Some("team"),
    );
    let cred = CredentialId::new();
    let r = e
        .engine
        .resolve(
            &src,
            cred,
            &ext(&src, "secret/db", CredentialKind::UserPassword),
            &token_login("hvs.user"),
        )
        .await
        .expect("resolve");
    assert_eq!(r.secret(SecretName::Password), Some(&b"pw-2"[..]), "latest version");
    assert_eq!(r.version, 2);
    assert_eq!(e.mock.with(|s| s.namespaces.clone()), [Some("team".into()), Some("team".into())]);
    // the second resolve reuses the cached token: no second lookup-self
    let mut pinned = ext(&src, "secret/db", CredentialKind::UserPassword);
    pinned.version = Some(1);
    let r1 = e.engine.resolve(&src, cred, &pinned, &token_login("hvs.user")).await.expect("v1");
    assert_eq!(r1.secret(SecretName::Password), Some(&b"pw-1"[..]));
    assert_eq!(e.mock.hits("/v1/auth/token/lookup-self"), 1);
    let events = e.audit.take();
    assert!(matches!(events[0], SecretEvent::Login { ttl: 3600, .. }));
    let SecretEvent::Resolved { fields, reference, version, .. } = &events[1] else {
        panic!("resolved")
    };
    assert_eq!(
        (fields.as_slice(), reference.as_str(), *version),
        (&["password", "username"][..], "secret/db", 2)
    );
    let dump = format!("{events:?}");
    assert!(!dump.contains("pw-") && !dump.contains("hvs.user"), "no values or tokens in events");
}

#[tokio::test]
async fn root_tokens_are_refused_and_bad_tokens_fail_closed() {
    let e = env(state_with_db()).await;
    let src = source(&e.mock, SecretSourceAuth::Token { credential_id: CredentialId::new() }, None);
    let f = ext(&src, "secret/db", CredentialKind::UserPassword);
    let err = e
        .engine
        .resolve(&src, CredentialId::new(), &f, &token_login("hvs.root"))
        .await
        .expect_err("root");
    assert!(matches!(err, SecretsError::RootToken));
    assert_eq!(err.code(), "credential.external_root_token");
    assert!(e.engine.cache().is_empty(), "a refused token is not cached");
    let err = e
        .engine
        .resolve(&src, CredentialId::new(), &f, &token_login("hvs.nope"))
        .await
        .expect_err("bad");
    assert_eq!(err.category(), Category::AuthFailed);
    assert!(e.audit.take().iter().all(|ev| matches!(ev, SecretEvent::Failed { .. })));
    let locked = |_: &SecretSource| {
        Err(SecretsError::Unavailable { category: Category::Locked, detail: "vault locked" })
    };
    let err = e.engine.resolve(&src, CredentialId::new(), &f, &locked).await.expect_err("locked");
    assert_eq!(err.category(), Category::Locked);
}

#[tokio::test]
async fn sealed_or_standby_is_unavailable_without_fallback() {
    let e = env(state_with_db()).await;
    let src = source(&e.mock, SecretSourceAuth::Token { credential_id: CredentialId::new() }, None);
    let f = ext(&src, "secret/db", CredentialKind::UserPassword);
    e.engine.resolve(&src, CredentialId::new(), &f, &token_login("hvs.user")).await.expect("first");
    e.mock.with(|s| s.sealed = true);
    let err = e
        .engine
        .resolve(&src, CredentialId::new(), &f, &token_login("hvs.user"))
        .await
        .expect_err("503");
    assert_eq!(
        (err.code(), err.category()),
        ("credential.external_unavailable", Category::Network)
    );
    e.mock.with(|s| {
        s.sealed = false;
        s.raw.insert("/v1/secret/data/db".into(), (429, "{}".into()));
    });
    let err = e
        .engine
        .resolve(&src, CredentialId::new(), &f, &token_login("hvs.user"))
        .await
        .expect_err("standby");
    assert_eq!(err.category(), Category::Network);
}

#[tokio::test]
async fn approle_login_renews_with_a_fake_clock_and_revokes_on_lock() {
    let mut st = state_with_db();
    st.approle = Some(("role-test".into(), "secret-test".into()));
    st.approle_ttl = 600;
    st.renew_ttl = 900;
    let e = env(st).await;
    let src = source(
        &e.mock,
        SecretSourceAuth::AppRole { mount: "approle".into(), credential_id: CredentialId::new() },
        None,
    );
    let f = ext(&src, "secret/db", CredentialKind::UserPassword);
    let bad = approle_login("role-test", "wrong");
    let err = e.engine.resolve(&src, CredentialId::new(), &f, &bad).await.expect_err("400");
    assert_eq!(err.category(), Category::AuthFailed);
    let good = approle_login("role-test", "secret-test");
    e.engine.resolve(&src, CredentialId::new(), &f, &good).await.expect("login");
    let cache = e.engine.cache();
    assert_eq!(cache.remaining(src.id), Some(Duration::from_secs(600)));
    assert!(cache.maintain().await.is_empty(), "not due yet");
    e.clock.advance(Duration::from_secs(545)); // 55 s left of 600: under 10 %, due
    assert_eq!(cache.maintain().await, [(src.id, Maintenance::Renewed)]);
    assert_eq!(cache.remaining(src.id), Some(Duration::from_secs(900)));
    assert_eq!(e.mock.hits("/v1/auth/token/renew-self"), 1);
    // non-renewable: dropped (and revoked, it is ours) when due
    e.mock.with(|s| s.tokens.values_mut().for_each(|t| t.renewable = false));
    e.clock.advance(Duration::from_secs(880));
    assert_eq!(cache.maintain().await, [(src.id, Maintenance::Dropped)]);
    assert!(cache.is_empty());
    assert_eq!(e.mock.with(|s| s.revoked.len()), 1);
    // expiry without maintenance: the next get misses and a resolve logs in again
    e.engine.resolve(&src, CredentialId::new(), &f, &good).await.expect("relogin");
    e.clock.advance(Duration::from_secs(601));
    assert!(cache.get(src.id).is_none(), "expired tokens are not served");
    e.engine.resolve(&src, CredentialId::new(), &f, &good).await.expect("again");
    assert_eq!(e.mock.hits("/v1/auth/approle/login"), 4);
    // lock: ours are revoked server-side and wiped
    let before = e.mock.with(|s| s.revoked.len());
    assert_eq!(cache.revoke_all().await, 1);
    assert!(cache.is_empty());
    assert_eq!(e.mock.with(|s| s.revoked.len()), before + 1);
}

#[tokio::test]
async fn stored_tokens_are_forgotten_not_revoked_and_renewer_runs() {
    let e = env(state_with_db()).await;
    let src = source(&e.mock, SecretSourceAuth::Token { credential_id: CredentialId::new() }, None);
    let f = ext(&src, "secret/db", CredentialKind::UserPassword);
    e.engine.resolve(&src, CredentialId::new(), &f, &token_login("hvs.user")).await.expect("ok");
    let handle = e.engine.cache().spawn_renewer(Duration::from_millis(5));
    e.clock.advance(Duration::from_secs(3590));
    e.mock.with(|s| s.renew_ttl = 7200);
    for _ in 0..200 {
        if e.mock.hits("/v1/auth/token/renew-self") > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(e.mock.hits("/v1/auth/token/renew-self") >= 1, "background renewal");
    handle.abort();
    assert_eq!(e.engine.cache().revoke_all().await, 1);
    assert!(e.mock.with(|s| s.revoked.is_empty()), "the user's token is not revoked");
    assert!(e.mock.with(|s| s.tokens.contains_key("hvs.user")));
}

#[tokio::test]
async fn a_token_revoked_server_side_is_replaced_once() {
    let e = env(state_with_db()).await;
    let src = source(&e.mock, SecretSourceAuth::Token { credential_id: CredentialId::new() }, None);
    let f = ext(&src, "secret/db", CredentialKind::UserPassword);
    e.engine.resolve(&src, CredentialId::new(), &f, &token_login("hvs.user")).await.expect("ok");
    e.mock.with(|s| s.tokens.get_mut("hvs.user").expect("tok").kv = false);
    let err = e
        .engine
        .resolve(&src, CredentialId::new(), &f, &token_login("hvs.user"))
        .await
        .expect_err("403");
    assert_eq!(err.category(), Category::Forbidden);
    assert_eq!(e.mock.hits("/v1/auth/token/lookup-self"), 2, "one fresh login, no loop");
}

/// Review 6 L-34: a lock while a login is in flight (the provider runs after the epoch was
/// captured, so it stands in for the lock) leaves nothing in the cache, revokes the fresh
/// token and fails `locked`; an OIDC flow begun before a lock cannot complete.
#[tokio::test]
async fn a_lock_during_a_login_refuses_and_revokes_the_token() {
    let mut st = state_with_db();
    st.approle = Some(("role-test".into(), "secret-test".into()));
    let e = env(st).await;
    let src = source(
        &e.mock,
        SecretSourceAuth::AppRole { mount: "approle".into(), credential_id: CredentialId::new() },
        None,
    );
    let f = ext(&src, "secret/db", CredentialKind::UserPassword);
    let cache = Arc::clone(e.engine.cache());
    assert_eq!(cache.epoch(), 0);
    let racing = move |_: &SecretSource| {
        let drained = cache.drain_for_lock();
        assert!(drained.is_empty());
        Ok(LoginMaterial::AppRole {
            role_id: Zeroizing::new("role-test".to_owned()),
            secret_id: Zeroizing::new("secret-test".to_owned()),
        })
    };
    let err = e.engine.resolve(&src, CredentialId::new(), &f, &racing).await.expect_err("locked");
    assert_eq!(err.category(), Category::Locked);
    assert_eq!(e.engine.cache().epoch(), 1);
    assert!(e.engine.cache().is_empty(), "the post-lock token is not cached");
    assert_eq!(e.mock.hits("/v1/auth/approle/login"), 1, "the login did complete");
    assert_eq!(e.mock.with(|s| s.revoked.len()), 1, "and its token was revoked");
    assert!(e.audit.take().iter().any(|ev| matches!(ev, SecretEvent::Revoked { .. })));
    // The next login, started in the new epoch, is cached as usual.
    let good = approle_login("role-test", "secret-test");
    e.engine.resolve(&src, CredentialId::new(), &f, &good).await.expect("login");
    assert_eq!(e.engine.cache().len(), 1);

    let oidc = source(
        &e.mock,
        SecretSourceAuth::Oidc { mount: "oidc".into(), role: "mooring".into() },
        None,
    );
    let flow = e.engine.begin_oidc(&oidc).await.expect("auth_url");
    assert_eq!(flow.epoch, 1);
    assert_eq!(e.engine.cache().drain_for_lock().len(), 1, "lock: the AppRole token goes");
    let ok = format!(
        "http://localhost:8250/oidc/callback?code={}&state={}",
        crate::mock::GOOD_CODE,
        crate::mock::IDP_STATE
    );
    let err = e.engine.complete_oidc(&oidc, flow, &ok).await.expect_err("stale flow");
    assert_eq!(err.category(), Category::Locked);
    assert_eq!(e.mock.hits("/v1/auth/oidc/oidc/callback"), 0, "the code is never exchanged");
    assert!(e.engine.cache().is_empty());
}
