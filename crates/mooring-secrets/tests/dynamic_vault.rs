//! ADR-0026 §1–§2 against QA's Vault mock: database credentials with a lease (renewed at
//! 2/3 TTL, revoked on release and lock, never cached), `ssh_sign` (public key only, the
//! certificate must certify that key), SSH OTP, PKI issue (+ revoke by serial on request),
//! and hostile responses (lease without id, wrong shapes, oversized, renew refused).

use std::sync::Arc;
use std::time::Duration;

use mooring_core::credential::testdata as td;
use mooring_core::credential::{ExternalRefFields, RefProvider, VaultEngine};
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, SourceKind, SourceOptions};
use mooring_core::{CredentialId, CredentialKind, SecretName, SecretSourceId};
use mooring_secrets::{
    ClientConfig, FakeClock, LoginMaterial, LoginProvider, MemoryAudit, ResolveCtx, SecretEvent,
    SecretsEngine, SecretsError, TokenCache,
};
use mooring_testsrv::tls::TestCert;
use mooring_testsrv::vault::{self, DynamicConfig, VaultConfig, VaultKnobs, VaultServer};
use zeroize::Zeroizing;

struct Env {
    srv: VaultServer,
    engine: SecretsEngine,
    clock: Arc<FakeClock>,
    audit: Arc<MemoryAudit>,
    source: SecretSource,
    _dir: tempfile::TempDir,
}

async fn env(dynamic: DynamicConfig) -> Env {
    let (cert, ca) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("cert");
    let config = VaultConfig { cert: Some(cert), dynamic, ..VaultConfig::default() };
    let srv = vault::start(config, 0).await.expect("vault mock");
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = Arc::new(FakeClock::default());
    let audit = Arc::new(MemoryAudit::default());
    let cache = Arc::new(TokenCache::new(clock.clone(), audit.clone()));
    let mut cfg = ClientConfig::new(dir.path().join("known_vault_certs"));
    cfg.retry.max_attempts = 1;
    let source = SecretSource {
        id: SecretSourceId::new(),
        name: "qa".into(),
        kind: SourceKind::Vault,
        address: srv.base_url(),
        namespace: None,
        auth: SecretSourceAuth::Token { credential_id: CredentialId::new() },
        options: SourceOptions { ca_pem: Some(ca), ..SourceOptions::default() },
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    let engine = SecretsEngine::new(cache, audit.clone(), cfg);
    Env { srv, engine, clock, audit, source, _dir: dir }
}

fn login() -> impl LoginProvider {
    |_: &SecretSource| Ok(LoginMaterial::Token(Zeroizing::new("hvs.test-token".to_owned())))
}

fn ext(env: &Env, engine: VaultEngine, reference: &str, kind: CredentialKind) -> ExternalRefFields {
    let mut f = ExternalRefFields::new(RefProvider::Vault, reference.into(), kind);
    f.source = Some(env.source.id);
    f.engine = engine;
    f
}

fn owned(owner: &str) -> ResolveCtx<'_> {
    ResolveCtx { owner: Some(owner), ..ResolveCtx::default() }
}

fn kinds(env: &Env) -> Vec<&'static str> {
    env.audit.take().iter().map(SecretEvent::name).collect()
}

#[tokio::test]
async fn database_lease_renews_and_is_revoked_on_release() {
    let e = env(DynamicConfig { db_ttl: 60, ..DynamicConfig::default() }).await;
    let f = ext(&e, VaultEngine::Database, "database/app-ro", CredentialKind::UserPassword);
    let r = e
        .engine
        .resolve_in(&e.source, CredentialId::new(), &f, &login(), &owned("s1"))
        .await
        .expect("db creds");
    let pw = String::from_utf8(r.secret(SecretName::Password).expect("pw").to_vec()).expect("utf8");
    assert!(pw.starts_with("A1a-"));
    assert!(!format!("{r:?}").contains(&pw));
    let again = e
        .engine
        .resolve_in(&e.source, CredentialId::new(), &f, &login(), &owned("s2"))
        .await
        .expect("second");
    assert_ne!(again.secret(SecretName::Password), r.secret(SecretName::Password), "never cached");
    assert_eq!((e.srv.live_leases(), e.engine.leases().len()), (2, 2));
    let st = e.engine.leases().status("s1");
    assert_eq!((st.len(), st[0].state, st[0].renewable), (1, "active", true));
    e.clock.advance(Duration::from_secs(39));
    assert_eq!(e.engine.leases().maintain().await, 0, "before 2/3");
    e.clock.advance(Duration::from_secs(2));
    assert_eq!(e.engine.leases().maintain().await, 2, "at 2/3");
    assert_eq!(e.srv.lease_events().iter().filter(|l| l.kind == "renew").count(), 2);
    let released = e.engine.leases().release("s1", "closed");
    assert_eq!(released.len(), 1);
    released.retire().await;
    assert_eq!((e.srv.live_leases(), e.engine.leases().len()), (1, 1));
    e.engine.leases().drain_for_lock("locked").retire().await;
    assert_eq!(e.srv.live_leases(), 0, "lock revokes every lease");
    let names = kinds(&e);
    for n in
        ["secret.lease_issued", "secret.lease_renewed", "secret.lease_revoked", "secret.resolved"]
    {
        assert!(names.contains(&n), "{n}: {names:?}");
    }
    e.srv.recorder().assert_no_violations();
    for line in e.srv.recorder().lines() {
        assert!(!line.contains(&pw), "{line}");
    }
}

#[tokio::test]
async fn renew_failure_keeps_the_lease_and_is_audited() {
    let e = env(DynamicConfig { db_ttl: 30, ..DynamicConfig::default() }).await;
    let f = ext(&e, VaultEngine::Database, "database/app-ro", CredentialKind::UserPassword);
    e.engine
        .resolve_in(&e.source, CredentialId::new(), &f, &login(), &owned("s"))
        .await
        .expect("ok");
    e.srv.set_knobs(VaultKnobs { lease_renew_fails: true, ..VaultKnobs::default() });
    e.clock.advance(Duration::from_secs(25));
    e.engine.leases().maintain().await;
    assert_eq!(e.engine.leases().status("s")[0].state, "renew_failed");
    assert!(kinds(&e).contains(&"secret.lease_renew_failed"));
    e.clock.advance(Duration::from_secs(10));
    assert_eq!(e.engine.leases().maintain().await, 0, "no retry storm");
    assert_eq!(e.engine.leases().status("s")[0].state, "expired");
}

#[tokio::test]
async fn test_resolves_and_locks_revoke_at_once() {
    let e = env(DynamicConfig::default()).await;
    let f = ext(&e, VaultEngine::Database, "database/app-ro", CredentialKind::UserPassword);
    let t = e.engine.test_ref(&e.source, &f, &login()).await.expect("test");
    assert_eq!(t.present, ["password", "username"]);
    assert_eq!((e.srv.live_leases(), e.engine.leases().len()), (0, 0), "test lease revoked");
    e.engine.resolve(&e.source, CredentialId::new(), &f, &login()).await.expect("no owner");
    assert_eq!(e.srv.live_leases(), 0, "an ownerless lease is revoked right away");
}

#[tokio::test]
async fn hostile_dynamic_bodies_are_refused_and_never_used() {
    let e = env(DynamicConfig::default()).await;
    let f = ext(&e, VaultEngine::Database, "database/app-ro", CredentialKind::UserPassword);
    let big = format!(
        r#"{{"lease_id":"l/1","data":{{"username":"u","password":"{}"}}}}"#,
        "p".repeat(2 << 20)
    );
    for (body, code) in [
        (
            r#"{"lease_id":"","lease_duration":60,"data":{"username":"u","password":"p"}}"#,
            "secret.lease_failed",
        ),
        (r#"{"lease_duration":60,"data":{"username":"u","password":"p"}}"#, "secret.lease_failed"),
        (r#"{"lease_id":"l/1","data":{"username":"u"}}"#, "credential.external_shape"),
        (r#"{"lease_id":"l/1","data":{"username":"u","password":7}}"#, "credential.external_shape"),
        (
            r#"{"lease_id":["x"],"data":{"username":"u","password":"p"}}"#,
            "credential.external_shape",
        ),
        (r#"{"lease_id":"l/1","data":null}"#, "credential.external_shape"),
        (
            r#"{"lease_id":"l/1","data":{"username":"a\u202eb","password":"p"}}"#,
            "credential.external_shape",
        ),
        ("[]", "credential.external_shape"),
        ("{", "credential.external_shape"),
        (big.as_str(), "credential.external_shape"),
    ] {
        e.srv.set_knobs(VaultKnobs {
            raw_dynamic_body: Some(body.to_owned()),
            ..VaultKnobs::default()
        });
        let err = e
            .engine
            .resolve_in(&e.source, CredentialId::new(), &f, &login(), &owned("s"))
            .await
            .expect_err(&body[..body.len().min(60)]);
        assert_eq!(err.code(), code, "{}", &body[..body.len().min(60)]);
        assert!(!err.to_string().contains("password\":"), "{err}");
    }
    assert!(e.engine.leases().is_empty(), "nothing registered from a refused response");
}

#[tokio::test]
async fn shape_refusal_after_issue_revokes_the_lease() {
    let e = env(DynamicConfig::default()).await;
    e.srv.set_knobs(VaultKnobs {
        raw_dynamic_body: Some(r#"{"lease_id":"database/creds/app-ro/zz","lease_duration":60,"data":{"username":"bad\u0007user","password":"p"}}"#.into()),
        ..VaultKnobs::default()
    });
    let f = ext(&e, VaultEngine::Database, "database/app-ro", CredentialKind::UserPassword);
    let err = e.engine.resolve_in(&e.source, CredentialId::new(), &f, &login(), &owned("s")).await;
    assert_eq!(err.expect_err("control char").code(), "credential.external_shape");
    let revoked: Vec<_> = e.srv.lease_events().into_iter().filter(|l| l.kind == "revoke").collect();
    assert_eq!(revoked.len(), 1, "the refused credential's lease is revoked");
    assert!(e.engine.leases().is_empty());
}

#[tokio::test]
async fn ssh_sign_sends_the_public_key_and_checks_the_certificate() {
    let dynamic =
        DynamicConfig { ssh_signed_key: td::SSH_CA_CERT.to_owned(), ..DynamicConfig::default() };
    let e = env(dynamic).await;
    let mut f = ext(&e, VaultEngine::SshSign, "ssh/deploy", CredentialKind::SshKey);
    f.principals = Some(vec!["deploy".into()]);
    f.ttl = Some(600);
    let c = e
        .engine
        .sign_ssh_key(&e.source, CredentialId::new(), &f, &login(), td::SSH_CA_SUBJECT_PUB)
        .await
        .expect("signed");
    assert_eq!(c.principals, 1);
    let req = &e.srv.sign_requests()[0];
    assert_eq!(req["public_key"], td::SSH_CA_SUBJECT_PUB);
    assert_eq!(
        (req["valid_principals"].as_str(), req["ttl"].as_str()),
        (Some("deploy"), Some("600s"))
    );
    assert_eq!(req["cert_type"], "user");
    for wrong in [
        td::SSH_CA_CERT_OTHER_KEY,
        td::SSH_CA_CERT_HOST,
        "ssh-ed25519-cert-v01@openssh.com AAAA",
        "",
    ] {
        e.srv.set_dynamic(DynamicConfig {
            ssh_signed_key: wrong.to_owned(),
            ..DynamicConfig::default()
        });
        let err = e
            .engine
            .sign_ssh_key(&e.source, CredentialId::new(), &f, &login(), td::SSH_CA_SUBJECT_PUB)
            .await
            .expect_err("refused");
        assert_eq!(err.code(), "credential.external_shape", "{wrong}");
    }
    let err =
        e.engine.resolve(&e.source, CredentialId::new(), &f, &login()).await.expect_err("modifier");
    assert_eq!(err.code(), "credential.external_engine");
    e.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn ssh_otp_and_pki() {
    let dynamic = DynamicConfig {
        pki_certificate: td::CERT_PEM.to_owned(),
        pki_private_key: td::placeholder_key_pem(),
        pki_lease: true,
        ..DynamicConfig::default()
    };
    let e = env(dynamic).await;
    let mut otp = ext(&e, VaultEngine::SshOtp, "ssh/otp-role", CredentialKind::UserPassword);
    otp.username = Some("deploy".into());
    let err =
        e.engine.resolve(&e.source, CredentialId::new(), &otp, &login()).await.expect_err("no ip");
    assert_eq!(err.code(), "credential.external_engine");
    let ctx = ResolveCtx {
        owner: Some("s"),
        ip: Some("192.0.2.10".parse().expect("ip")),
        revoke_cert: false,
    };
    let r = e
        .engine
        .resolve_in(&e.source, CredentialId::new(), &otp, &login(), &ctx)
        .await
        .expect("otp");
    assert_eq!(r.fields.account().0.as_deref(), Some("deploy"));
    assert!(e.engine.leases().is_empty(), "an OTP is consumed by its first use");
    let mut pki = ext(&e, VaultEngine::Pki, "pki/web", CredentialKind::X509);
    pki.common_name = Some("app.example.test".into());
    let ctx = ResolveCtx { owner: Some("s"), revoke_cert: true, ..ResolveCtx::default() };
    let r = e
        .engine
        .resolve_in(&e.source, CredentialId::new(), &pki, &login(), &ctx)
        .await
        .expect("pki");
    assert!(r.secret(SecretName::KeyPem).is_some());
    e.engine.leases().release("s", "closed").retire().await;
    let ev = e.srv.lease_events();
    assert!(ev.iter().any(|l| l.kind == "revoke_cert"), "{ev:?}");
    assert!(ev.iter().any(|l| l.kind == "revoke"), "{ev:?}");
    let ctx = ResolveCtx { owner: Some("t"), ..ResolveCtx::default() };
    e.engine.resolve_in(&e.source, CredentialId::new(), &pki, &login(), &ctx).await.expect("pki 2");
    e.engine.leases().release("t", "closed").retire().await;
    let certs = e.srv.lease_events().iter().filter(|l| l.kind == "revoke_cert").count();
    assert_eq!(certs, 1, "revokeCertOnDisconnect is off by default");
}

#[tokio::test]
async fn provider_must_match_the_source_kind() {
    let e = env(DynamicConfig::default()).await;
    let mut f = ext(&e, VaultEngine::Kv2, "op://v/i/f", CredentialKind::ApiToken);
    f.provider = RefProvider::Onepassword;
    let err =
        e.engine.resolve(&e.source, CredentialId::new(), &f, &login()).await.expect_err("kind");
    assert_eq!(err.code(), "source.kind_unsupported");
    assert!(matches!(err, SecretsError::KindUnsupported(_)));
}
