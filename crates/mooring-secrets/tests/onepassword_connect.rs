//! ADR-0026 §3 against the 1Password Connect mock: `op://` references (whole item by label /
//! purpose / OTP type, one field, a section field, UUIDs instead of titles), `fieldMap`,
//! and hostile cases (401, duplicate field labels, another item's id, wrong shapes,
//! oversized bodies, a redirect off-host). Every test ends with no recorder violation.

use std::sync::Arc;

use mooring_core::credential::{ExternalRefFields, RefProvider};
use mooring_core::secret_source::{SecretSource, SecretSourceAuth, SourceKind, SourceOptions};
use mooring_core::{CredentialId, CredentialKind, SecretName, SecretSourceId};
use mooring_secrets::{
    Category, ClientConfig, FakeClock, LoginMaterial, LoginProvider, MemoryAudit, SecretEvent,
    SecretsEngine, SecretsError, TokenCache,
};
use mooring_testsrv::onepassword::{self, ConnectConfig, ConnectKnobs, ConnectServer, OpVault};
use mooring_testsrv::tls::TestCert;
use serde_json::json;
use zeroize::Zeroizing;

struct Env {
    srv: ConnectServer,
    engine: SecretsEngine,
    audit: Arc<MemoryAudit>,
    source: SecretSource,
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let (cert, ca) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("cert");
    let srv = onepassword::start(ConnectConfig { cert: Some(cert), ..ConnectConfig::default() }, 0)
        .await
        .expect("connect mock");
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = Arc::new(MemoryAudit::default());
    let cache = Arc::new(TokenCache::new(Arc::new(FakeClock::default()), audit.clone()));
    let mut cfg = ClientConfig::new(dir.path().join("known_vault_certs"));
    cfg.retry.max_attempts = 1;
    let source = SecretSource {
        id: SecretSourceId::new(),
        name: "connect".into(),
        kind: SourceKind::Onepassword,
        address: srv.base_url(),
        namespace: None,
        auth: SecretSourceAuth::Token { credential_id: CredentialId::new() },
        options: SourceOptions { ca_pem: Some(ca), ..SourceOptions::default() },
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    Env { srv, engine: SecretsEngine::new(cache, audit.clone(), cfg), audit, source, _dir: dir }
}

fn login(token: &'static str) -> impl LoginProvider {
    move |_: &SecretSource| Ok(LoginMaterial::Token(Zeroizing::new(token.to_owned())))
}

const TOKEN: &str = "test-only-connect-token";

fn op(e: &Env, reference: &str, kind: CredentialKind) -> ExternalRefFields {
    let mut f = ExternalRefFields::new(RefProvider::Onepassword, reference.into(), kind);
    f.source = Some(e.source.id);
    f
}

fn text(r: &mooring_secrets::ResolvedSecrets, n: SecretName) -> String {
    String::from_utf8(r.secret(n).expect("secret").to_vec()).expect("utf8")
}

impl Env {
    async fn resolve(
        &self,
        f: &ExternalRefFields,
    ) -> Result<mooring_secrets::ResolvedSecrets, SecretsError> {
        self.engine.resolve(&self.source, CredentialId::new(), f, &login(TOKEN)).await
    }

    fn clean(&self) {
        self.srv.recorder().assert_no_violations();
        for line in self.srv.recorder().lines() {
            assert!(!line.contains("op-testpass") && !line.contains(TOKEN), "{line}");
        }
    }
}

#[tokio::test]
async fn whole_items_fields_and_sections() {
    let e = env().await;
    let r =
        e.resolve(&op(&e, "op://Infra/DB prod", CredentialKind::UserPassword)).await.expect("item");
    assert_eq!(text(&r, SecretName::Password), "op-testpass");
    assert_eq!(text(&r, SecretName::OtpSeed), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "OTP by type");
    assert_eq!(r.names(), ["otp_seed", "password", "username"], "other fields are ignored");
    let r = e
        .resolve(&op(&e, "op://Infra/API/credential", CredentialKind::ApiToken))
        .await
        .expect("one");
    assert_eq!(text(&r, SecretName::Token), "op-token-1");
    let ids = "op://aaaaaaaaaaaaaaaaaaaaaaaaaa/cccccccccccccccccccccccccc/credential";
    assert!(e.resolve(&op(&e, ids, CredentialKind::ApiToken)).await.is_ok(), "UUIDs skip lookups");
    let r =
        e.resolve(&op(&e, "op://Infra/DB prod/admin/password", CredentialKind::VncPassword)).await;
    assert_eq!(r.expect_err("vnc cap 8").code(), "credential.external_shape");
    let r = e
        .resolve(&op(&e, "op://Infra/DB prod/sec1/password", CredentialKind::ApiToken))
        .await
        .expect("section by id");
    assert_eq!(text(&r, SecretName::Token), "op-adminpass");
    let r = e.resolve(&op(&e, "op://Infra/DB prod/password", CredentialKind::ApiToken)).await;
    assert_eq!(text(&r.expect("top level wins"), SecretName::Token), "op-testpass");
    let mut mapped = op(&e, "op://Infra/API", CredentialKind::ApiToken);
    mapped.field_map = Some([("token".to_owned(), "credential".to_owned())].into());
    assert!(e.resolve(&mapped).await.is_ok(), "fieldMap renames by label");
    let err = e.resolve(&op(&e, "op://Infra/API/credential", CredentialKind::UserPassword)).await;
    assert_eq!(err.expect_err("one field, two names").code(), "credential.external_engine");
    let ev = e.audit.take();
    assert!(ev.iter().any(|x| matches!(x, SecretEvent::Resolved { provider: "onepassword", .. })));
    e.clean();
}

#[tokio::test]
async fn missing_and_refused() {
    let e = env().await;
    for (r, code) in [
        ("op://Nope/DB prod", "credential.external_not_found"),
        ("op://Infra/Nope", "credential.external_not_found"),
        ("op://Infra/API/nope", "credential.external_not_found"),
        ("op://Infra/DB prod/nosection/password", "credential.external_not_found"),
    ] {
        let err = e.resolve(&op(&e, r, CredentialKind::ApiToken)).await.expect_err(r);
        assert_eq!(err.code(), code, "{r}");
    }
    let err = e
        .engine
        .resolve(
            &e.source,
            CredentialId::new(),
            &op(&e, "op://Infra/API", CredentialKind::ApiToken),
            &login("wrong"),
        )
        .await
        .expect_err("401");
    assert_eq!(err.category(), Category::AuthFailed);
    e.clean();
}

#[tokio::test]
async fn hostile_items() {
    let e = env().await;
    let dup = json!({ "id": "dddddddddddddddddddddddddd", "title": "Dup", "fields": [
        { "id": "a", "label": "password", "value": "one" },
        { "id": "b", "label": "password", "value": "two" },
        { "id": "u", "label": "username", "value": "x" } ] });
    let mut vaults = onepassword::default_vaults();
    vaults[0].items.push(dup);
    vaults.push(OpVault {
        id: "eeeeeeeeeeeeeeeeeeeeeeeeee".into(),
        name: "Infra".into(),
        items: vec![],
    });
    e.srv.set_vaults(vaults.clone());
    let err = e
        .resolve(&op(&e, "op://Infra/Dup", CredentialKind::UserPassword))
        .await
        .expect_err("2 vaults");
    assert!(err.to_string().contains("two vaults"), "{err}");
    vaults.pop();
    e.srv.set_vaults(vaults);
    let err =
        e.resolve(&op(&e, "op://Infra/Dup", CredentialKind::UserPassword)).await.expect_err("dup");
    assert_eq!(err.code(), "credential.external_shape");
    assert!(err.to_string().contains("two fields") && !err.to_string().contains("one"), "{err}");
    let item = "op://aaaaaaaaaaaaaaaaaaaaaaaaaa/cccccccccccccccccccccccccc";
    let fields = r#"[{"id":"credential","label":"credential","value":"v"}]"#;
    for body in [
        format!(r#"{{"id":"zzzzzzzzzzzzzzzzzzzzzzzzzz","fields":{fields}}}"#),
        r#"{"id":"cccccccccccccccccccccccccc","fields":[{"id":"credential","label":"credential","value":5}]}"#.to_owned(),
        r#"{"id":"cccccccccccccccccccccccccc","fields":"x"}"#.to_owned(),
        format!(r#"{{"id":"cccccccccccccccccccccccccc","fields":[{}]}}"#, vec![r#"{"id":"f"}"#; 257].join(",")),
        r#"{"id":"cccccccccccccccccccccccccc","fields":[{"id":"credential","label":"cred\u0000ential","value":"v"}]}"#.to_owned(),
        "[]".to_owned(),
        "{".to_owned(),
    ] {
        e.srv.set_knobs(ConnectKnobs { raw_item_body: Some(body.clone()), ..ConnectKnobs::default() });
        let mut f = op(&e, item, CredentialKind::ApiToken);
        f.field_map = Some([("token".to_owned(), "credential".to_owned())].into());
        let err = e.resolve(&f).await.expect_err(&body[..body.len().min(50)]);
        assert_eq!(err.code(), "credential.external_shape", "{}", &body[..body.len().min(50)]);
    }
    e.srv.set_knobs(ConnectKnobs { oversized_body: Some(2 << 20), ..ConnectKnobs::default() });
    let err = e.resolve(&op(&e, "op://Infra/API/credential", CredentialKind::ApiToken)).await;
    assert_eq!(err.expect_err("cap").code(), "credential.external_shape");
    e.srv.set_knobs(ConnectKnobs { redirect_off_host: true, ..ConnectKnobs::default() });
    let err = e.resolve(&op(&e, "op://Infra/API/credential", CredentialKind::ApiToken)).await;
    assert_eq!(err.expect_err("redirect").code(), "credential.external_unavailable");
    e.clean();
}

#[tokio::test]
async fn source_test_counts_vaults() {
    let e = env().await;
    let t = e.engine.test_source(&e.source, &login(TOKEN)).await.expect("test");
    assert_eq!((t.method, t.policies_count), ("token", 1));
    assert!(e.engine.test_source(&e.source, &login("wrong")).await.is_err());
    let f = op(&e, "op://Infra/DB prod", CredentialKind::UserPassword);
    let names = e.engine.test_ref(&e.source, &f, &login(TOKEN)).await.expect("ref");
    assert_eq!(names.present, ["otp_seed", "password", "username"]);
    e.clean();
}
