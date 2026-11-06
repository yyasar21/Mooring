//! The network path against the `mooring-testsrv` LDAP mock: bind, paged search, caps,
//! escaping on the wire, trust prompt, referrals and hostile responses. Every run ends with
//! `assert_no_violations` (bind / search / abandon / unbind only).

use std::time::Duration;

use mooring_core::known_certs::CertProtocol;
use mooring_core::Protocol;
use mooring_http::tls::{client_config, TlsTarget};
use mooring_http::{HttpError, TlsClient};
use mooring_testsrv::ldap::{self, Hostile, LdapConfig, LdapEntry, LdapKnobs, LdapServer};
use zeroize::Zeroizing;

use super::*;

const BASE: &str = "DC=corp,DC=example,DC=test";

struct Env {
    srv: LdapServer,
    dir: tempfile::TempDir,
}

async fn env(knobs: LdapKnobs) -> Env {
    let cfg = LdapConfig { knobs, ..LdapConfig::default() };
    let srv = ldap::start(cfg, 0).await.expect("mock");
    Env { srv, dir: tempfile::tempdir().expect("tmp") }
}

fn pin(srv: &LdapServer) -> [u8; 32] {
    let hex = srv.cert().sha256_hex();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

impl Env {
    async fn tls(&self, trusted: bool) -> TlsClient {
        let t = TlsTarget {
            protocol: CertProtocol::Ldap,
            host: "127.0.0.1".into(),
            port: self.srv.addr().port(),
            known_certs_path: self.dir.path().join("known_ldap_certs"),
            extra_ca_pem: None,
            trusted_once: trusted.then(|| pin(&self.srv)),
        };
        client_config(&t).await.expect("tls config")
    }

    fn query(&self) -> LdapQuery {
        LdapQuery {
            url: self.srv.url(),
            base_dn: BASE.into(),
            scope: SearchScope::Sub,
            kind: DirectoryKind::Ad,
            name_contains: None,
            size_limit: None,
        }
    }

    async fn run(&self, q: &LdapQuery, limits: &LdapLimits) -> Result<ImportPlan, LdapError> {
        let p = q.prepare(limits).expect("prepared");
        preview(&p, &cred(true), self.tls(true).await, limits, &BindSignal::default()).await
    }
}

fn cred(ok: bool) -> BindCredential {
    BindCredential {
        name: "svc-mooring@corp.example.test".into(),
        password: Zeroizing::new(if ok { "test-bind-pw" } else { "wrong" }.into()),
    }
}

fn fast() -> LdapLimits {
    LdapLimits {
        deadline: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        ..LdapLimits::DEFAULT
    }
}

#[tokio::test]
async fn binds_searches_and_maps_the_fixture() {
    let e = env(LdapKnobs::default()).await;
    let plan = e.run(&e.query(), &fast()).await.expect("plan");
    let c = plan.counts();
    assert_eq!((c.folders, c.connections, c.credentials, c.skipped), (3, 3, 1, 1));
    let by_name = |n: &str| plan.connections.iter().find(|c| c.name == n).expect(n);
    assert_eq!(
        (by_name("WEB01").protocol, by_name("WEB01").host.as_str()),
        (Protocol::Rdp, "web01.corp.example.test")
    );
    assert_eq!(by_name("DB01").protocol, Protocol::Ssh);
    assert_eq!(by_name("LAPTOP07").protocol, Protocol::Rdp);
    let web = plan.folders.iter().find(|f| f.name == "Web").expect("Web");
    let servers = plan.folders.iter().find(|f| f.name == "Servers").expect("Servers");
    assert_eq!(web.parent.as_deref(), Some(servers.key.as_str()));
    assert_eq!(by_name("WEB01").folder.as_deref(), Some(web.key.as_str()));
    assert_eq!(plan.credentials[0].name, "Directory account (corp.example.test)");
    let rec = e.srv.recorder();
    rec.assert_no_violations();
    assert_eq!(rec.ops(), ["bind", "search", "unbind"]);
    let s = &rec.searches()[0];
    assert_eq!(s.filter.as_deref(), Some("(objectClass=computer)"));
    assert_eq!(s.base.as_deref(), Some("dc=corp,dc=example,dc=test"));
    assert_eq!((s.scope, s.size_limit, s.time_limit), (Some(2), Some(5000), Some(5)));
    assert_eq!(s.paged.as_ref().map(|(n, c)| (*n, c.is_empty())), Some((500, true)));
    assert!(ATTRIBUTES.iter().all(|a| s.attrs.iter().any(|x| x == a)));
    assert_eq!(rec.requests()[0].bind_name.as_deref(), Some("svc-mooring@corp.example.test"));
    assert!(!format!("{:?}", rec.requests()).contains("test-bind-pw"));
}

#[tokio::test]
async fn pages_with_cookies_and_caps_pages_and_entries() {
    let e = env(LdapKnobs::default()).await;
    let limits = LdapLimits { page_size: 2, ..fast() };
    let plan = e.run(&e.query(), &limits).await.expect("plan");
    assert_eq!(plan.counts().connections, 3);
    let searches = e.srv.recorder().searches();
    assert_eq!(searches.len(), 2);
    assert_eq!(searches[0].paged.as_ref().map(|(_, c)| c.clone()), Some(Vec::new()));
    assert_eq!(searches[1].paged.as_ref().map(|(_, c)| c.clone()), Some(b"2".to_vec()));
    e.srv.recorder().assert_no_violations();

    // One page allowed, more needed → size limit.
    let limits = LdapLimits { page_size: 1, max_pages: 1, ..fast() };
    assert_eq!(e.run(&e.query(), &limits).await.expect_err("page cap").code(), "ldap.size_limit");

    // The client-side entry cap abandons the running search.
    // The mock honours the request's sizeLimit (rc 4) like a real server.
    let q = LdapQuery { size_limit: Some(2), ..e.query() };
    assert_eq!(e.run(&q, &fast()).await.expect_err("rc 4").code(), "ldap.size_limit");
    // Server-side limit knob.
    let e2 = env(LdapKnobs { size_limit_after: Some(1), ..LdapKnobs::default() }).await;
    assert_eq!(
        e2.run(&e2.query(), &fast()).await.expect_err("server cap").code(),
        "ldap.size_limit"
    );
    e2.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn client_cap_abandons_when_the_server_sends_more() {
    let e = env(LdapKnobs { ignore_size_limit: true, ..LdapKnobs::default() }).await;
    let many: Vec<LdapEntry> = (0..6)
        .map(|i| {
            LdapEntry::new(
                &format!("CN=H{i},OU=Servers,{BASE}"),
                &[
                    ("objectClass", &["computer"]),
                    ("cn", &[&format!("H{i}")]),
                    ("dNSHostName", &[&format!("h{i}.corp.example.test")]),
                ],
            )
        })
        .collect();
    e.srv.set_entries(many);
    let limits = LdapLimits { max_entries: 3, ..fast() };
    let q = LdapQuery { size_limit: Some(3), ..e.query() };
    let p = q.prepare(&limits).expect("p");
    let err = preview(&p, &cred(true), e.tls(true).await, &limits, &BindSignal::default())
        .await
        .expect_err("cap");
    assert_eq!(err.code(), "ldap.size_limit");
    assert_eq!(e.srv.recorder().ops(), ["bind", "search", "abandon", "unbind"]);
    e.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn name_filter_reaches_the_server_escaped() {
    let e = env(LdapKnobs::default()).await;
    let q = LdapQuery { name_contains: Some("*)(objectClass=*".into()), ..e.query() };
    let plan = e.run(&q, &fast()).await.expect("plan");
    assert_eq!(plan.counts().connections, 0, "the injected clause matched nothing");
    let s = &e.srv.recorder().searches()[0];
    assert_eq!(s.filter.as_deref(), Some("(&(objectClass=computer)(|(cn=*\\2a\\29\\28objectClass=\\2a*)(dNSHostName=*\\2a\\29\\28objectClass=\\2a*)))"));
    let q = LdapQuery { name_contains: Some("web".into()), ..e.query() };
    let plan = e.run(&q, &fast()).await.expect("plan");
    assert_eq!(plan.counts().connections, 1);
    let q = LdapQuery { kind: DirectoryKind::OpenLdap, scope: SearchScope::One, ..e.query() };
    assert_eq!(e.run(&q, &fast()).await.expect("plan").counts().connections, 0);
    let s = e.srv.recorder().searches().pop().expect("search");
    assert_eq!(
        (s.filter.as_deref(), s.scope),
        (Some("(|(objectClass=ipHost)(objectClass=device))"), Some(1))
    );
    e.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn bind_failure_and_bind_only() {
    let e = env(LdapKnobs::default()).await;
    let p = e.query().prepare(&fast()).expect("p");
    let bind = BindSignal::default();
    let err = preview(&p, &cred(false), e.tls(true).await, &fast(), &bind).await.expect_err("bind");
    assert_eq!(bind.phase(), BindPhase::Attempted);
    assert_eq!(err.code(), "ldap.bind");
    assert!(matches!(err, LdapError::Bind(49)));
    assert_eq!(e.srv.recorder().ops(), ["bind", "unbind"]);
    let bind = BindSignal::default();
    bind_only(&p, &cred(true), e.tls(true).await, &fast(), &bind).await.expect("bind only");
    assert_eq!(bind.phase(), BindPhase::Bound);
    assert_eq!(e.srv.recorder().ops(), ["bind", "unbind", "bind", "unbind"]);
    e.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn unknown_certificate_is_a_trust_prompt() {
    let e = env(LdapKnobs::default()).await;
    let p = e.query().prepare(&fast()).expect("p");
    let bind = BindSignal::default();
    let err =
        preview(&p, &cred(true), e.tls(false).await, &fast(), &bind).await.expect_err("prompt");
    assert_eq!(bind.phase(), BindPhase::NotAttempted, "nothing reaches the server without trust");
    assert_eq!(err.code(), "http.trust_prompt");
    let LdapError::Tls(HttpError::TrustPrompt(d)) = err else { panic!("{err:?}") };
    assert_eq!(
        (d.host.as_str(), d.port, d.fingerprint),
        ("127.0.0.1", e.srv.addr().port(), pin(&e.srv))
    );
    assert!(e.srv.recorder().requests().is_empty(), "nothing is sent before the handshake");
}

#[tokio::test]
async fn referrals_are_ignored_and_unpaged_servers_work() {
    let e = env(LdapKnobs { referral: true, ignore_paging: true, ..LdapKnobs::default() }).await;
    let plan = e.run(&e.query(), &LdapLimits { page_size: 1, ..fast() }).await.expect("plan");
    assert_eq!(plan.counts().connections, 3);
    assert_eq!(e.srv.recorder().searches().len(), 1);
    e.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn hostile_responses_never_panic_or_hang() {
    // Deep nesting: 2 000 levels overflowed the stack with ldap3's codec; 100 000 levels
    // (≈ 500 KiB) must be refused by the scan in constant stack, before any parsing.
    for h in [
        Hostile::EmptyMessage,
        Hostile::Garbage,
        Hostile::DeepNesting(40),
        Hostile::DeepNesting(2_000),
        Hostile::DeepNesting(100_000),
        Hostile::HugeLength,
    ] {
        let e = env(LdapKnobs { hostile: Some(h), ..LdapKnobs::default() }).await;
        let started = std::time::Instant::now();
        let err = e.run(&e.query(), &fast()).await.expect_err("hostile");
        assert_eq!(err.code(), "ldap.response", "{h:?}: {err:?}");
        assert!(started.elapsed() < Duration::from_secs(4), "{h:?} must fail fast");
        e.srv.recorder().assert_no_violations();
    }
    let short = LdapLimits { deadline: Duration::from_millis(1500), ..fast() };
    let e = env(LdapKnobs { never_answer_search: true, ..LdapKnobs::default() }).await;
    let started = std::time::Instant::now();
    assert_eq!(e.run(&e.query(), &short).await.expect_err("timeout").code(), "ldap.timeout");
    assert!(started.elapsed() < Duration::from_secs(10));
    let e =
        env(LdapKnobs { hostile: Some(Hostile::OversizedValue(5_000)), ..LdapKnobs::default() })
            .await;
    let plan = e.run(&e.query(), &fast()).await.expect("oversized value is dropped, not fatal");
    assert_eq!(plan.counts().connections, 1);
    assert_eq!(plan.connections[0].name, "BIG");
    let e = env(LdapKnobs { hostile: Some(Hostile::ExtraElement), ..LdapKnobs::default() }).await;
    assert_eq!(
        e.run(&e.query(), &fast()).await.expect("malformed entry skipped").counts().connections,
        0
    );
}

#[tokio::test]
async fn slow_bind_hits_the_deadline() {
    let e =
        env(LdapKnobs { bind_delay: Some(Duration::from_secs(5)), ..LdapKnobs::default() }).await;
    let short = LdapLimits { deadline: Duration::from_millis(800), ..fast() };
    assert_eq!(e.run(&e.query(), &short).await.expect_err("slow").code(), "ldap.timeout");
}
