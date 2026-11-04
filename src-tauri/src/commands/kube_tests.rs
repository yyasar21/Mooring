//! Kubernetes command tests against QA's `mooring-testsrv::kube` mock (loopback TLS). The
//! fixture here is shared with `kube_flow_tests.rs`.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use mooring_core::session::Size;
use mooring_testsrv::kube::{self as mock, KubeConfig, KubeServer};
use mooring_testsrv::tls::TestCert;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::*;
use crate::commands::kube_wire;
use crate::commands::conn_options;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing::{audit_events, unlocked, Fixture};

#[path = "kube_flow_tests.rs"]
mod flow;

pub(super) const SIZE: Size = Size { width: 80, height: 24 };
const TOKEN: &str = "test-token";

/// How the test connection authenticates and anchors trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Auth {
    /// `kube_token` with `server` + `caPem` options (CA-issued server leaf).
    TokenCa,
    /// `kubeconfig` with `certificate-authority-data` (anchored, no TOFU).
    KubeconfigCa,
    /// `kubeconfig` without CA data: system roots fail → certificate prompt.
    KubeconfigTofu,
}

pub(super) struct Kube {
    pub(super) f: Fixture,
    pub(super) srv: KubeServer,
    pub(super) conn: String,
    pub(super) cred: String,
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

pub(super) fn kubeconfig(server: &str, ca: Option<&str>, token: &str) -> String {
    let ca = ca.map(|c| format!("\n    certificate-authority-data: {}", b64(c))).unwrap_or_default();
    format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: mock\nclusters:\n- name: mock\n  cluster:\n    \
         server: {server}{ca}\ncontexts:\n- name: mock\n  context:\n    cluster: mock\n    user: alice\n    \
         namespace: default\n- name: other\n  context: {{cluster: mock, user: alice}}\nusers:\n- name: alice\n  \
         user:\n    token: {token}\n"
    )
}

fn new_cred(kind: &str, secrets: &[(&str, &str)]) -> NewCredential {
    NewCredential { name: format!("{kind} cred"), kind: kind.to_owned(), fields: json!({}), secrets: WireSecrets::of(secrets) }
}

/// A Kubernetes connection with `cred` and `options`.
pub(super) fn connection(f: &Fixture, cred: Option<&str>, options: Value) -> IpcResult<String> {
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string()))?;
    let c = tree::create_connection(
        &f.state,
        ConnectionFields {
            credential_id: cred.map(str::to_owned),
            ..ConnectionFields::basic(&root, "cluster", "kubernetes", "127.0.0.1")
        },
    )?;
    conn_options::set(&f.state, &c.id, options)?;
    Ok(c.id)
}

pub(super) async fn fixture_with(auth: Auth, mut cfg: KubeConfig, extra: Value, token: &str) -> Kube {
    let (cert, ca) = TestCert::generate_ca_issued(&["localhost", "127.0.0.1"]).expect("cert");
    cfg.cert = Some(match auth {
        Auth::KubeconfigTofu => TestCert::generate(&[]).expect("self-signed"),
        _ => cert,
    });
    let srv = mock::start(cfg, 0).await.expect("mock");
    let f = unlocked();
    let (cred, mut options) = match auth {
        Auth::TokenCa => {
            let c = credentials::create(&f.state, new_cred("kube_token", &[("token", token)])).expect("cred");
            (c.id, json!({ "server": srv.base_url(), "caPem": ca }))
        }
        Auth::KubeconfigCa | Auth::KubeconfigTofu => {
            let ca = (auth == Auth::KubeconfigCa).then_some(ca.as_str());
            let yaml = kubeconfig(&srv.base_url(), ca, token);
            let c = credentials::create(&f.state, new_cred("kubeconfig", &[("kubeconfig_yaml", &yaml)])).expect("cred");
            (c.id, json!({}))
        }
    };
    if let (Value::Object(o), Value::Object(extra)) = (&mut options, extra) {
        o.extend(extra);
    }
    let conn = connection(&f, Some(&cred), options).expect("connection");
    Kube { f, srv, conn, cred }
}

pub(super) async fn fixture(auth: Auth) -> Kube {
    fixture_with(auth, KubeConfig::default(), json!({}), TOKEN).await
}

pub(super) type Events = mpsc::UnboundedReceiver<Value>;

pub(super) fn cluster_sink() -> (ClusterSink, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(move |e| tx.send(serde_json::to_value(&e).expect("json")).is_ok()), rx)
}

pub(super) fn event_sink() -> (EventSink, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(move |e| tx.send(serde_json::to_value(&e).expect("json")).is_ok()), rx)
}

pub(super) async fn next(rx: &mut Events) -> Value {
    tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.expect("event within 20 s").expect("channel open")
}

/// The next event of `kind` (others are skipped).
pub(super) async fn until(rx: &mut Events, kind: &str) -> Value {
    loop {
        let e = next(rx).await;
        if e["kind"] == kind {
            return e;
        }
    }
}

/// Open the cluster session and wait for `connected`.
pub(super) async fn connected(k: &Kube) -> (String, Events, Value) {
    let (sink, mut rx) = cluster_sink();
    let id = open(&k.f.state, &k.conn, sink).expect("open").session_id;
    let e = next(&mut rx).await;
    assert_eq!(e["kind"], "connected", "{e}");
    (id, rx, e)
}

pub(super) async fn wait_gone(state: &AppState) {
    for _ in 0..400 {
        if state.sessions.lock().expect("lock").is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("sessions still registered");
}

pub(super) fn audited(state: &AppState, name: &str) -> usize {
    audit_events(state).iter().filter(|e| *e == name).count()
}

// ------------------------------------------------------------------ credential rules

#[tokio::test]
async fn credential_rules_fail_before_any_request() {
    let k = fixture(Auth::TokenCa).await;
    let st = &k.f.state;
    // kube_token: context is a kubeconfig option; server is required at open.
    let e = conn_options::set(st, &k.conn, json!({ "server": k.srv.base_url(), "caPem": null, "context": "x" }));
    assert_eq!(e.expect_err("context").code, "input.invalid");
    let incomplete = connection(&k.f, Some(&k.cred), json!({})).expect("saved while incomplete");
    let (sink, _rx) = cluster_sink();
    assert_eq!(open(st, &incomplete, sink).expect_err("no server").code, "input.invalid");
    // kubeconfig: server / caPem come from the file.
    let yaml = kubeconfig(&k.srv.base_url(), None, TOKEN);
    let kc = credentials::create(st, new_cred("kubeconfig", &[("kubeconfig_yaml", &yaml)])).expect("kc");
    let e = connection(&k.f, Some(&kc.id), json!({ "server": k.srv.base_url() })).expect_err("server");
    assert_eq!(e.code, "input.invalid");
    // A connection switched to that kubeconfig while it holds server/caPem is refused too.
    let root = st.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let fields = ConnectionFields { credential_id: Some(kc.id.clone()), ..ConnectionFields::basic(&root, "cluster", "kubernetes", "127.0.0.1") };
    assert_eq!(tree::update_connection(st, &k.conn, fields).expect_err("switch").code, "input.invalid");
    // ... and nothing changed.
    let (sink, mut rx) = cluster_sink();
    open(st, &k.conn, sink).expect("still the token connection");
    assert_eq!(next(&mut rx).await["kind"], "connected");
    // No credential, wrong protocol, unknown context.
    let bare = connection(&k.f, None, json!({})).expect("bare");
    let (sink, _rx) = cluster_sink();
    assert_eq!(open(st, &bare, sink).expect_err("no cred").code, "kube.unsupported_auth");
    let ssh = tree::create_connection(st, ConnectionFields::basic(&root, "ssh", "ssh", "127.0.0.1")).expect("ssh");
    let (sink, _rx) = cluster_sink();
    assert_eq!(open(st, &ssh.id, sink).expect_err("ssh").code, "input.invalid");
    let ctx = connection(&k.f, Some(&kc.id), json!({ "context": "missing" })).expect("ctx");
    let (sink, _rx) = cluster_sink();
    assert_eq!(open(st, &ctx, sink).expect_err("ctx").code, "credential.kubeconfig_rejected");
    assert_eq!(contexts(st, &kc.id).expect("contexts").contexts, ["mock", "other"]);
    assert_eq!(contexts(st, &k.cred).expect_err("token").code, "input.invalid");
    k.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn an_expired_jwt_fails_early_and_a_live_one_is_shown() {
    let jwt = |exp: i64| {
        let e = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        format!("{}.{}.sig", e(r#"{"alg":"RS256"}"#), e(&format!(r#"{{"exp":{exp}}}"#)))
    };
    let expired = jwt(1_000_000);
    let cfg = KubeConfig { token: Some(expired.clone()), ..KubeConfig::default() };
    let k = fixture_with(Auth::TokenCa, cfg, json!({}), &expired).await;
    let (sink, _rx) = cluster_sink();
    assert_eq!(open(&k.f.state, &k.conn, sink).expect_err("expired").code, "kube.auth_failed");
    assert!(k.srv.recorder().is_empty(), "nothing was sent");

    let live = jwt(4_102_444_800); // 2100-01-01
    let cfg = KubeConfig { token: Some(live.clone()), ..KubeConfig::default() };
    let k = fixture_with(Auth::KubeconfigCa, cfg, json!({}), &live).await;
    let (_, _rx, e) = connected(&k).await;
    assert_eq!(e["tokenExpiresAt"], "2100-01-01T00:00:00Z");
}

#[tokio::test]
async fn a_wrong_token_closes_with_auth_failed() {
    let k = fixture_with(Auth::TokenCa, KubeConfig::default(), json!({}), "wrong-token").await;
    let (sink, mut rx) = cluster_sink();
    open(&k.f.state, &k.conn, sink).expect("open");
    let e = next(&mut rx).await;
    assert_eq!((e["kind"].as_str(), e["code"].as_str()), (Some("closed"), Some("auth_failed")), "{e}");
    wait_gone(&k.f.state).await;
    assert!(!e.to_string().contains("wrong-token"));
}

// ------------------------------------------------------------------ guard / audit mapping

#[test]
fn secrets_and_mutations_cannot_be_expressed_through_the_client() {
    use mooring_proto_kube::{check, GuardPolicy, RequestShape};
    let policy = GuardPolicy { max_log_bytes: 1024 };
    let ok = |m: &str, p: &str, ws: bool| {
        let method: tauri::http::Method = m.parse().expect("method");
        let uri: tauri::http::Uri = p.parse().expect("uri");
        check(RequestShape { method: &method, uri: &uri, websocket: ws, impersonates: false }, policy).is_ok()
    };
    assert!(ok("GET", "/api/v1/namespaces/default/pods", false));
    for (m, p) in [
        ("GET", "/api/v1/namespaces/default/secrets"),
        ("GET", "/api/v1/namespaces/default/secrets/db"),
        ("GET", "/api/v1/namespaces/default/configmaps"),
        ("GET", "/api/v1/secrets"),
        ("DELETE", "/api/v1/namespaces/default/pods/web-0"),
        ("POST", "/api/v1/namespaces/default/pods"),
        ("PATCH", "/api/v1/namespaces/default/pods/web-0"),
        ("GET", "/api/v1/namespaces/default/pods/../secrets"),
        ("GET", "/api/v1/namespaces/default/pods?dryRun=All"),
    ] {
        assert!(!ok(m, p, false), "{m} {p}");
    }
    // The refusal becomes `kube_request_refused` (method + template only).
    let e = kube_wire::audit_event("c", mooring_proto_kube::KubeAudit::RequestRefused { method: "GET", template: "unlisted" });
    let v = serde_json::to_value(e.expect("event")).expect("json");
    assert_eq!(v["event"], "kube_request_refused");
    assert_eq!(v["template"], "unlisted");
}

#[test]
fn kube_errors_map_to_literal_codes() {
    use mooring_proto_kube::KubeError as K;
    for (e, code) in [
        (K::RbacDenied, "kube.rbac_denied"),
        (K::NotFound, "kube.not_found"),
        (K::Unauthorized, "kube.auth_failed"),
        (K::StreamLimit, "kube.stream_limit"),
        (K::Invalid("x"), "input.invalid"),
        (K::Status(500), "kube.status"),
        (K::Protocol("x"), "kube.protocol"),
        (K::Closed, "kube.closed"),
    ] {
        assert_eq!(kube_wire::kube_error(&e).code, code);
    }
}

#[test]
fn cluster_events_have_the_documented_shape() {
    let e = ClusterEvent::Closed { reason: "vault locked".into(), code: mooring_core::CloseCode::VaultLocked };
    assert_eq!(serde_json::to_value(&e).expect("json"), json!({ "kind": "closed", "reason": "vault locked", "code": "vault_locked" }));
    let d = kube_wire::LogChunkDto::from(mooring_proto_kube::LogChunk::Data(b"hi\n".to_vec()));
    assert_eq!(serde_json::to_value(&d).expect("json"), json!({ "kind": "data", "data": "aGkK" }));
    let a = serde_json::to_value(AccessDto { exec: true, ..AccessDto::default() }).expect("json");
    assert_eq!(a, json!({ "listPods": false, "getLogs": false, "exec": true, "portForward": false, "listNamespaces": false }));
}
