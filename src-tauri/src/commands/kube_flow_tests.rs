//! End-to-end command flows against the kube mock: open → pre-flight → browse → exec →
//! logs (with the byte cap) → pod forward → lock ends everything; the certificate prompt;
//! RBAC denials; hostile inputs.

use std::time::Duration;

use mooring_testsrv::kube::{AccessRule, KubeConfig, KubeKnobs};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::commands::forward::{self, WireEndpoint};
use crate::commands::kube_logs::{self, ChunkSink, LogsRequest};
use crate::commands::sessions as sess;

fn exec_req(pod: &str, command: Option<&str>) -> ExecRequest {
    ExecRequest { namespace: "default".into(), pod: pod.into(), container: None, command: command.map(str::to_owned), size: SIZE }
}

fn chunk_sink() -> (ChunkSink, Events) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (Arc::new(move |c| tx.send(serde_json::to_value(&c).expect("json")).is_ok()), rx)
}

/// Data of a log stream up to its `end` event.
async fn drain_log(rx: &mut Events) -> (String, Value) {
    let mut text = Vec::new();
    loop {
        let c = next(rx).await;
        if c["kind"] == "end" {
            return (String::from_utf8(text).expect("utf8"), c);
        }
        let data = c["data"].as_str().expect("data");
        text.extend(base64::engine::general_purpose::STANDARD.decode(data).expect("b64"));
    }
}

async fn read_bytes_until(rx: &mut Events, needle: &str) -> String {
    let mut out = String::new();
    while !out.contains(needle) {
        let e = next(rx).await;
        assert_ne!(e["kind"], "closed", "closed early: {e} after {out:?}");
        if e["kind"] == "bytes" {
            let raw = base64::engine::general_purpose::STANDARD.decode(e["data"].as_str().expect("d")).expect("b64");
            out.push_str(&String::from_utf8_lossy(&raw));
        }
    }
    out
}

fn bytes(s: &str) -> sess::WireInput {
    serde_json::from_value(json!({ "kind": "bytes", "data": base64::engine::general_purpose::STANDARD.encode(s) })).expect("input")
}

fn loopback() -> WireEndpoint {
    WireEndpoint { host: "127.0.0.1".into(), port: 0 }
}

#[tokio::test]
async fn open_browse_exec_logs_forward_then_lock_ends_everything() {
    let k = fixture(Auth::TokenCa).await;
    let st = &k.f.state;
    let (cid, mut cluster, e) = connected(&k).await;
    assert_eq!(e["identity"]["user"], "alice");
    assert_eq!(e["namespace"], "default");
    assert_eq!(e["rbac"], json!({ "listPods": true, "getLogs": true, "exec": true, "portForward": true, "listNamespaces": true }));
    assert_eq!(e["execCommand"], "/bin/sh");
    assert!(e["tokenExpiresAt"].is_null());

    // Browse.
    assert!(access(st, &cid, "team-a").await.expect("access").exec);
    let ns = namespaces(st, &cid).await.expect("namespaces");
    assert_eq!(ns.items, ["default", "kube-system", "team-a"]);
    let pods_default = pods(st, &cid, "default", None).await.expect("pods");
    assert_eq!(pods_default.items.len(), 2);
    let web = pods(st, &cid, "default", Some("app=web")).await.expect("selector");
    assert_eq!(web.items.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["web-0"]);
    assert_eq!(pod(st, &cid, "default", "web-0").await.expect("pod").containers.len(), 2);
    assert_eq!(pod(st, &cid, "default", "nope").await.expect_err("404").code, "kube.not_found");

    // Exec: an ordinary session; echo, then `exit 3`.
    let (sink, mut term) = event_sink();
    let xid = exec_open(st, &cid, exec_req("db-0", None), sink).await.expect("exec").session_id;
    assert_eq!(until(&mut term, "connected").await["protocol"], "kubernetes");
    sess::send(st, &xid, bytes("hello kube\n")).await.expect("send");
    read_bytes_until(&mut term, "hello kube").await;
    let rows = sess::list(st).expect("list");
    let kinds: Vec<(Option<&str>, Option<&str>)> = rows.iter().map(|r| (r.kind, r.parent_session_id.as_deref())).collect();
    assert!(kinds.contains(&(Some("cluster"), None)) && kinds.contains(&(Some("exec"), Some(cid.as_str()))), "{kinds:?}");
    sess::send(st, &xid, bytes("exit 3\n")).await.expect("exit");
    assert_eq!(until(&mut term, "closed").await["code"], "server_ended");
    assert_eq!(k.srv.exec_sessions()[0].command, ["/bin/sh"]);

    // A second shell that the lock will end.
    let (sink, mut term2) = event_sink();
    let xid2 = exec_open(st, &cid, exec_req("db-0", Some("bash")), sink).await.expect("exec 2").session_id;
    until(&mut term2, "connected").await;

    // Logs: a whole stream, then a following one the lock will end.
    let (sink, mut logs) = chunk_sink();
    let req = LogsRequest { namespace: "default".into(), pod: "db-0".into(), tail_lines: Some(3), ..LogsRequest::default() };
    kube_logs::open(st, &cid, req, sink).await.expect("logs");
    let (text, end) = drain_log(&mut logs).await;
    assert_eq!(text.lines().count(), 3, "{text}");
    assert_eq!(end, json!({ "kind": "end", "truncated": false, "reason": null }));
    let knobs = KubeKnobs { follow_lines: 100_000, follow_interval: Duration::from_millis(50), ..KubeKnobs::default() };
    k.srv.set_knobs(knobs);
    let (sink, mut follow) = chunk_sink();
    let req = LogsRequest { namespace: "default".into(), pod: "db-0".into(), follow: true, ..LogsRequest::default() };
    let sid = kube_logs::open(st, &cid, req, sink).await.expect("follow").stream_id;
    next(&mut follow).await;

    // Pod forward: loopback echo through the mock.
    let target = json!({ "namespace": "default", "pod": "db-0", "port": 5432 });
    let fwd = forward::open_any(st, &cid, "pod".into(), loopback(), Some(target), None).await.expect("forward");
    let forward::AnyForward::Pod(fwd) = fwd else { panic!("pod forward") };
    assert_eq!((fwd.kind, fwd.exposure, fwd.bind.host.as_str()), ("pod", "loopback", "127.0.0.1"));
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", fwd.bind.port)).await.expect("connect");
    tcp.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut buf)).await.expect("echo in time").expect("read");
    assert_eq!(&buf, b"ping");
    assert_eq!(forward::list_any(st, &cid).expect("list").len(), 1);

    // Lock: cluster, shell, log stream and forward all end; the token is gone with them.
    crate::commands::vault::lock(st, None).expect("lock");
    let closed = until(&mut cluster, "closed").await;
    assert_eq!(closed["code"], "vault_locked");
    assert_eq!(until(&mut term2, "closed").await["code"], "vault_locked");
    wait_gone(st).await;
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", fwd.bind.port)).await.is_err(), "listener closed");
    assert_eq!(kube_logs::close(st, &cid, &sid).expect_err("gone").code, "session.not_found");
    let _ = xid2;
    for name in [
        "kube_cluster_opened",
        "kube_cluster_closed",
        "kube_exec_opened",
        "kube_exec_closed",
        "kube_logs_opened",
        "kube_logs_closed",
        "kube_forward_opened",
        "kube_forward_closed",
    ] {
        assert!(audited(st, name) >= 1, "{name}: {:?}", audit_events(st));
    }
    assert_eq!(audited(st, "kube_exec_opened"), 2);
    assert_eq!(audited(st, "kube_logs_closed"), 2);
    k.srv.recorder().assert_no_violations();
    assert!(!std::fs::read_to_string(st.data_dir.join(crate::state::AppState::AUDIT_FILE)).expect("audit").contains("test-token"));
}

#[tokio::test]
async fn logs_stop_at_the_byte_cap_and_streams_are_limited() {
    let knobs = KubeKnobs { huge_log: Some(1 << 20), ..KubeKnobs::default() };
    let cfg = KubeConfig { knobs, ..KubeConfig::default() };
    let k = fixture_with(Auth::KubeconfigCa, cfg, json!({ "maxLogBytes": 4096 }), "test-token").await;
    let st = &k.f.state;
    let (cid, _cluster, _) = connected(&k).await;
    let (sink, mut rx) = chunk_sink();
    let req = LogsRequest { namespace: "default".into(), pod: "db-0".into(), ..LogsRequest::default() };
    kube_logs::open(st, &cid, req, sink).await.expect("logs");
    let (text, end) = drain_log(&mut rx).await;
    assert!(text.len() <= 4096, "{}", text.len());
    assert_eq!(end, json!({ "kind": "end", "truncated": true, "reason": "kube.stream_limit" }));
    // 8 following streams per cluster; the 9th is refused.
    let knobs = KubeKnobs { follow_lines: 100_000, follow_interval: Duration::from_millis(100), ..KubeKnobs::default() };
    k.srv.set_knobs(knobs);
    let mut keep = Vec::new();
    for _ in 0..8 {
        let (sink, rx) = chunk_sink();
        let req = LogsRequest { namespace: "default".into(), pod: "db-0".into(), follow: true, ..LogsRequest::default() };
        keep.push((kube_logs::open(st, &cid, req, sink).await.expect("stream").stream_id, rx));
    }
    let (sink, _rx) = chunk_sink();
    let req = LogsRequest { namespace: "default".into(), pod: "db-0".into(), follow: true, ..LogsRequest::default() };
    assert_eq!(kube_logs::open(st, &cid, req, sink).await.expect_err("9th").code, "kube.stream_limit");
    let (id, _) = keep.pop().expect("one");
    kube_logs::close(st, &cid, &id).expect("close");
    assert_eq!(kube_logs::close(st, &cid, &id).expect_err("twice").code, "kube.not_found");
    sess::close(st, &cid).await.expect("close cluster");
    wait_gone(st).await;
    assert_eq!(audited(st, "kube_logs_closed"), 9);
    k.srv.recorder().assert_no_violations();
}

async fn prompted(k: &Kube) -> (String, Events, Value) {
    let (sink, mut rx) = cluster_sink();
    let id = open(&k.f.state, &k.conn, sink).expect("open").session_id;
    let p = next(&mut rx).await;
    assert_eq!((p["kind"].as_str(), p["purpose"].as_str()), (Some("prompt"), Some("certificate_trust")), "{p}");
    assert!(p["certificate"]["sha256"].is_string());
    (id, rx, p)
}

async fn answer(st: &AppState, id: &str, p: &Value, text: &str) {
    let input = serde_json::from_value(json!({ "kind": "answer", "id": p["id"], "text": text })).expect("answer");
    sess::send(st, id, input).await.expect("answer accepted");
}

#[tokio::test]
async fn the_certificate_prompt_pins_on_yes_trusts_once_and_rejects_no() {
    let k = fixture(Auth::KubeconfigTofu).await;
    let st = &k.f.state;
    let pins = known_certs_path(st, CertProtocol::Kube);
    // no → closed trust_rejected, nothing pinned.
    let (id, mut rx, p) = prompted(&k).await;
    assert_eq!(sess::send(st, &id, bytes("x")).await.expect_err("not an answer").code, "input.invalid");
    answer(st, &id, &p, "no").await;
    assert_eq!(until(&mut rx, "closed").await["code"], "trust_rejected");
    assert!(!pins.exists() || std::fs::read_to_string(&pins).expect("pins").trim().is_empty());
    // once → connected, still not pinned; the next open prompts again.
    let (id, mut rx, p) = prompted(&k).await;
    answer(st, &id, &p, "once").await;
    assert_eq!(next(&mut rx).await["kind"], "connected");
    sess::close(st, &id).await.expect("close");
    // yes → pinned; the next open connects without a prompt.
    let (id, mut rx, p) = prompted(&k).await;
    answer(st, &id, &p, "yes").await;
    assert_eq!(next(&mut rx).await["kind"], "connected");
    sess::close(st, &id).await.expect("close");
    let (_, _rx, _) = connected(&k).await;
    let decisions = std::fs::read_to_string(st.data_dir.join(crate::state::AppState::AUDIT_FILE)).expect("audit");
    for d in ["\"rejected\"", "\"trusted_once\"", "\"accepted\""] {
        assert!(decisions.contains(d), "{d}");
    }
    // Lock while a prompt is open: closed vault_locked.
    let _ = std::fs::remove_file(&pins);
    let (_, mut rx, _) = prompted(&k).await;
    crate::commands::vault::lock(st, None).expect("lock");
    assert_eq!(until(&mut rx, "closed").await["code"], "vault_locked");
    k.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn rbac_denials_surface_as_flags_and_codes() {
    let rules = vec![AccessRule::new(&["get", "list"], &["pods"]).in_namespaces(&["default"])];
    let cfg = KubeConfig { rules, ..KubeConfig::default() };
    let k = fixture_with(Auth::KubeconfigCa, cfg, json!({ "allowedNamespaces": ["default", "team-a"] }), "test-token").await;
    let st = &k.f.state;
    let (cid, _rx, e) = connected(&k).await;
    assert_eq!(e["rbac"], json!({ "listPods": true, "getLogs": false, "exec": false, "portForward": false, "listNamespaces": false }));
    assert_eq!(e["allowedNamespaces"], json!(["default", "team-a"]));
    assert_eq!(namespaces(st, &cid).await.expect_err("denied").code, "kube.rbac_denied");
    let (sink, _t) = event_sink();
    assert_eq!(exec_open(st, &cid, exec_req("db-0", None), sink).await.expect_err("exec").code, "kube.rbac_denied");
    let (sink, _l) = chunk_sink();
    let req = LogsRequest { namespace: "default".into(), pod: "db-0".into(), ..LogsRequest::default() };
    assert_eq!(kube_logs::open(st, &cid, req, sink).await.expect_err("logs").code, "kube.rbac_denied");
    assert!(!access(st, &cid, "team-a").await.expect("access").list_pods);
    k.srv.recorder().assert_no_violations();
}

#[tokio::test]
async fn hostile_inputs_are_refused_before_any_request() {
    let k = fixture(Auth::KubeconfigCa).await;
    let st = &k.f.state;
    let (cid, _rx, _) = connected(&k).await;
    k.srv.recorder().clear();
    for bad in ["../x", "Default", "", "a/b", "x%2Fy", &"a".repeat(64), "kube\u{202e}"] {
        assert_eq!(pods(st, &cid, bad, None).await.expect_err(bad).code, "input.invalid", "{bad:?}");
        assert_eq!(access(st, &cid, bad).await.expect_err(bad).code, "input.invalid");
    }
    assert_eq!(pod(st, &cid, "default", "../../secrets").await.expect_err("pod").code, "input.invalid");
    assert_eq!(pods(st, &cid, "default", Some(&"a".repeat(2000))).await.expect_err("sel").code, "input.invalid");
    let (sink, _t) = event_sink();
    for (pod, cmd) in [("db-0", Some("/bin/rm")), ("db-0", Some("sh -c id")), ("A B", None)] {
        let e = exec_open(st, &cid, exec_req(pod, cmd), sink.clone()).await.expect_err("exec");
        assert_eq!(e.code, "input.invalid");
    }
    let mut r = exec_req("db-0", None);
    r.container = Some("Bad_Name".into());
    assert_eq!(exec_open(st, &cid, r, sink.clone()).await.expect_err("container").code, "input.invalid");
    let (lsink, _l) = chunk_sink();
    for req in [
        LogsRequest { namespace: "default".into(), pod: "db-0".into(), tail_lines: Some(0), ..LogsRequest::default() },
        LogsRequest { namespace: "default".into(), pod: "db-0".into(), since_seconds: Some(u64::MAX), ..LogsRequest::default() },
    ] {
        assert_eq!(kube_logs::open(st, &cid, req, lsink.clone()).await.expect_err("logs").code, "input.invalid");
    }
    let t = || Some(json!({ "namespace": "default", "pod": "db-0", "port": 5432 }));
    let ext = forward::open_any(st, &cid, "pod".into(), loopback(), t(), Some("external".into())).await;
    assert_eq!(ext.expect_err("external").code, "input.invalid");
    let lan = WireEndpoint { host: "192.0.2.10".into(), port: 0 };
    assert_eq!(forward::open_any(st, &cid, "pod".into(), lan, t(), None).await.expect_err("lan").code, "input.invalid");
    let local = forward::open_any(st, &cid, "local".into(), loopback(), Some(json!({ "host": "x.example.test", "port": 1 })), None).await;
    assert_eq!(local.expect_err("ssh kind").code, "input.invalid");
    let extra = Some(json!({ "namespace": "default", "pod": "db-0", "port": 5432, "host": "x" }));
    assert_eq!(forward::open_any(st, &cid, "pod".into(), loopback(), extra, None).await.expect_err("extra").code, "input.invalid");
    let port0 = Some(json!({ "namespace": "default", "pod": "db-0", "port": 0 }));
    assert_eq!(forward::open_any(st, &cid, "pod".into(), loopback(), port0, None).await.expect_err("p0").code, "input.invalid");
    assert!(k.srv.recorder().is_empty(), "{:?}", k.srv.recorder().lines());
    // Unknown and wrong-kind session ids.
    assert_eq!(namespaces(st, "nope").await.expect_err("unknown").code, "session.not_found");
    assert_eq!(namespaces(st, &"x".repeat(65)).await.expect_err("long").code, "input.invalid");
    let (sink, mut term) = event_sink();
    let xid = exec_open(st, &cid, exec_req("db-0", None), sink).await.expect("exec").session_id;
    until(&mut term, "connected").await;
    assert_eq!(namespaces(st, &xid).await.expect_err("exec id").code, "input.invalid");
    // Closing the cluster closes its shell.
    sess::close(st, &cid).await.expect("close");
    assert_eq!(until(&mut term, "closed").await["kind"], "closed");
    wait_gone(st).await;
    k.srv.recorder().assert_no_violations();
}
