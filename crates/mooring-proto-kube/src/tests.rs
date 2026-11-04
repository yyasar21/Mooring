//! Loopback tests against [`crate::mock`]: browsing, pagination, RBAC, logs, exec, port-forward,
//! and the gate that every recorded request is on the allow-list.

use std::time::Duration;

use http::Method;
use mooring_core::options::ExecCommand;
use mooring_core::session::{CloseCode, Session, SessionEvent, SessionInput, Size};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::mock::{limits, Mock, TOKEN};
use crate::{
    check, ExecTarget, GuardPolicy, KubeAudit, KubeError, LogChunk, LogParams, PodForward,
    PodTarget, RequestShape, STREAM_LIMIT,
};

/// Every request the mock saw must pass the guard (ADR-0014 test plan: recorded ⊆ allow-list).
fn assert_all_allowed(m: &Mock) {
    for s in m.seen() {
        let uri: http::Uri = s.uri.parse().expect("uri");
        let ws = s.uri.contains("/exec?") || s.uri.contains("/portforward?");
        let shape =
            RequestShape { method: &s.method, uri: &uri, websocket: ws, impersonates: false };
        assert!(
            check(shape, GuardPolicy { max_log_bytes: 64 << 20 }).is_ok(),
            "{} {}",
            s.method,
            s.uri
        );
        assert!(s.authorized, "bearer missing on {}", s.uri);
    }
}

async fn timeout<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f).await.expect("timed out")
}

#[tokio::test]
async fn browse_namespaces_pods_and_one_pod() {
    let m = Mock::start().await;
    let c = m.client();
    assert_eq!(c.version().await.expect("version"), "v1.33.2");
    let ns = c.namespaces().await.expect("namespaces");
    assert_eq!(ns.items, ["default", "kube-system"], "page 2 followed, invalid name dropped");
    assert!(!ns.truncated);
    let pods = c.pods("ns", Some("app=web")).await.expect("pods");
    assert_eq!(pods.items.len(), 2);
    let p = &pods.items[0];
    assert_eq!(
        (p.name.as_str(), p.phase.as_str(), p.node.as_deref()),
        ("web-1", "Running", Some("node-a"))
    );
    assert_eq!(p.restarts, 3);
    assert_eq!(p.containers[0].image, "registry.example.test/app:1[31m", "ESC stripped");
    assert_eq!(p.containers[0].ports, [8080]);
    assert!(p.containers[0].ready && !p.containers[1].ready);
    assert!(p.age_seconds.is_some());
    assert_eq!(c.pod("ns", "web-1").await.expect("pod").name, "web-1");
    assert!(matches!(c.pod("ns", "nope").await, Err(KubeError::NotFound)));
    assert!(matches!(c.pods("NS", None).await, Err(KubeError::Invalid(_))));
    assert!(matches!(c.pods("ns", Some("a;b")).await, Err(KubeError::Invalid(_))));
    let seen = m.seen();
    assert!(seen.iter().any(|s| s.uri == "/api/v1/namespaces?limit=500&continue=tok%2B2%2F%3D"));
    assert!(seen
        .iter()
        .any(|s| s.uri == "/api/v1/namespaces/ns/pods?limit=500&labelSelector=app%3Dweb"));
    assert_all_allowed(&m);
}

#[tokio::test]
async fn wrong_token_is_unauthorized() {
    let m = Mock::start().await;
    let c = m.client_with(limits(1024), Some("other"));
    assert!(matches!(c.version().await, Err(KubeError::Unauthorized)));
}

#[tokio::test]
async fn preflight_maps_reviews() {
    let m = Mock::start().await;
    let r = m.client().preflight("ns").await.expect("preflight");
    assert!(r.can_list_pods && r.can_get_logs && r.can_exec);
    assert!(!r.can_port_forward && !r.can_list_namespaces);
    let id = r.identity.expect("identity");
    assert_eq!(id.user, "system:serviceaccount:ns:viewer", "bidi stripped");
    assert_eq!(id.groups, ["system:authenticated"]);
    assert_eq!(r.rules.len(), 1);
    assert_eq!(r.rules[0].resources, ["pods", "pods/log"]);
    assert!(m.seen().iter().all(|s| s.method == Method::POST));
    assert_all_allowed(&m);
}

#[tokio::test]
async fn refused_request_never_reaches_the_server() {
    let m = Mock::start().await;
    let c = m.client();
    let req =
        http::Request::delete("/api/v1/namespaces/ns/pods/web-1").body(Vec::new()).expect("req");
    let err = c.send(req, false).await.expect_err("refused");
    assert_eq!(err.code(), "kube.refused");
    let req = http::Request::get("/api/v1/namespaces/ns/secrets").body(Vec::new()).expect("req");
    assert!(matches!(c.send(req, false).await, Err(KubeError::Forbidden(_))));
    assert!(m.seen().is_empty(), "nothing left the process");
    let audit = c.audit().take();
    assert_eq!(audit.len(), 2);
    assert_eq!(
        audit[0],
        KubeAudit::RequestRefused {
            method: "DELETE",
            template: "/api/v1/namespaces/{ns}/pods/{pod}"
        }
    );
    assert_eq!(audit[1], KubeAudit::RequestRefused { method: "GET", template: "unlisted" });
}

async fn collect(s: &mut crate::LogStream) -> (Vec<u8>, LogChunk) {
    let mut data = Vec::new();
    loop {
        match timeout(s.next()).await.expect("chunk").expect("not none before end") {
            LogChunk::Data(d) => data.extend(d),
            end @ LogChunk::End { .. } => return (data, end),
        }
    }
}

#[tokio::test]
async fn logs_are_sanitised_and_capped() {
    let m = Mock::start().await;
    let c = m.client_with(limits(4096), Some(TOKEN));
    let mut s = c.logs("ns", "web-1", LogParams::default()).await.expect("logs");
    let (data, end) = collect(&mut s).await;
    assert_eq!(String::from_utf8(data).expect("utf8"), "line one bold\ntwo ok\npartial");
    assert_eq!(end, LogChunk::End { truncated: false, reason: None });
    assert!(timeout(s.next()).await.expect("ok").is_none());
    let follow = LogParams { follow: true, container: Some("app".into()), ..LogParams::default() };
    let mut s = c.logs("ns", "web-1", follow).await.expect("logs");
    let (data, end) = collect(&mut s).await;
    assert!(data.len() <= 4096, "{}", data.len());
    assert_eq!(end, LogChunk::End { truncated: true, reason: Some(STREAM_LIMIT) });
    let uri = &m.seen()[1].uri;
    assert!(
        uri.contains("limitBytes=4096")
            && uri.contains("tailLines=500")
            && uri.contains("container=app"),
        "{uri}"
    );
    assert!(c.audit().take().iter().any(|a| a.action() == "kube.logs.opened"));
    assert_all_allowed(&m);
}

#[tokio::test]
async fn log_streams_are_limited_per_cluster() {
    let m = Mock::start().await;
    let c = m.client();
    let mut open = Vec::new();
    for _ in 0..crate::MAX_LOG_STREAMS {
        open.push(c.logs("ns", "web-1", LogParams::default()).await.expect("slot"));
    }
    let err = c.logs("ns", "web-1", LogParams::default()).await.expect_err("ninth");
    assert_eq!(err.code(), "kube.stream_limit");
    open.pop();
    assert!(c.logs("ns", "web-1", LogParams::default()).await.is_ok());
}

async fn next(s: &mut crate::ExecSession) -> SessionEvent {
    timeout(s.next_event()).await.expect("event").expect("some")
}

#[tokio::test]
async fn exec_session_echoes_resizes_and_reports_exit() {
    let m = Mock::start().await;
    let c = m.client();
    let target = ExecTarget {
        namespace: "ns".into(),
        pod: "web-1".into(),
        container: Some("app".into()),
        command: ExecCommand::BinBash,
    };
    let mut s = c.exec(target, Some(Size { width: 80, height: 24 })).await.expect("exec");
    assert!(
        matches!(next(&mut s).await, SessionEvent::Connected { security: Some(p), .. } if p == "v5.channel.k8s.io")
    );
    s.send(SessionInput::Bytes { data: b"ls\n".to_vec() }).await.expect("send");
    assert!(matches!(next(&mut s).await, SessionEvent::Bytes { data } if data == b"ls\n"));
    for w in [100, 120, 132] {
        s.send(SessionInput::Resize { size: Size { width: w, height: 40 } }).await.expect("resize");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    s.send(SessionInput::Bytes { data: b"exit 7\n".to_vec() }).await.expect("send");
    let SessionEvent::Closed { code, reason } = next(&mut s).await else { panic!("closed") };
    assert_eq!(code, CloseCode::ServerEnded);
    assert!(reason.contains('7'), "{reason}");
    let resizes = m.state.lock().expect("lock").resizes.clone();
    assert_eq!(
        resizes,
        ["{\"Width\":80,\"Height\":24}", "{\"Width\":132,\"Height\":40}"],
        "debounced"
    );
    assert!(s.send(SessionInput::Bytes { data: vec![1] }).await.is_err());
    let uri = m.seen().into_iter().find(|x| x.uri.contains("/exec")).expect("exec").uri;
    assert!(uri.contains("command=%2Fbin%2Fbash") && uri.contains("tty=true"), "{uri}");
    let actions: Vec<_> = c.audit().take().iter().map(KubeAudit::action).collect();
    assert_eq!(actions, ["kube.exec.opened", "kube.exec.closed"]);
    assert_all_allowed(&m);
}

#[tokio::test]
async fn exec_close_by_user_and_input_caps() {
    let m = Mock::start().await;
    let c = m.client();
    let target = ExecTarget {
        namespace: "ns".into(),
        pod: "web-1".into(),
        container: None,
        command: ExecCommand::Sh,
    };
    let mut s = c.exec(target, None).await.expect("exec");
    let _ = next(&mut s).await;
    let big = SessionInput::Bytes { data: vec![0; crate::MAX_BYTES + 1] };
    assert!(s.send(big).await.is_err());
    assert!(s.send(SessionInput::ReleaseAll).await.is_err());
    s.close().await.expect("close");
    assert!(matches!(next(&mut s).await, SessionEvent::Closed { code: CloseCode::User, .. }));
    assert!(timeout(s.next_event()).await.expect("ok").is_none());
    let bad = ExecTarget {
        namespace: "ns".into(),
        pod: "../x".into(),
        container: None,
        command: ExecCommand::Sh,
    };
    assert!(matches!(c.exec(bad, None).await, Err(KubeError::Invalid(_))));
}

#[tokio::test]
async fn port_forward_stream_and_loopback_listener() {
    let m = Mock::start().await;
    let c = m.client();
    let target = PodTarget { namespace: "ns".into(), pod: "web-1".into(), port: 8080 };
    let mut s = c.port_forward(&target).await.expect("pf");
    s.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    timeout(s.read_exact(&mut buf)).await.expect("read");
    assert_eq!(&buf, b"ping");
    drop(s);

    let any: std::net::SocketAddr = "0.0.0.0:0".parse().expect("addr");
    assert!(matches!(
        PodForward::open(&c, "fwd-1", any, target.clone()).await,
        Err(KubeError::Invalid(_))
    ));
    let lo: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let mut fwd = PodForward::open(&c, "fwd-1", lo, target).await.expect("listen");
    let mut tcp = tokio::net::TcpStream::connect(fwd.local_addr()).await.expect("connect");
    tcp.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 5];
    timeout(tcp.read_exact(&mut buf)).await.expect("read");
    assert_eq!(&buf, b"hello");
    fwd.close();
    let actions: Vec<_> = c.audit().take().iter().map(KubeAudit::action).collect();
    assert_eq!(actions, ["session.forward.open", "session.forward.close"]);
    assert!(m
        .seen()
        .iter()
        .all(|x| x.uri == "/api/v1/namespaces/ns/pods/web-1/portforward?ports=8080"));
    assert_all_allowed(&m);

    let off = m.client_with(
        crate::KubeLimits { port_forward_enabled: false, ..limits(1024) },
        Some(TOKEN),
    );
    let t = PodTarget { namespace: "ns".into(), pod: "web-1".into(), port: 80 };
    assert!(matches!(off.port_forward(&t).await, Err(KubeError::Invalid(_))));
}

/// ADR-0014 §2: kube's config loaders are never called (clippy `disallowed-methods` too).
#[test]
fn no_kube_config_loader_in_sources() {
    let banned = [
        "Config::infer",
        "Config::from_kubeconfig",
        "Config::from_custom_kubeconfig",
        "Kubeconfig::read",
        "Kubeconfig::from_yaml",
        "try_default",
        "Config::incluster",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(dir).expect("src") {
        let path = entry.expect("entry").path();
        if path.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read");
        for b in banned {
            assert!(!text.contains(b), "{} uses {b}", path.display());
        }
    }
}
