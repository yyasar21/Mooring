//! The guard matrix (ADR-0014 test plan): every allowed row, every other method on it,
//! unlisted resources, traversal / encoding tricks, query injection, proptests.

use http::Method;
use proptest::prelude::*;

use super::*;

const P: GuardPolicy = GuardPolicy { max_log_bytes: 1024 };

fn run(method: &Method, uri: &str, websocket: bool) -> Result<Route, Refused> {
    let uri: http::Uri = uri.parse().expect("uri");
    check(RequestShape { method, uri: &uri, websocket, impersonates: false }, P)
}

fn ok(method: &Method, uri: &str, ws: bool) -> Route {
    run(method, uri, ws).unwrap_or_else(|e| panic!("{method} {uri} refused: {}", e.reason))
}

fn refused(method: &Method, uri: &str, ws: bool) {
    assert!(run(method, uri, ws).is_err(), "{method} {uri} (ws={ws}) was allowed");
}

const NS: &str = "/api/v1/namespaces/team-a";
const POD: &str = "/api/v1/namespaces/team-a/pods/web-7d9f.x";

/// (route, a concrete request URI, kind).
fn rows() -> Vec<(Route, String)> {
    vec![
        (Route::Version, "/version".into()),
        (Route::Api, "/api".into()),
        (Route::Apis, "/apis".into()),
        (Route::Namespaces, "/api/v1/namespaces?limit=500".into()),
        (Route::Namespace, NS.into()),
        (Route::Pods, format!("{NS}/pods?limit=500&labelSelector=app%3Dweb%2Ctier+in+%28a%2Cb%29")),
        (Route::Pod, POD.into()),
        (Route::PodLog, format!("{POD}/log?container=app&follow=true&tailLines=10000&limitBytes=1024&sinceSeconds=60&timestamps=1")),
        (Route::PodExec, format!("{POD}/exec?command=%2Fbin%2Fsh&container=app&stdin=true&stdout=true&stderr=false&tty=true")),
        (Route::PodPortForward, format!("{POD}/portforward?ports=8080")),
        (Route::AccessReview, Route::AccessReview.template().into()),
        (Route::RulesReview, Route::RulesReview.template().into()),
        (Route::SelfReview, Route::SelfReview.template().into()),
    ]
}

#[test]
fn every_allowed_row_and_only_its_methods() {
    let all = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
        Method::CONNECT,
        Method::TRACE,
    ];
    let rows = rows();
    assert_eq!(rows.len(), Route::ALL.len());
    for (route, uri) in rows {
        for m in &all {
            for ws in [false, true] {
                let allowed = match route.kind() {
                    Kind::Read => (*m == Method::GET || *m == Method::HEAD) && !ws,
                    Kind::Upgrade => *m == Method::GET && ws,
                    Kind::Post => *m == Method::POST && !ws,
                };
                if allowed {
                    assert_eq!(ok(m, &uri, ws), route);
                } else {
                    refused(m, &uri, ws);
                }
            }
        }
    }
    let custom = Method::from_bytes(b"PROPFIND").expect("m");
    let e = run(&custom, "/version", false).expect_err("custom");
    assert_eq!(e.method, "OTHER");
}

#[test]
fn unlisted_resources_are_refused() {
    for uri in [
        "/",
        "/healthz",
        "/metrics",
        "/api/v1",
        "/apis/apps/v1/deployments",
        "/api/v1/namespaces/team-a/secrets",
        "/api/v1/namespaces/team-a/configmaps",
        "/api/v1/namespaces/team-a/events",
        "/api/v1/namespaces/team-a/services",
        "/api/v1/secrets",
        "/api/v1/pods",
        "/api/v1/nodes",
        "/api/v1/namespaces/team-a/pods/web/attach",
        "/api/v1/namespaces/team-a/pods/web/proxy",
        "/api/v1/namespaces/team-a/pods/web/proxy/x",
        "/api/v1/namespaces/team-a/pods/web/eviction",
        "/api/v1/namespaces/team-a/pods/web/ephemeralcontainers",
        "/api/v1/namespaces/team-a/pods/web/binding",
        "/api/v1/namespaces/team-a/serviceaccounts/default/token",
        "/apis/authorization.k8s.io/v1/subjectaccessreviews",
        "/apis/authorization.k8s.io/v1/namespaces/team-a/localsubjectaccessreviews",
        "/apis/authentication.k8s.io/v1/tokenreviews",
        "/VERSION",
        "/API/v1/namespaces",
    ] {
        refused(&Method::GET, uri, false);
        refused(&Method::POST, uri, false);
    }
    let e = run(&Method::GET, "/api/v1/namespaces/a/secrets", false).expect_err("x");
    assert_eq!((e.method, e.template), ("GET", "unlisted"));
}

#[test]
fn traversal_and_encoding_tricks() {
    for uri in [
        "/api/v1/namespaces/team-a/pods/../secrets",
        "/api/v1/namespaces/team-a/pods/./web",
        "/api/v1/namespaces/../namespaces/team-a/pods",
        "/api/v1/namespaces/team-a/pods/%2e%2e/secrets",
        "/api/v1/namespaces/team-a/pods/%2E%2E",
        "/api/v1/namespaces/team-a%2Fsecrets",
        "/api/v1/namespaces/team-a/pods/web%2Fexec",
        "/api/v1/namespaces/team-a/pods/web;exec",
        "/api/v1/namespaces/team-a;x/pods",
        "//api/v1/namespaces",
        "/api//v1/namespaces",
        "/api/v1/namespaces/",
        "/api/v1/namespaces/team-a/pods/",
        "/api/v1/namespaces/Team-A/pods",
        "/api/v1/namespaces/-a/pods",
        "/api/v1/namespaces/team-a/pods/Web",
        "/api/v1/namespaces/team-a/pods/web..x",
        "/api/v1/namespaces/team-a/pods/web/log/extra",
        "/version/",
        "/api/v1/namespaces/team_a/pods",
    ] {
        refused(&Method::GET, uri, false);
    }
    let long = format!("/api/v1/namespaces/team-a/pods/{}", "a".repeat(254));
    refused(&Method::GET, &long, false);
    refused(&Method::GET, &format!("/api/v1/namespaces/{}", "a".repeat(64)), false);
    let abs = "https://api.example.test/version";
    let e = run(&Method::GET, abs, false).expect_err("absolute");
    assert_eq!(e.template, "unlisted");
}

#[test]
fn query_injection_and_values() {
    let pods = format!("{NS}/pods");
    for q in [
        "dryRun=All",
        "fieldManager=x",
        "dry%52un=All",
        "limit=500&dryRun=All",
        "limit=501",
        "limit=0",
        "limit=1&limit=2",
        "limit",
        "&limit=5",
        "limit=5&",
        "limit=5&&watch=1",
        "watch=yes",
        "fieldSelector=spec.nodeName%3Dx",
        "labelSelector=a%3Bb",
        "labelSelector=%00",
        "continue=a%0Ab",
        "pretty=true",
        "propagationPolicy=Background",
        "timeoutSeconds=0",
        "resourceVersion=1%2F2",
        "limit=%35%30%30x",
    ] {
        refused(&Method::GET, &format!("{pods}?{q}"), false);
    }
    ok(&Method::GET, &format!("{pods}?"), false);
    ok(
        &Method::GET,
        &format!("{pods}?watch=1&resourceVersion=123&allowWatchBookmarks=true&timeoutSeconds=300"),
        false,
    );
    ok(&Method::GET, &format!("{pods}?limit=%35%30%30"), false);
    let log = format!("{POD}/log");
    for q in [
        "tailLines=10001",
        "limitBytes=1025",
        "limitBytes=0",
        "container=App",
        "previous=true",
        "sinceSeconds=0",
        "sinceTime=2026-01-01T00%3A00%3A00Z",
        "insecureSkipTLSVerifyBackend=true",
    ] {
        refused(&Method::GET, &format!("{log}?{q}"), false);
    }
    let exec = format!("{POD}/exec");
    for q in [
        "command=%2Fbin%2Fzsh",
        "command=%2Fbin%2Fsh&command=-c",
        "command=rm",
        "stdin=true",
        "command=sh&tty=maybe",
        "command=sh%00",
    ] {
        refused(&Method::GET, &format!("{exec}?{q}"), true);
    }
    for c in ["sh", "bash", "%2Fbin%2Fash", "%2Fbin%2Fbash"] {
        ok(&Method::GET, &format!("{exec}?command={c}"), true);
    }
    let pf = format!("{POD}/portforward");
    for q in ["", "ports=0", "ports=65536", "ports=80&ports=81", "ports=80%2C81", "ports=http"] {
        refused(&Method::GET, &format!("{pf}?{q}"), true);
    }
    for q in ["limit=1", "dryRun=All", "fieldManager=m"] {
        refused(&Method::POST, &format!("{}?{q}", Route::AccessReview.template()), false);
    }
    ok(&Method::POST, &format!("{}?", Route::AccessReview.template()), false);
}

#[test]
fn impersonation_headers_are_refused() {
    let req =
        http::Request::get("/version").header("Impersonate-User", "admin").body(()).expect("req");
    let e = check(RequestShape::of(&req), P).expect_err("impersonate");
    assert_eq!(e.template, "/version");
    let req = http::Request::get("/version")
        .header("impersonate-group", "system:masters")
        .body(())
        .expect("req");
    assert!(check(RequestShape::of(&req), P).is_err());
}

#[test]
fn websocket_detection_needs_both_headers() {
    let uri = format!("{POD}/exec?command=sh");
    let only_upgrade =
        http::Request::get(uri.as_str()).header("upgrade", "websocket").body(()).expect("r");
    assert!(check(RequestShape::of(&only_upgrade), P).is_err());
    let both = http::Request::get(uri.as_str())
        .header("upgrade", "WebSocket")
        .header("connection", "keep-alive, Upgrade")
        .body(())
        .expect("r");
    assert_eq!(check(RequestShape::of(&both), P), Ok(Route::PodExec));
}

#[test]
fn refusals_are_audited_by_the_layer() {
    use tower::{Service as _, ServiceExt as _};
    let audit = AuditSink::default();
    let inner =
        tower::service_fn(|_req: Request<()>| async { Ok::<_, std::convert::Infallible>(()) });
    let mut svc = ReadOnlyGuardLayer::new(P, audit.clone()).layer(inner);
    let rt = tokio::runtime::Builder::new_current_thread().build().expect("rt");
    rt.block_on(async {
        let ok = Request::get("/version").body(()).expect("r");
        svc.ready().await.expect("ready").call(ok).await.expect("allowed");
        let bad = Request::patch("/api/v1/namespaces/a/pods/b").body(()).expect("r");
        let err = svc.ready().await.expect("ready").call(bad).await.expect_err("refused");
        let refused = err.downcast::<Refused>().expect("typed");
        assert_eq!(refused.method, "PATCH");
    });
    assert_eq!(
        audit.take(),
        [KubeAudit::RequestRefused {
            method: "PATCH",
            template: "/api/v1/namespaces/{ns}/pods/{pod}"
        }]
    );
}

proptest! {
    #[test]
    fn guard_never_panics_and_oracle_holds(m in 0u8..6, flags in 0u8..4, path in "[ -~]{0,200}") {
        let mut data = vec![m, flags];
        data.extend_from_slice(path.as_bytes());
        crate::fuzz::fuzz_guard_path(&data);
    }

    #[test]
    fn mutating_methods_are_always_refused(path in "/[a-z0-9./%;?=&-]{0,120}") {
        for m in [Method::PUT, Method::PATCH, Method::DELETE] {
            if let Ok(uri) = path.parse::<http::Uri>() {
                let shape = RequestShape { method: &m, uri: &uri, websocket: false, impersonates: false };
                prop_assert!(check(shape, P).is_err());
            }
        }
    }

    #[test]
    fn valid_names_route(ns in "[a-z][a-z0-9-]{0,20}[a-z0-9]", pod in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z0-9]{1,5}){0,3}") {
        let uri = format!("/api/v1/namespaces/{ns}/pods/{pod}/log?tailLines=5");
        prop_assert_eq!(run(&Method::GET, &uri, false), Ok(Route::PodLog));
    }

    #[test]
    fn frames_and_logs_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        crate::fuzz::fuzz_exec_frame(&data);
        crate::fuzz::fuzz_portforward_frame(&data);
        crate::fuzz::fuzz_log_line(&data);
    }
}
