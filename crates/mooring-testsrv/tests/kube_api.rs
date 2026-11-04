//! Self-tests of the kube mock's REST side: discovery, auth, lists, RBAC, reviews, logs,
//! watch, the forbidden-call trap and the transport knobs.

mod common;

use std::time::{Duration, Instant};

use bytes::Bytes;
use common::http_client::{get, post_json, request, send, send_streaming};
use common::within;
use http::Method;
use http_body_util::BodyExt as _;
use mooring_testsrv::http::HttpKnobs;
use mooring_testsrv::kube::{self, many_pods, AccessRule, KubeConfig, KubeKnobs};
use serde_json::json;

const AUTH: (&str, &str) = ("authorization", "Bearer test-token");

async fn srv() -> kube::KubeServer {
    kube::start(KubeConfig::default(), 0).await.expect("start")
}

#[tokio::test]
async fn discovery_is_open_and_recorded() {
    let s = srv().await;
    within(async {
        assert_eq!(get(s.addr(), "/version", &[]).await.json()["gitVersion"], "v1.30.4");
        assert_eq!(get(s.addr(), "/api", &[]).await.json()["versions"][0], "v1");
        let groups = get(s.addr(), "/apis", &[]).await.json();
        assert_eq!(groups["groups"].as_array().map(Vec::len), Some(2));
    })
    .await;
    assert_eq!(s.recorder().lines(), ["GET /version", "GET /api", "GET /apis"]);
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn bearer_and_client_cert_auth() {
    let s = srv().await;
    within(async {
        let ok = get(s.addr(), "/api/v1/namespaces", &[AUTH]).await;
        assert_eq!(ok.status, 200);
        assert_eq!(ok.json()["items"].as_array().map(Vec::len), Some(3));
        assert_eq!(get(s.addr(), "/api/v1/namespaces", &[]).await.status, 401);
        assert_eq!(
            get(s.addr(), "/api/v1/namespaces", &[("authorization", "Bearer nope")]).await.status,
            401
        );
        let id = s.client_identity().expect("client cert auth on by default");
        let review =
            json!({ "apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview" });
        let req = request(
            Method::POST,
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            &[("content-type", "application/json")],
            serde_json::to_vec(&review).expect("json"),
        );
        let r = send(s.addr(), req, Some(id)).await;
        assert_eq!(r.status, 201);
        assert_eq!(r.json()["status"]["userInfo"]["username"], "mooring-client");
    })
    .await;
    let rec = s.recorder().requests();
    assert_eq!(rec[0].header("authorization"), Some(mooring_testsrv::http::REDACTED));
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn pods_selector_get_and_pagination() {
    let s = srv().await;
    within(async {
        let pods = get(s.addr(), "/api/v1/namespaces/default/pods", &[AUTH]).await.json();
        assert_eq!(pods["items"].as_array().map(Vec::len), Some(2));
        let web = get(s.addr(), "/api/v1/namespaces/default/pods?labelSelector=app%3Dweb", &[AUTH])
            .await
            .json();
        assert_eq!(web["items"][0]["metadata"]["name"], "web-0");
        let pod = get(s.addr(), "/api/v1/namespaces/default/pods/web-0", &[AUTH]).await.json();
        assert_eq!(pod["spec"]["containers"][1]["ports"][0]["containerPort"], 9090);
        assert_eq!(
            get(s.addr(), "/api/v1/namespaces/default/pods/nope", &[AUTH]).await.status,
            404
        );
        assert_eq!(get(s.addr(), "/api/v1/namespaces/ghost/pods", &[AUTH]).await.status, 404);
        s.set_pods(many_pods("default", 1200));
        let (mut seen, mut cont, mut pages) = (0, String::new(), 0);
        loop {
            let path = format!("/api/v1/namespaces/default/pods?limit=500&continue={cont}");
            let page = get(s.addr(), &path, &[AUTH]).await.json();
            seen += page["items"].as_array().map_or(0, Vec::len);
            pages += 1;
            match page["metadata"]["continue"].as_str() {
                Some(c) => cont = c.to_owned(),
                None => break,
            }
        }
        assert_eq!((seen, pages), (1200, 3));
        assert_eq!(
            get(s.addr(), "/api/v1/namespaces/default/pods?continue=zz", &[AUTH]).await.status,
            410
        );
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn forbidden_calls_are_trapped() {
    let s = srv().await;
    within(async {
        for (m, p) in [
            (Method::GET, "/api/v1/namespaces/default/secrets"),
            (Method::GET, "/api/v1/namespaces/default/configmaps"),
            (Method::DELETE, "/api/v1/namespaces/default/pods/web-0"),
            (Method::POST, "/api/v1/namespaces/default/pods"),
            (Method::PATCH, "/api/v1/namespaces/default/pods/web-0"),
            (Method::GET, "/api/v1/namespaces?dryRun=All"),
            (Method::POST, "/api/v1/namespaces/default/pods/web-0/exec?command=sh"),
        ] {
            let r = send(s.addr(), request(m.clone(), p, &[AUTH], Bytes::new()), None).await;
            assert_eq!(r.status, 500, "{m} {p}");
        }
    })
    .await;
    assert_eq!(s.recorder().violations().len(), 7);
    let caught = std::panic::catch_unwind(|| s.recorder().assert_no_violations());
    assert!(caught.is_err(), "the gate must fail on a violation");
}

#[tokio::test]
async fn rbac_reviews_and_auth_knobs() {
    let s = srv().await;
    s.set_rules(vec![
        AccessRule::new(&["list", "get"], &["pods", "pods/log"]).in_namespaces(&["team-a"])
    ]);
    within(async {
        let r = get(s.addr(), "/api/v1/namespaces", &[AUTH]).await;
        assert_eq!(r.status, 403);
        assert!(r.json()["message"].as_str().unwrap_or("").contains("cannot list resource \"namespaces\""));
        assert_eq!(get(s.addr(), "/api/v1/namespaces/default/pods", &[AUTH]).await.status, 403);
        assert_eq!(get(s.addr(), "/api/v1/namespaces/team-a/pods", &[AUTH]).await.status, 200);
        let ssar = |ns: &str, verb: &str, res: &str, sub: &str| {
            json!({ "kind": "SelfSubjectAccessReview", "apiVersion": "authorization.k8s.io/v1",
                    "spec": { "resourceAttributes": { "namespace": ns, "verb": verb, "resource": res, "subresource": sub } } })
        };
        let path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";
        let yes = post_json(s.addr(), path, &[AUTH], &ssar("team-a", "list", "pods", "")).await;
        assert_eq!((yes.status, yes.json()["status"]["allowed"].as_bool()), (201, Some(true)));
        let no = post_json(s.addr(), path, &[AUTH], &ssar("team-a", "create", "pods", "exec")).await;
        assert_eq!(no.json()["status"]["allowed"], false);
        let rules = post_json(s.addr(), "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", &[AUTH],
            &json!({ "spec": { "namespace": "team-a" } })).await.json();
        assert_eq!(rules["status"]["resourceRules"][0]["resources"], json!(["pods", "pods/log"]));
        s.set_knobs(KubeKnobs { force_401: true, ..KubeKnobs::default() });
        assert_eq!(get(s.addr(), "/api/v1/namespaces/team-a/pods", &[AUTH]).await.status, 401);
        s.set_knobs(KubeKnobs { force_403: true, ..KubeKnobs::default() });
        assert_eq!(get(s.addr(), "/api/v1/namespaces/team-a/pods", &[AUTH]).await.status, 403);
        assert_eq!(get(s.addr(), "/version", &[]).await.status, 200);
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn logs_tail_limit_timestamps_follow_and_huge() {
    let s = srv().await;
    let base = "/api/v1/namespaces/default/pods/web-0/log";
    within(async {
        assert_eq!(
            get(s.addr(), base, &[AUTH]).await.status,
            400,
            "two containers: container is required"
        );
        let tail =
            get(s.addr(), &format!("{base}?container=app&tailLines=3"), &[AUTH]).await.text();
        assert_eq!(tail, "line 97 of web-0/app\nline 98 of web-0/app\nline 99 of web-0/app\n");
        let ts =
            get(s.addr(), &format!("{base}?container=app&tailLines=1&timestamps=true"), &[AUTH])
                .await
                .text();
        assert!(ts.starts_with("2026-11-04T00:01:39.000000000Z line 99"), "{ts}");
        let lim = get(s.addr(), &format!("{base}?container=app&limitBytes=10"), &[AUTH]).await;
        assert_eq!(lim.body.len(), 10);
        let one = get(s.addr(), "/api/v1/namespaces/default/pods/db-0/log?tailLines=1", &[AUTH])
            .await
            .text();
        assert_eq!(one, "line 99 of db-0/postgres\n");
        let follow =
            get(s.addr(), &format!("{base}?container=sidecar&tailLines=1&follow=true"), &[AUTH])
                .await
                .text();
        assert_eq!(follow.lines().count(), 6);
        assert!(follow.ends_with("follow 4 of web-0/sidecar\n"));
        s.set_knobs(KubeKnobs { huge_log: Some(5 * 1024 * 1024 + 7), ..KubeKnobs::default() });
        let resp = send_streaming(
            s.addr(),
            request(
                Method::GET,
                &format!("{base}?container=app&limitBytes=100"),
                &[AUTH],
                Bytes::new(),
            ),
            None,
        )
        .await;
        let mut body = resp.into_body();
        let mut n = 0;
        while let Some(f) = body.frame().await {
            n += f.expect("frame").into_data().map_or(0, |d| d.len());
        }
        assert_eq!(n, 5 * 1024 * 1024 + 7, "huge-log ignores limitBytes");
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn watch_streams_added_then_pushed_events() {
    let s = srv().await;
    within(async {
        let req = request(
            Method::GET,
            "/api/v1/namespaces/default/pods?watch=1&timeoutSeconds=2",
            &[AUTH],
            Bytes::new(),
        );
        let mut body = send_streaming(s.addr(), req, None).await.into_body();
        let mut text = String::new();
        while text.lines().count() < 2 {
            let f = body.frame().await.expect("frame").expect("ok");
            text.push_str(&String::from_utf8_lossy(&f.into_data().unwrap_or_default()));
        }
        let mut pod = kube::default_pods().remove(1);
        pod.phase = "Failed".to_owned();
        s.push_pod_event("MODIFIED", &pod);
        while let Some(f) = body.frame().await {
            text.push_str(&String::from_utf8_lossy(
                &f.expect("ok").into_data().unwrap_or_default(),
            ));
        }
        let events: Vec<serde_json::Value> =
            text.lines().map(|l| serde_json::from_str(l).expect("event")).collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2]["type"], "MODIFIED");
        assert_eq!(events[2]["object"]["status"]["phase"], "Failed");
    })
    .await;
}

#[tokio::test]
async fn transport_knobs_oversized_drip_delay_and_body_cap() {
    let s = srv().await;
    within(async {
        s.set_knobs(KubeKnobs { oversized_body: Some(20 * 1024 * 1024), ..KubeKnobs::default() });
        let big = get(s.addr(), "/api/v1/namespaces", &[AUTH]).await;
        assert!(big.body.len() > 20 * 1024 * 1024);
        assert_eq!(big.json()["items"].as_array().map(Vec::len), Some(3));
        s.set_knobs(KubeKnobs::default());
        s.set_http_knobs(HttpKnobs {
            drip: Some(Duration::from_millis(2)),
            ..HttpKnobs::default()
        });
        let t = Instant::now();
        let v = get(s.addr(), "/version", &[]).await;
        assert!(t.elapsed() >= Duration::from_millis(u64::try_from(v.body.len()).expect("len")));
        assert_eq!(v.header("content-length"), Some(v.body.len().to_string()));
        s.set_http_knobs(HttpKnobs {
            response_delay: Some(Duration::from_secs(30)),
            ..HttpKnobs::default()
        });
        let slow =
            tokio::time::timeout(Duration::from_millis(300), get(s.addr(), "/version", &[])).await;
        assert!(slow.is_err(), "the client must time out first");
        s.set_http_knobs(HttpKnobs { max_request_body: 64, ..HttpKnobs::default() });
        let r = post_json(
            s.addr(),
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            &[AUTH],
            &json!({ "pad": "x".repeat(200) }),
        )
        .await;
        assert_eq!(r.status, 413);
    })
    .await;
    let rec = s.recorder().requests();
    assert!(rec.iter().any(|r| r.status == 413 && r.body_len == 0));
    assert_eq!(
        rec.iter().filter(|r| r.path == "/version").count(),
        2,
        "the delayed request is recorded too"
    );
}
