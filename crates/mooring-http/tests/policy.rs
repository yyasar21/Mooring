//! Caps, streaming, rate limit, retries, redirects, plaintext, status mapping, redaction and
//! the tower service, against in-process servers (the certificate is pinned up front).

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::*;
use mooring_http::{
    Headers, HttpClient, HttpError, Method, RateLimit, RedirectPolicy, StatusClass,
};

async fn pinned(h: Handler) -> Server {
    let (s, der) = self_signed_server(h).await;
    pin(&s, &der);
    s
}

#[tokio::test]
async fn declared_oversized_body_is_refused_before_buffering() {
    let s = pinned(handler(|_| async { full(200, vec![b'x'; 4096]) })).await;
    let mut cfg = s.config();
    cfg.max_body = 1024;
    let c = HttpClient::new(cfg).expect("client");
    let err = c.get_json::<serde_json::Value>("/big", &Headers::new()).await.expect_err("cap");
    assert!(matches!(err, HttpError::BodyTooLarge { cap: 1024 }), "{err:?}");
}

#[tokio::test]
async fn chunked_body_over_the_cap_is_refused_while_reading() {
    let s = pinned(handler(|_| async { chunked(8, 512) })).await;
    let mut cfg = s.config();
    cfg.max_body = 1024;
    let c = HttpClient::new(cfg).expect("client");
    let err = c.request(Method::GET, "/c", &Headers::new(), None, 1024).await.expect_err("cap");
    assert!(matches!(err, HttpError::BodyTooLarge { cap: 1024 }), "{err:?}");
    let ok = c.request(Method::GET, "/c", &Headers::new(), None, 4096).await.expect("fits");
    assert_eq!(ok.body.len(), 4096);
}

#[tokio::test]
async fn stream_chunks_are_bounded_and_truncate_at_the_total_cap() {
    let s = pinned(handler(|_| async { chunked(2, 100 * 1024) })).await;
    let c = HttpClient::new(s.config()).expect("client");
    let mut st = c.get_stream("/log", &Headers::new(), 150 * 1024).await.expect("stream");
    let mut total = 0;
    while let Some(chunk) = st.next_chunk().await.expect("chunk") {
        assert!(chunk.len() <= mooring_http::STREAM_CHUNK);
        total += chunk.len();
    }
    assert_eq!(total, 150 * 1024);
    assert!(st.truncated());

    let mut st = c.get_stream("/log", &Headers::new(), 200 * 1024).await.expect("stream");
    let mut total = 0;
    while let Some(chunk) = st.next_chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 200 * 1024);
    assert!(!st.truncated(), "exactly at the cap is not truncated");
}

#[tokio::test]
async fn invalid_json_reports_position_only() {
    let s = pinned(handler(|_| async { full(200, "{\"a\": SECRETVALUE}") })).await;
    let c = HttpClient::new(s.config()).expect("client");
    let err = c.get_json::<serde_json::Value>("/j", &Headers::new()).await.expect_err("bad");
    assert!(matches!(err, HttpError::Decode { line: 1, .. }), "{err:?}");
    assert!(!format!("{err} {err:?}").contains("SECRET"));
}

#[tokio::test]
async fn rate_limit_paces_requests() {
    let s = pinned(ok_json()).await;
    let mut cfg = s.config();
    cfg.rate = RateLimit { rps: 10.0, burst: 1 };
    let c = HttpClient::new(cfg).expect("client");
    let start = Instant::now();
    for _ in 0..4 {
        c.get_json::<serde_json::Value>("/r", &Headers::new()).await.expect("ok");
    }
    // One token up front, then three refills at 100 ms each.
    assert!(start.elapsed() >= Duration::from_millis(280), "{:?}", start.elapsed());
}

#[tokio::test]
async fn retries_are_bounded_and_idempotent_only() {
    let s = pinned(handler(|_| async { full(503, "") })).await;
    let c = HttpClient::new(s.config()).expect("client");
    let err = c.get_json::<serde_json::Value>("/r", &Headers::new()).await.expect_err("503");
    assert_eq!(err.status_class(), Some(StatusClass::Server));
    assert_eq!(s.hits(), 3, "max_attempts = 3");
    let err = c.post_json::<_, serde_json::Value>("/p", &Headers::new(), &1).await.expect_err("p");
    assert!(matches!(err, HttpError::Status { .. }));
    assert_eq!(s.hits(), 4, "POST is never retried");

    let n = Arc::new(Mutex::new(0u32));
    let s = pinned(handler(move |_| {
        let n = Arc::clone(&n);
        async move {
            let mut g = n.lock().expect("lock");
            *g += 1;
            if *g == 1 {
                full(429, "")
            } else {
                full(200, "{}")
            }
        }
    }))
    .await;
    let c = HttpClient::new(s.config()).expect("client");
    c.get_json::<serde_json::Value>("/r", &Headers::new()).await.expect("recovered");
    assert_eq!(s.hits(), 2);
}

fn redirect(to: &'static str) -> Handler {
    handler(move |req| async move {
        if req.uri().path() == "/final" {
            return full(200, "{\"done\":1}");
        }
        let mut r = full(302, "");
        r.headers_mut().insert("location", http::HeaderValue::from_static(to));
        r
    })
}

#[tokio::test]
async fn redirects_are_refused_unless_same_origin_is_opted_in() {
    let s = pinned(redirect("/final")).await;
    let c = HttpClient::new(s.config()).expect("client");
    let err = c.get_json::<serde_json::Value>("/start", &Headers::new()).await.expect_err("3xx");
    assert!(matches!(err, HttpError::Redirect { .. }), "{err:?}");

    let mut cfg = s.config();
    cfg.redirects = RedirectPolicy::SameOrigin { max: 3 };
    let c = HttpClient::new(cfg.clone()).expect("client");
    let v = c.get_json::<serde_json::Value>("/start", &Headers::new()).await.expect("followed");
    assert_eq!(v["done"], 1);

    let s = pinned(redirect("https://evil.example.test/final")).await;
    let mut cfg = s.config();
    cfg.redirects = RedirectPolicy::SameOrigin { max: 3 };
    let c = HttpClient::new(cfg).expect("client");
    let err = c.get_json::<serde_json::Value>("/start", &Headers::new()).await.expect_err("x");
    assert!(matches!(err, HttpError::Redirect { .. }));
}

#[tokio::test]
async fn plaintext_is_refused_unless_loopback_and_opted_in_and_never_after_tls() {
    let s = serve_plain(ok_json()).await;
    let mut cfg = s.config();
    cfg.base_url = s.http();
    assert!(matches!(HttpClient::new(cfg.clone()), Err(HttpError::PlaintextRefused)));
    let mut remote = cfg.clone();
    remote.base_url = "http://api.example.test:8200".into();
    remote.allow_plaintext = true;
    assert!(matches!(HttpClient::new(remote), Err(HttpError::PlaintextRefused)));
    cfg.allow_plaintext = true;
    let c = HttpClient::new(cfg.clone()).expect("loopback");
    c.get_json::<serde_json::Value>("/x", &Headers::new()).await.expect("plain ok");

    // A "TLS seen" marker (or a pin) for the host turns plaintext off (downgrade guard).
    mooring_core::known_certs::KnownCerts::mark_tls_and_save(
        &s.known(),
        "127.0.0.1",
        s.addr.port(),
        time::OffsetDateTime::now_utc(),
    )
    .expect("mark");
    let c = HttpClient::new(cfg).expect("client");
    let err = c.get_json::<serde_json::Value>("/x", &Headers::new()).await.expect_err("guard");
    assert!(matches!(err, HttpError::PlaintextRefused), "{err:?}");
}

#[tokio::test]
async fn status_mapping_and_conditional_put() {
    let s = pinned(handler(|req| async move {
        match (req.method().as_str(), req.headers().get("if-match").is_some()) {
            ("PUT", true) => {
                let mut resp = full(412, "");
                resp.headers_mut().insert("etag", http::HeaderValue::from_static("\"v2\""));
                resp
            }
            ("PUT", false) => full(200, ""),
            ("DELETE", _) => full(204, ""),
            _ => full(404, ""),
        }
    }))
    .await;
    let c = HttpClient::new(s.config()).expect("client");
    let err = c.get_json::<serde_json::Value>("/nope", &Headers::new()).await.expect_err("404");
    assert_eq!(err.status_class(), Some(StatusClass::NotFound));
    let cond = Headers::new().insert("If-Match", "\"v1\"").expect("h");
    let raw = c.put_raw("/o", &cond, Bytes::from_static(b"blob"), None).await.expect("raw");
    assert_eq!(raw.status.as_u16(), 412);
    assert_eq!(raw.header("etag"), Some("\"v2\""));
    assert!(
        matches!(raw.error_for_status(), Err(e) if e.status_class() == Some(StatusClass::PreconditionFailed))
    );
    assert_eq!(c.delete("/o", &Headers::new()).await.expect("del").as_u16(), 204);
}

#[tokio::test]
async fn tower_service_joins_the_base_and_refuses_other_origins() {
    use tower_service::Service as _;
    let s = pinned(handler(|req| async move { full(200, req.uri().path().to_owned()) })).await;
    let mut cfg = s.config();
    cfg.base_url = format!("{}/prefix", s.https());
    let c = HttpClient::new(cfg).expect("client");
    let mut svc = c.service(1024).expect("svc");
    let req = http::Request::get("/api/v1/namespaces")
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("r");
    let resp = svc.call(req).await.expect("ok");
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.expect("body").to_bytes();
    assert_eq!(&body[..], b"/prefix/api/v1/namespaces");
    let req = http::Request::get("https://evil.example.test/api")
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("r");
    assert!(matches!(svc.call(req).await, Err(HttpError::InvalidRequest(_))));
}
