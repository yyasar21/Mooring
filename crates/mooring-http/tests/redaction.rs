//! Credentials never reach `tracing` output or `Debug` (its own binary: tracing's callsite
//! interest cache is process-wide, so a scoped subscriber must not race other tests).

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use mooring_http::{Headers, HttpClient, Method};

async fn pinned(h: Handler) -> Server {
    let (s, der) = self_signed_server(h).await;
    pin(&s, &der);
    s
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn credentials_never_reach_tracing_or_debug() {
    let server = pinned(handler(|req| async move {
        let auth = req.headers().get("authorization").map(|v| v.as_bytes().to_vec());
        let mut r =
            full(if auth.as_deref() == Some(b"Bearer tok-SECRET") { 200 } else { 401 }, "{}");
        r.headers_mut().insert("set-cookie", http::HeaderValue::from_static("s=SECRET"));
        r
    }))
    .await;
    let cap = Capture::default();
    let writer = cap.clone();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let client = HttpClient::new(server.config()).expect("client");
    let headers = Headers::new()
        .bearer("tok-SECRET")
        .and_then(|h| h.insert("X-Vault-Token", "hvs.SECRET"))
        .expect("h");
    let resp =
        client.request(Method::GET, "/a?token=SECRET", &headers, None, 1024).await.expect("ok");
    assert_eq!(resp.status.as_u16(), 200, "the server saw the bearer token");
    let dbg = format!("{resp:?} {headers:?} {client:?}");
    let logs = String::from_utf8(cap.0.lock().expect("lock").clone()).expect("utf8");
    assert!(logs.contains("http response"), "{logs}");
    assert!(!logs.contains("SECRET") && !dbg.contains("SECRET"), "{logs}\n{dbg}");
}
