//! L-40: the manifest fetch against a local HTTP server named `updates.example.test` (resolved
//! to loopback by the test client; plaintext only here, production is `https_only`).

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// How the server answers `/real.json` (`/latest.json` redirects there).
#[derive(Clone, Copy)]
enum Body {
    /// A small manifest with `Content-Length`.
    Manifest,
    /// `n` bytes declared in `Content-Length`.
    Declared(usize),
    /// `n` bytes, no length, ended by closing the connection.
    Streamed(usize),
    /// `204 No Content`.
    NoContent,
    /// Redirect to itself forever.
    Loop,
}

const MANIFEST: &str = r#"{"version":"9.9.9","platforms":{}}"#;

async fn server(body: Body) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&b[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head);
                let reply = if head.starts_with("GET /latest.json ") || matches!(body, Body::Loop) {
                    "HTTP/1.1 302 Found\r\nLocation: /real.json\r\nContent-Length: 0\r\n\r\n".to_owned().into_bytes()
                } else {
                    match body {
                        Body::Manifest => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{MANIFEST}",
                            MANIFEST.len()
                        )
                        .into_bytes(),
                        Body::Declared(n) => {
                            let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").into_bytes();
                            r.extend(std::iter::repeat_n(b' ', n));
                            r
                        }
                        Body::Streamed(n) => {
                            let mut r = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
                            r.extend(std::iter::repeat_n(b' ', n));
                            r
                        }
                        Body::NoContent | Body::Loop => b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
                    }
                };
                let _ = s.write_all(&reply).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

async fn get(body: Body) -> Result<Option<serde_json::Value>, SourceError> {
    let addr = server(body).await;
    let client = builder().no_proxy().resolve("updates.example.test", addr).build().expect("client");
    let url = format!("http://updates.example.test:{}/latest.json", addr.port());
    fetch(&client, &url, MANIFEST_CAP).await
}

#[tokio::test]
async fn a_normal_manifest_is_read_through_the_redirect() {
    let v = get(Body::Manifest).await.expect("ok").expect("some");
    assert_eq!(v["version"], "9.9.9");
}

#[tokio::test]
async fn an_oversize_manifest_is_refused_declared_or_streamed() {
    for body in [Body::Declared(MANIFEST_CAP + 1), Body::Streamed(MANIFEST_CAP + 1), Body::Streamed(8 * MANIFEST_CAP)] {
        let e = get(body).await.expect_err("over the cap");
        assert_eq!(e, SourceError::Manifest);
        assert_eq!(e.code(), "update.manifest");
    }
    // At the cap but not JSON: still `update.manifest`, nothing larger was buffered.
    assert_eq!(get(Body::Declared(MANIFEST_CAP)).await.expect_err("blank"), SourceError::Manifest);
}

#[tokio::test]
async fn no_content_is_no_update_and_a_redirect_loop_is_a_network_error() {
    assert_eq!(get(Body::NoContent).await.expect("ok"), None);
    assert_eq!(get(Body::Loop).await.expect_err("loop"), SourceError::Network);
}

#[test]
fn the_endpoint_must_be_one_plain_https_url() {
    let cfg = |v: serde_json::Value| {
        let mut p = tauri::utils::config::PluginConfig::default();
        p.0.insert("updater".to_owned(), v);
        p
    };
    let ok = cfg(serde_json::json!({ "endpoints": ["https://github.com/yyasar21/Mooring/releases/latest/download/latest.json"] }));
    assert!(endpoint(&ok).expect("ok").ends_with("/latest.json"));
    for bad in [
        serde_json::json!({}),
        serde_json::json!({ "endpoints": [] }),
        serde_json::json!({ "endpoints": ["http://updates.example.test/latest.json"] }),
        serde_json::json!({ "endpoints": ["https://updates.example.test/{{target}}/latest.json"] }),
    ] {
        assert_eq!(endpoint(&cfg(bad)), Err(SourceError::Unconfigured));
    }
    assert!(client().is_ok());
}
