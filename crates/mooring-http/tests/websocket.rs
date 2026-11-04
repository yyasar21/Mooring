//! WebSocket upgrade through our TLS: echo, sub-protocol negotiation, message cap.

mod common;

use bytes::Bytes;
use common::*;
use futures_util::{SinkExt as _, StreamExt as _};
use hyper_util::rt::TokioIo;
use mooring_http::{Headers, HttpClient, HttpError, Message, WsLimits};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

/// Echo server; selects `pick` (or the first offered protocol when `None`). `/big` sends one
/// 64 KiB message instead of echoing.
fn ws_handler(pick: Option<&'static str>) -> Handler {
    handler(move |mut req| async move {
        let key = req.headers().get("sec-websocket-key").map(|k| derive_accept_key(k.as_bytes()));
        let Some(accept) = key else { return full(400, "") };
        let offered = req
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next().map(|s| s.trim().to_owned()));
        let big = req.uri().path() == "/big";
        let on = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(up) = on.await else { return };
            let mut ws =
                WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, None).await;
            if big {
                let _ = ws.send(Message::Binary(Bytes::from(vec![0u8; 64 * 1024]))).await;
                return;
            }
            while let Some(Ok(m)) = ws.next().await {
                if m.is_binary() || m.is_text() {
                    let _ = ws.send(m).await;
                }
            }
        });
        let mut r = full(101, "");
        let h = r.headers_mut();
        h.insert("connection", http::HeaderValue::from_static("Upgrade"));
        h.insert("upgrade", http::HeaderValue::from_static("websocket"));
        h.insert("sec-websocket-accept", http::HeaderValue::from_str(&accept).expect("accept"));
        if let Some(p) = pick.map(str::to_owned).or(offered) {
            h.insert("sec-websocket-protocol", http::HeaderValue::from_str(&p).expect("p"));
        }
        r
    })
}

async fn pinned(h: Handler) -> Server {
    let (s, der) = self_signed_server(h).await;
    pin(&s, &der);
    s
}

#[tokio::test]
async fn echo_over_tls_with_negotiated_protocol() {
    let s = pinned(ws_handler(Some("v4.channel.k8s.io"))).await;
    let c = HttpClient::new(s.config()).expect("client");
    let protos = ["v5.channel.k8s.io", "v4.channel.k8s.io"];
    let mut ws =
        c.websocket("/exec", &Headers::new(), &protos, WsLimits::default()).await.expect("ws");
    assert_eq!(ws.protocol(), Some("v4.channel.k8s.io"));
    assert!(ws.trust().is_some());
    ws.send_binary(Bytes::from_static(b"\x00hello")).await.expect("send");
    let m = ws.recv().await.expect("msg").expect("ok");
    assert_eq!(m, Message::Binary(Bytes::from_static(b"\x00hello")));
    ws.close().await.expect("close");
}

#[tokio::test]
async fn protocol_not_offered_is_refused() {
    let s = pinned(ws_handler(Some("evil"))).await;
    let c = HttpClient::new(s.config()).expect("client");
    let err = c
        .websocket("/exec", &Headers::new(), &["v5.channel.k8s.io"], WsLimits::default())
        .await
        .expect_err("x");
    assert!(matches!(err, HttpError::WebSocket(_)), "{err:?}");
    let err = c
        .websocket("/exec", &Headers::new(), &["bad token"], WsLimits::default())
        .await
        .expect_err("y");
    assert!(matches!(err, HttpError::InvalidRequest(_)));
}

#[tokio::test]
async fn oversized_message_is_an_error() {
    let s = pinned(ws_handler(None)).await;
    let c = HttpClient::new(s.config()).expect("client");
    let limits = WsLimits { max_message: 16 * 1024, max_frame: 16 * 1024 };
    let mut ws = c.websocket("/big", &Headers::new(), &[], limits).await.expect("ws");
    let r = ws.recv().await.expect("something");
    assert!(matches!(r, Err(HttpError::WebSocket(_))), "{r:?}");
}

#[tokio::test]
async fn non_101_is_a_status_error() {
    let s = pinned(ok_json()).await;
    let c = HttpClient::new(s.config()).expect("client");
    let err =
        c.websocket("/exec", &Headers::new(), &[], WsLimits::default()).await.expect_err("200");
    assert!(matches!(err, HttpError::Status { .. }), "{err:?}");
}
