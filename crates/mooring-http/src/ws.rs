//! WebSocket over the same connector (kube exec / port-forward, later WebMKS): an HTTP/1.1
//! upgrade through our TLS and verifier, then `tokio-tungstenite` framing with size caps.

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http::header::{
    CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_VERSION, UPGRADE,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

pub use tokio_tungstenite::tungstenite::Message;

use crate::client::{HttpClient, Spec};
use crate::error::HttpError;
use crate::headers::Headers;
use crate::verify::TrustDecision;

/// The upgraded byte stream under the framing.
pub type WsIo = TokioIo<hyper::upgrade::Upgraded>;

/// Frame and message caps of one WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsLimits {
    /// Largest message (default 1 MiB).
    pub max_message: usize,
    /// Largest frame (default 1 MiB).
    pub max_frame: usize,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self { max_message: 1024 * 1024, max_frame: 1024 * 1024 }
    }
}

/// A client WebSocket. `recv` yields data messages; ping/pong is answered by tungstenite.
#[derive(Debug)]
pub struct WsStream {
    inner: WebSocketStream<WsIo>,
    protocol: Option<String>,
    trust: Option<TrustDecision>,
}

impl WsStream {
    /// The sub-protocol the server selected (one of those offered), if any.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// The handshake decision of the connection.
    pub fn trust(&self) -> Option<&TrustDecision> {
        self.trust.as_ref()
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: Bytes) -> Result<(), HttpError> {
        self.send(Message::Binary(data)).await
    }

    /// Send any message.
    pub async fn send(&mut self, msg: Message) -> Result<(), HttpError> {
        self.inner.send(msg).await.map_err(|_| HttpError::WebSocket("send failed"))
    }

    /// The next message; `None` once closed. Oversized messages / frames are errors.
    pub async fn recv(&mut self) -> Option<Result<Message, HttpError>> {
        self.inner.next().await.map(|r| {
            r.map_err(|e| match e {
                tokio_tungstenite::tungstenite::Error::Capacity(_) => {
                    HttpError::WebSocket("message exceeds the cap")
                }
                _ => HttpError::WebSocket("receive failed"),
            })
        })
    }

    /// Send a close frame and flush.
    pub async fn close(&mut self) -> Result<(), HttpError> {
        self.inner.close(None).await.map_err(|_| HttpError::WebSocket("close failed"))
    }

    /// The framed stream itself (a `futures` `Stream + Sink<Message>`), e.g. for kube's own
    /// channel demux.
    pub fn into_inner(self) -> WebSocketStream<WsIo> {
        self.inner
    }
}

/// Whether `p` is a valid sub-protocol token (RFC 6455 §4.1: visible ASCII, no separators).
fn token(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 128
        && p.bytes().all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b))
}

impl HttpClient {
    /// Open a WebSocket on `path` offering `protocols` (in preference order). The server must
    /// answer `101` with the matching `Sec-WebSocket-Accept`, and may only select an offered
    /// protocol. Never retried; redirects refused.
    pub async fn websocket(
        &self,
        path: &str,
        headers: &Headers,
        protocols: &[&str],
        limits: WsLimits,
    ) -> Result<WsStream, HttpError> {
        if protocols.len() > 8 || !protocols.iter().all(|p| token(p)) {
            return Err(HttpError::InvalidRequest("invalid websocket sub-protocol"));
        }
        let key = generate_key();
        let mut extra = HeaderMap::new();
        extra.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        extra.insert(UPGRADE, HeaderValue::from_static("websocket"));
        extra.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
        extra.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_str(&key).map_err(|_| HttpError::WebSocket("key"))?,
        );
        if !protocols.is_empty() {
            let v = HeaderValue::from_str(&protocols.join(", "))
                .map_err(|_| HttpError::InvalidRequest("invalid websocket sub-protocol"))?;
            extra.insert(SEC_WEBSOCKET_PROTOCOL, v);
        }
        let spec = Spec { method: Method::GET, path, headers, body: None, retry: false, extra };
        let resp = self.execute(&spec).await?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(HttpError::Status { status: resp.status() });
        }
        let h = resp.headers();
        let accept = h.get(SEC_WEBSOCKET_ACCEPT).map(HeaderValue::as_bytes);
        if accept != Some(derive_accept_key(key.as_bytes()).as_bytes()) {
            return Err(HttpError::WebSocket("bad Sec-WebSocket-Accept"));
        }
        let upgrade_ok = h
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if !upgrade_ok {
            return Err(HttpError::WebSocket("server did not upgrade to websocket"));
        }
        let selected = match h.get(SEC_WEBSOCKET_PROTOCOL) {
            None => None,
            Some(v) => {
                let s = v.to_str().map_err(|_| HttpError::WebSocket("bad sub-protocol"))?;
                if !protocols.contains(&s) {
                    return Err(HttpError::WebSocket("server selected a sub-protocol not offered"));
                }
                Some(s.to_owned())
            }
        };
        let trust = resp.extensions().get::<TrustDecision>().cloned();
        let upgraded =
            hyper::upgrade::on(resp).await.map_err(|_| HttpError::WebSocket("upgrade failed"))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(limits.max_message))
            .max_frame_size(Some(limits.max_frame));
        let inner =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, Some(config))
                .await;
        Ok(WsStream { inner, protocol: selected, trust })
    }
}
