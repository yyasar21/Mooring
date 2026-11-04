//! Raw hyper 1 HTTP/1.1 + rustls client and a tiny masked WebSocket client for the mock API
//! self-tests. Not the product client (`mooring-http`, ADR-0014 §1): it trusts any server
//! certificate (recording the leaf) and has no caps.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, Request};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use mooring_testsrv::tls::ClientIdentity;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A buffered response.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("JSON body")
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
    }
}

fn client_config(identity: Option<&ClientIdentity>) -> Arc<rustls::ClientConfig> {
    let (base, _) = super::tls::client_config();
    let Some(id) = identity else { return base };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(super::tls::RecordingVerifier::new(Arc::clone(&provider)));
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![id.cert_der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der().to_vec())),
        )
        .expect("client cert");
    Arc::new(cfg)
}

/// Builds a request; `headers` are `(name, value)`.
pub fn request(
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> Request<Full<Bytes>> {
    let mut b = Request::builder().method(method).uri(path);
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        b = b.header("host", "localhost");
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(body.into())).expect("request")
}

/// Sends one request on a fresh connection and returns the streaming response.
pub async fn send_streaming(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
    identity: Option<&ClientIdentity>,
) -> hyper::Response<Incoming> {
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let tls = TlsConnector::from(client_config(identity))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("tls");
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.expect("handshake");
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    sender.send_request(req).await.expect("send")
}

/// Sends one request and buffers the whole body.
pub async fn send(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
    identity: Option<&ClientIdentity>,
) -> Resp {
    let resp = send_streaming(addr, req, identity).await;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.expect("body").to_bytes().to_vec();
    Resp { status, headers, body }
}

pub async fn get(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> Resp {
    send(addr, request(Method::GET, path, headers, Bytes::new()), None).await
}

pub async fn post_json(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    v: &serde_json::Value,
) -> Resp {
    let mut h = headers.to_vec();
    h.push(("content-type", "application/json"));
    send(addr, request(Method::POST, path, &h, serde_json::to_vec(v).expect("json")), None).await
}

/// Client end of a WebSocket (masked frames out, unmasked in).
#[derive(Debug)]
pub struct Ws {
    io: TokioIo<hyper::upgrade::Upgraded>,
    pub protocol: String,
}

/// Opens a WebSocket at `path` offering `protocols`; `Err((status, body))` when refused.
pub async fn ws_connect(
    addr: SocketAddr,
    path: &str,
    protocols: &[&str],
    headers: &[(&str, &str)],
) -> Result<Ws, (u16, String)> {
    let proto = protocols.join(", ");
    let mut h = vec![
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("sec-websocket-protocol", proto.as_str()),
    ];
    h.extend_from_slice(headers);
    let resp = send_streaming(addr, request(Method::GET, path, &h, Bytes::new()), None).await;
    if resp.status().as_u16() != 101 {
        let status = resp.status().as_u16();
        let body =
            resp.into_body().collect().await.map(|c| c.to_bytes().to_vec()).unwrap_or_default();
        return Err((status, String::from_utf8_lossy(&body).into_owned()));
    }
    let accept =
        resp.headers().get("sec-websocket-accept").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC 6455 accept key");
    let protocol = resp
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let up = hyper::upgrade::on(resp).await.expect("upgrade");
    Ok(Ws { io: TokioIo::new(up), protocol })
}

impl Ws {
    /// Sends one masked binary frame.
    pub async fn send(&mut self, data: &[u8]) {
        self.frame(0x2, data).await;
    }

    async fn frame(&mut self, op: u8, data: &[u8]) {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut out = vec![0x80 | op];
        let n = data.len();
        if n < 126 {
            out.push(0x80 | u8::try_from(n).expect("len"));
        } else if n <= 0xffff {
            out.push(0xfe);
            out.extend_from_slice(&u16::try_from(n).expect("len").to_be_bytes());
        } else {
            out.push(0xff);
            out.extend_from_slice(&u64::try_from(n).expect("len").to_be_bytes());
        }
        out.extend_from_slice(&mask);
        out.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.io.write_all(&out).await.expect("ws write");
        self.io.flush().await.expect("ws flush");
    }

    /// Sends a raw, deliberately unmasked frame (protocol-violation test).
    pub async fn send_unmasked(&mut self, data: &[u8]) {
        let mut out = vec![0x82, u8::try_from(data.len()).expect("small")];
        out.extend_from_slice(data);
        self.io.write_all(&out).await.expect("ws write");
    }

    /// Next frame as `(opcode, payload)`; `None` on EOF.
    pub async fn recv(&mut self) -> Option<(u8, Vec<u8>)> {
        let mut h = [0u8; 2];
        self.io.read_exact(&mut h).await.ok()?;
        assert_eq!(h[1] & 0x80, 0, "server frames must not be masked");
        let len = match h[1] & 0x7f {
            126 => usize::from(self.io.read_u16().await.ok()?),
            127 => usize::try_from(self.io.read_u64().await.ok()?).ok()?,
            n => usize::from(n),
        };
        let mut p = vec![0u8; len];
        self.io.read_exact(&mut p).await.ok()?;
        Some((h[0] & 0x0f, p))
    }

    /// Next binary message split into `(channel, payload)`; `None` on close / EOF.
    pub async fn recv_channel(&mut self) -> Option<(u8, Vec<u8>)> {
        loop {
            let (op, p) = self.recv().await?;
            match op {
                0x2 => return p.split_first().map(|(c, rest)| (*c, rest.to_vec())),
                0x8 => return None,
                _ => {}
            }
        }
    }

    pub async fn close(&mut self) {
        self.frame(0x8, &1000u16.to_be_bytes()).await;
    }
}
