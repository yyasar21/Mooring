//! Minimal loopback Kubernetes API mock for this crate's tests (plain HTTP on 127.0.0.1, which
//! `mooring-http` permits only with `allow_plaintext` + a loopback IP literal). It records
//! every request so tests can assert the recorded set stays inside the allow-list.
//!
//! TODO(merge): switch to QA's `mooring_testsrv::kube` once Q1 lands on a3.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use mooring_core::known_certs::CertProtocol;
use mooring_http::{HttpClient, HttpConfig};
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::audit::AuditSink;
use crate::client::{KubeClient, KubeLimits};

pub(crate) const TOKEN: &str = "test-token-not-a-secret";

type Body = BoxBody<Bytes, Infallible>;

/// One recorded request.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: Method,
    pub(crate) uri: String,
    pub(crate) authorized: bool,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) seen: Vec<Seen>,
    pub(crate) resizes: Vec<String>,
}

pub(crate) struct Mock {
    pub(crate) addr: std::net::SocketAddr,
    pub(crate) state: Arc<Mutex<State>>,
    _dir: tempfile::TempDir,
    pub(crate) known: std::path::PathBuf,
}

fn full(status: u16, body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(Full::new(body.into()).boxed());
    *r.status_mut() = StatusCode::from_u16(status).expect("status");
    r
}

fn json_resp(v: &Value) -> Response<Body> {
    full(200, serde_json::to_vec(v).expect("json"))
}

fn pod(name: &str) -> Value {
    json!({
        "metadata": {"name": name, "namespace": "ns", "creationTimestamp": "2026-01-01T00:00:00Z",
                     "annotations": {"secret": "never-read"}},
        "spec": {"nodeName": "node-a", "containers": [
            {"name": "app", "image": "registry.example.test/app:1\u{1b}[31m", "ports": [{"containerPort": 8080}],
             "env": [{"name": "PASSWORD", "value": "never-read"}]},
            {"name": "side", "image": "side:2"}]},
        "status": {"phase": "Running", "containerStatuses": [
            {"name": "app", "ready": true, "restartCount": 2},
            {"name": "side", "ready": false, "restartCount": 1}]}
    })
}

async fn review(req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_owned();
    let body = req
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if path.ends_with("selfsubjectaccessreviews") {
        let ra = &v["spec"]["resourceAttributes"];
        let denied = ra["subresource"] == "portforward" || ra["resource"] == "namespaces";
        return json_resp(&json!({"status": {"allowed": !denied}}));
    }
    if path.ends_with("selfsubjectrulesreviews") {
        return json_resp(&json!({"status": {"incomplete": false, "resourceRules": [
            {"verbs": ["get", "list"], "apiGroups": [""], "resources": ["pods", "pods/log"]}]}}));
    }
    json_resp(
        &json!({"status": {"userInfo": {"username": "system:serviceaccount:ns:viewer\u{202e}",
                                               "groups": ["system:authenticated"]}}}),
    )
}

fn logs(query: &str) -> Response<Body> {
    let big = query.contains("follow=true");
    let mut frames: Vec<Result<Frame<Bytes>, Infallible>> = vec![
        Ok(Frame::data(Bytes::from_static(b"line one \x1b[1mbold\x1b[0m\n"))),
        Ok(Frame::data(Bytes::from_static(b"two \x1b]0;evil\x07ok\npartial"))),
    ];
    if big {
        for _ in 0..64 {
            frames.push(Ok(Frame::data(Bytes::from(vec![b'x'; 1024]))));
        }
    }
    Response::new(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(frames))))
}

fn upgrade(mut req: Request<Incoming>, state: Arc<Mutex<State>>) -> Response<Body> {
    let Some(accept) =
        req.headers().get("sec-websocket-key").map(|k| derive_accept_key(k.as_bytes()))
    else {
        return full(400, "");
    };
    let offered = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let exec = req.uri().path().ends_with("/exec");
    let proto = if exec && offered.contains("v5.channel.k8s.io") {
        "v5.channel.k8s.io"
    } else {
        "v4.channel.k8s.io"
    };
    let port: u16 = req
        .uri()
        .query()
        .and_then(|q| q.strip_prefix("ports="))
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let on = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let Ok(up) = on.await else { return };
        let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, None).await;
        if exec {
            exec_server(&mut ws, &state).await;
        } else {
            let hdr = port.to_le_bytes();
            let _ = ws.send(Message::Binary(Bytes::from(vec![0, hdr[0], hdr[1]]))).await;
            let _ = ws.send(Message::Binary(Bytes::from(vec![1, hdr[0], hdr[1]]))).await;
            while let Some(Ok(Message::Binary(b))) = ws.next().await {
                if b.first() == Some(&0) {
                    let _ = ws.send(Message::Binary(b)).await;
                }
            }
        }
    });
    let mut r = full(101, "");
    let h = r.headers_mut();
    h.insert("connection", http::HeaderValue::from_static("Upgrade"));
    h.insert("upgrade", http::HeaderValue::from_static("websocket"));
    h.insert("sec-websocket-accept", http::HeaderValue::from_str(&accept).expect("accept"));
    h.insert("sec-websocket-protocol", http::HeaderValue::from_static(proto));
    r
}

async fn exec_server(
    ws: &mut WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    state: &Mutex<State>,
) {
    while let Some(Ok(Message::Binary(b))) = ws.next().await {
        match b.split_first() {
            Some((0, data)) if data.starts_with(b"exit ") => {
                let code = String::from_utf8_lossy(&data[5..]).trim().to_owned();
                let st = json!({"status": "Failure", "reason": "NonZeroExitCode",
                                "details": {"causes": [{"reason": "ExitCode", "message": code}]}});
                let mut m = vec![3u8];
                m.extend(serde_json::to_vec(&st).expect("json"));
                let _ = ws.send(Message::Binary(m.into())).await;
                let _ = ws.close(None).await;
                return;
            }
            Some((0, data)) => {
                let mut m = vec![1u8];
                m.extend_from_slice(data);
                let _ = ws.send(Message::Binary(m.into())).await;
            }
            Some((4, data)) => {
                state
                    .lock()
                    .expect("lock")
                    .resizes
                    .push(String::from_utf8_lossy(data).into_owned());
            }
            _ => {}
        }
    }
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<State>>,
) -> Result<Response<Body>, Infallible> {
    let authorized = req.headers().get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"));
    let uri = req.uri().path_and_query().map_or("/", |p| p.as_str()).to_owned();
    state.lock().expect("lock").seen.push(Seen {
        method: req.method().clone(),
        uri: uri.clone(),
        authorized,
    });
    if !authorized {
        return Ok(full(401, "{}"));
    }
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let r = match (req.method().clone(), path.as_str()) {
        (Method::GET, "/version") => json_resp(&json!({"gitVersion": "v1.33.2"})),
        (Method::GET, "/api/v1/namespaces") if query.contains("continue=") => {
            json_resp(&json!({"metadata": {}, "items": [{"metadata": {"name": "kube-system"}}]}))
        }
        (Method::GET, "/api/v1/namespaces") => {
            json_resp(&json!({"metadata": {"continue": "tok+2/="},
            "items": [{"metadata": {"name": "default"}}, {"metadata": {"name": "Bad_Name"}}]}))
        }
        (Method::GET, "/api/v1/namespaces/ns/pods") => {
            json_resp(&json!({"metadata": {}, "items": [pod("web-1"), pod("web-2")]}))
        }
        (Method::GET, "/api/v1/namespaces/ns/pods/web-1") => json_resp(&pod("web-1")),
        (Method::GET, "/api/v1/namespaces/ns/pods/web-1/log") => logs(&query),
        (Method::GET, p) if p.ends_with("/exec") || p.ends_with("/portforward") => {
            upgrade(req, Arc::clone(&state))
        }
        (Method::POST, _) => review(req).await,
        _ => full(404, "{}"),
    };
    Ok(r)
}

impl Mock {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(Mutex::new(State::default()));
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let st = Arc::clone(&st);
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |r| handle(r, Arc::clone(&st)));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        let dir = tempfile::tempdir().expect("tempdir");
        let known = dir.path().join("known_kube_certs");
        std::fs::write(&known, "").expect("known");
        Self { addr, state, _dir: dir, known }
    }

    pub(crate) fn http(&self) -> HttpClient {
        let mut cfg = HttpConfig::new(
            CertProtocol::Kube,
            &format!("http://{}", self.addr),
            self.known.clone(),
        );
        cfg.allow_plaintext = true;
        cfg.rate.rps = 1000.0;
        cfg.rate.burst = 1000;
        HttpClient::new(cfg).expect("http client")
    }

    pub(crate) fn client_with(&self, limits: KubeLimits, token: Option<&str>) -> KubeClient {
        let server = format!("http://{}", self.addr);
        KubeClient::with_http(
            &self.http(),
            &server,
            token.map(SecretString::from),
            limits,
            Some("ns".to_owned()),
            AuditSink::default(),
        )
        .expect("kube client")
    }

    pub(crate) fn client(&self) -> KubeClient {
        self.client_with(limits(8 * 1024 * 1024), Some(TOKEN))
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.state.lock().expect("lock").seen.clone()
    }
}

pub(crate) fn limits(max_log_bytes: u64) -> KubeLimits {
    KubeLimits {
        max_log_bytes,
        log_tail_lines: 500,
        allowed_namespaces: vec!["ns".into()],
        port_forward_enabled: true,
    }
}
