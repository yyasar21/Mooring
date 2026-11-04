//! Shared HTTP/1.1-over-TLS plumbing for the A3 mock API servers (ADR-0014..0017 §Test plan).
//!
//! Every server is a [`Handler`] behind [`serve`]: a loopback TCP listener, a rustls (ring)
//! acceptor with a [`TestCert`](crate::tls::TestCert), hyper 1 `http1` with upgrades (for the
//! kube WebSockets). [`serve`] reads the request body with a hard cap, calls the handler, and
//! writes one [`RecordedRequest`] per request into the server's [`Recorder`] *before* the
//! response leaves, so a test can assert on it even after a client-side timeout.

mod body;
pub mod recorder;
pub mod time;
pub mod ws;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub use body::Body;
pub use recorder::{RecordedRequest, Recorder, REDACTED};

/// Transport-level knobs every mock server has (hostile / slow server behaviour).
#[derive(Debug, Clone)]
pub struct HttpKnobs {
    /// Sleep this long after recording a request and before sending the response head.
    pub response_delay: Option<Duration>,
    /// Slow-loris response: send a fixed-size body one byte at a time with this gap
    /// (`Content-Length` is still announced up front).
    pub drip: Option<Duration>,
    /// Request bodies above this are refused with 413 before the handler runs.
    pub max_request_body: usize,
}

impl Default for HttpKnobs {
    fn default() -> Self {
        Self { response_delay: None, drip: None, max_request_body: 16 * 1024 * 1024 }
    }
}

/// One request as the handler sees it: the head, the whole (capped) body, the upgrade future
/// for WebSocket requests, and the verified client certificate if the client sent one.
#[derive(Debug)]
pub struct Ctx {
    pub method: Method,
    /// Raw request path, percent-encoding preserved.
    pub path: String,
    /// Raw query string (without `?`).
    pub raw_query: Option<String>,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub upgrade: Option<OnUpgrade>,
    pub client_cert: Option<CertificateDer<'static>>,
}

impl Ctx {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Percent-decoded query pairs in order (`+` is a space, as in forms).
    pub fn query(&self) -> Vec<(String, String)> {
        parse_query(self.raw_query.as_deref().unwrap_or(""))
    }

    pub fn query_get(&self, key: &str) -> Option<String> {
        self.query().into_iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Every value of `key`, also splitting comma lists (`hosts=a,b&hosts=c`).
    pub fn query_all(&self, key: &str) -> Vec<String> {
        self.query()
            .into_iter()
            .filter(|(k, _)| k == key)
            .flat_map(|(_, v)| v.split(',').map(str::to_owned).collect::<Vec<_>>())
            .filter(|v| !v.is_empty())
            .collect()
    }

    pub fn json_body(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// A handler's answer, plus a violation reason when the request broke the server's
/// allow-list (the "never mutates / never calls X" gate; see [`Recorder::violations`]).
#[derive(Debug)]
pub struct Reply {
    pub resp: Response<Body>,
    pub violation: Option<String>,
}

impl From<Response<Body>> for Reply {
    fn from(resp: Response<Body>) -> Self {
        Self { resp, violation: None }
    }
}

impl Reply {
    /// The trap answer: 500 with a JSON body naming the reason, recorded as a violation.
    pub fn violation(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let body = serde_json::json!({ "mooringTestsrvViolation": reason });
        Self { resp: json(StatusCode::INTERNAL_SERVER_ERROR, &body), violation: Some(reason) }
    }
}

pub type HandlerFuture = Pin<Box<dyn Future<Output = Reply> + Send>>;

/// A mock API server's request logic.
pub trait Handler: Send + Sync + 'static {
    fn http_knobs(&self) -> HttpKnobs;
    fn handle(self: Arc<Self>, ctx: Ctx) -> HandlerFuture;
}

/// A running listener; dropping it stops accepting and ends open HTTP connections.
#[derive(Debug)]
pub struct Running {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
    _stop: watch::Sender<bool>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Binds `127.0.0.1:port` and serves `handler` over TLS until the returned value is dropped.
pub async fn serve<H: Handler>(
    tls: Arc<ServerConfig>,
    port: u16,
    handler: Arc<H>,
    recorder: Recorder,
) -> std::io::Result<Running> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let acceptor = TlsAcceptor::from(tls);
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            let recorder = recorder.clone();
            let mut stop = stop_rx.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(tcp).await else { return };
                let client_cert =
                    stream.get_ref().1.peer_certificates().and_then(|c| c.first().cloned());
                let svc = service_fn(move |req| {
                    let h = Arc::clone(&handler);
                    let rec = recorder.clone();
                    let cc = client_cert.clone();
                    async move { Ok::<_, Infallible>(dispatch(h, rec, cc, req).await) }
                });
                let conn = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades();
                tokio::select! {
                    _ = conn => {}
                    _ = stop.changed() => {}
                }
            });
        }
    });
    Ok(Running { addr, task, _stop: stop_tx })
}

async fn dispatch<H: Handler>(
    handler: Arc<H>,
    recorder: Recorder,
    client_cert: Option<CertificateDer<'static>>,
    mut req: Request<Incoming>,
) -> Response<Body> {
    let knobs = handler.http_knobs();
    let wants_upgrade = req.headers().contains_key(http::header::UPGRADE);
    let upgrade = wants_upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, incoming) = req.into_parts();
    let mut record = RecordedRequest::new(&parts.method, &parts.uri, &parts.headers, wants_upgrade);
    let announced = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let too_big = |n: u64| usize::try_from(n).map_or(true, |n| n > knobs.max_request_body);
    let body = if announced.is_some_and(too_big) {
        None
    } else {
        Limited::new(incoming, knobs.max_request_body)
            .collect()
            .await
            .ok()
            .map(http_body_util::Collected::to_bytes)
    };
    let Some(body) = body else {
        record.status = 413;
        recorder.push(record);
        return empty(StatusCode::PAYLOAD_TOO_LARGE);
    };
    record.body_len = body.len();
    let ctx = Ctx {
        method: parts.method,
        path: parts.uri.path().to_owned(),
        raw_query: parts.uri.query().map(str::to_owned),
        headers: parts.headers,
        body,
        upgrade,
        client_cert,
    };
    let reply = handler.handle(ctx).await;
    record.status = reply.resp.status().as_u16();
    record.violation = reply.violation;
    recorder.push(record);
    if let Some(d) = knobs.response_delay {
        tokio::time::sleep(d).await;
    }
    match knobs.drip {
        Some(gap) => body::drip(reply.resp, gap),
        None => reply.resp,
    }
}

/// Percent-decodes `s` (`+` → space when `form`); invalid escapes are kept verbatim.
pub fn pct_decode(s: &str, form: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| char::from(c).to_digit(16);
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' if form => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// RFC 3986 encoding of everything but the unreserved set (and `/` when `keep_slash`).
pub fn pct_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && c == b'/')
        {
            out.push(char::from(c));
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{c:02X}"));
        }
    }
    out
}

pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct_decode(k, true), pct_decode(v, true))
        })
        .collect()
}

pub fn json(status: StatusCode, v: &serde_json::Value) -> Response<Body> {
    bytes(status, "application/json", serde_json::to_vec(v).unwrap_or_default())
}

pub fn bytes(status: StatusCode, content_type: &str, b: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(Body::full(b));
    *r.status_mut() = status;
    if let Ok(v) = HeaderValue::from_str(content_type) {
        r.headers_mut().insert(CONTENT_TYPE, v);
    }
    r
}

pub fn empty(status: StatusCode) -> Response<Body> {
    let mut r = Response::new(Body::full(Bytes::new()));
    *r.status_mut() = status;
    r
}

/// Lowercase hex (no extra crate).
pub fn hex(b: &[u8]) -> String {
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// `n` random bytes as hex (session ids, tokens, ETags of fixtures).
pub fn random_hex(n: usize) -> String {
    use rand_core::RngCore as _;
    let mut b = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut b);
    hex(&b)
}
