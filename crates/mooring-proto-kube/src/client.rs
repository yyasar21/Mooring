//! [`KubeClient`]: `kube::Client::new(service)` over `mooring-http`, under the
//! [`crate::ReadOnlyGuard`] (ADR-0014 §2, §4). Every request — JSON, log stream, WebSocket
//! upgrade — goes through the same stack: `kube::Client` → guard → bearer → `HttpService`.
//!
//! `kube::Config`, its kubeconfig loaders and the inferring constructors are never used (clippy
//! `disallowed-methods`). We only borrow kube's buffered client; responses are read with our
//! own caps and decoded with position-only errors (kube's helpers log bodies on failure).

use std::sync::Arc;

use bytes::Bytes;
use http::header::{
    CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_VERSION, UPGRADE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use kube::client::Body;
use mooring_core::credential::kubeconfig::Resolved;
use mooring_core::options::KubeConnOptions;
use mooring_http::{HttpClient, HttpConfig};
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;
use tower::ServiceBuilder;
use zeroize::Zeroizing;

use crate::audit::{AuditSink, KubeAudit};
use crate::auth::{bearer, http_config, BearerLayer};
use crate::error::KubeError;
use crate::guard::{GuardPolicy, ReadOnlyGuardLayer};

/// Body cap of JSON responses (ADR-0014 §5: 16 MiB).
pub const MAX_JSON_BODY: usize = 16 * 1024 * 1024;
/// Largest WebSocket message / frame accepted from the API server.
pub const MAX_WS_MESSAGE: usize = 1024 * 1024;
/// Concurrent log streams per cluster (ADR-0014 §5).
pub const MAX_LOG_STREAMS: usize = 8;

/// A framed WebSocket from an upgrade through the guarded stack.
pub type KubeWs = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

/// Per-connection limits taken from [`KubeConnOptions`].
#[derive(Debug, Clone)]
pub struct KubeLimits {
    /// `limitBytes` and the read cap of a log stream.
    pub max_log_bytes: u64,
    /// Default `tailLines` (clamped to 10 000 per request).
    pub log_tail_lines: u32,
    /// Offered when `list namespaces` is denied.
    pub allowed_namespaces: Vec<String>,
    /// Whether pod port-forwards may be opened.
    pub port_forward_enabled: bool,
}

impl KubeLimits {
    /// From validated options.
    pub fn from_options(o: &KubeConnOptions) -> Self {
        Self {
            max_log_bytes: o.max_log_bytes,
            log_tail_lines: o.log_tail_lines,
            allowed_namespaces: o.allowed_namespaces.clone(),
            port_forward_enabled: o.port_forward_enabled,
        }
    }
}

/// A connected, read-only Kubernetes API client (cheap to clone).
#[derive(Clone)]
pub struct KubeClient {
    api: kube::Client,
    stream: kube::Client,
    pub(crate) audit: AuditSink,
    pub(crate) limits: Arc<KubeLimits>,
    namespace: Option<String>,
    server: String,
    pub(crate) log_slots: Arc<Semaphore>,
}

impl std::fmt::Debug for KubeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeClient")
            .field("server", &self.server)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// `buffered`: lists, gets and reviews get the request deadline on the whole body (a dripped
/// response fails with `kube.unreachable` / `http.timeout` instead of completing after
/// minutes); streams (watch, logs, upgrades) are long-lived and keep only their byte caps.
fn build(
    http: &HttpClient,
    cap: usize,
    buffered: bool,
    guard: &ReadOnlyGuardLayer,
    auth: &BearerLayer,
) -> Result<kube::Client, KubeError> {
    let service = if buffered { http.buffered_service(cap)? } else { http.service(cap)? };
    let svc = ServiceBuilder::new().layer(guard.clone()).layer(auth.clone()).service(service);
    Ok(kube::Client::new(svc, "default"))
}

impl KubeClient {
    /// Build the client for `resolved` and check reachability with `GET /version`. A first
    /// contact with an unknown certificate fails with `Http(TrustPrompt)`: prompt, then call
    /// again with `template.trusted_once` set (or after the Gate wrote the pin). Records
    /// `kube.connected` with the `SelfSubjectReview` identity when it is allowed.
    pub async fn connect(
        resolved: &Resolved,
        options: &KubeConnOptions,
        template: HttpConfig,
    ) -> Result<Self, KubeError> {
        options.validate().map_err(|_| KubeError::Invalid("connection options"))?;
        let cfg = http_config(resolved, template)?;
        let http = HttpClient::new(cfg)?;
        let namespace = options.namespace.clone().or_else(|| resolved.namespace.clone());
        let client = Self::with_http(
            &http,
            resolved.server.as_str(),
            bearer(&resolved.auth),
            KubeLimits::from_options(options),
            namespace,
            AuditSink::default(),
        )?;
        client.version().await?;
        let identity = client.whoami().await.ok().map(|i| i.user);
        client.audit.push(KubeAudit::Connected { server: client.server.clone(), identity });
        Ok(client)
    }

    /// Lower-level constructor over an existing [`HttpClient`] (K4 for tests, loopback mocks).
    pub fn with_http(
        http: &HttpClient,
        server: &str,
        token: Option<SecretString>,
        limits: KubeLimits,
        namespace: Option<String>,
        audit: AuditSink,
    ) -> Result<Self, KubeError> {
        let policy = GuardPolicy { max_log_bytes: limits.max_log_bytes };
        let guard = ReadOnlyGuardLayer::new(policy, audit.clone());
        let auth = BearerLayer(token.map(Arc::new));
        let stream_cap = usize::try_from(limits.max_log_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(MAX_WS_MESSAGE)
            .clamp(MAX_JSON_BODY, 256 * 1024 * 1024);
        Ok(Self {
            api: build(http, MAX_JSON_BODY, true, &guard, &auth)?,
            stream: build(http, stream_cap, false, &guard, &auth)?,
            audit,
            limits: Arc::new(limits),
            namespace,
            server: server.to_owned(),
            log_slots: Arc::new(Semaphore::new(MAX_LOG_STREAMS)),
        })
    }

    /// The audit queue (drain with [`AuditSink::take`]).
    pub fn audit(&self) -> &AuditSink {
        &self.audit
    }

    /// The default namespace (options, then context), if any.
    pub fn default_namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The API server URL.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Namespaces offered when `list namespaces` is denied.
    pub fn allowed_namespaces(&self) -> &[String] {
        &self.limits.allowed_namespaces
    }

    /// `GET /version` → `gitVersion`.
    pub async fn version(&self) -> Result<String, KubeError> {
        #[derive(serde::Deserialize)]
        struct V {
            #[serde(rename = "gitVersion", default)]
            git_version: String,
        }
        let v: V = self.get_json("/version").await?;
        Ok(crate::browse::clean(&v.git_version, 64))
    }

    /// Send through the guarded stack; non-success statuses become errors (body dropped).
    pub(crate) async fn send(
        &self,
        req: Request<Vec<u8>>,
        streaming: bool,
    ) -> Result<Response<Body>, KubeError> {
        let c = if streaming { &self.stream } else { &self.api };
        let resp = c.send(req.map(Body::from)).await.map_err(KubeError::from_kube)?;
        let s = resp.status();
        if s.is_success() || s == StatusCode::SWITCHING_PROTOCOLS {
            Ok(resp)
        } else {
            Err(KubeError::from_status(s))
        }
    }

    /// `GET path` → JSON, capped at 16 MiB, decoded from a zeroizing buffer.
    pub(crate) async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, KubeError> {
        let req =
            Request::get(path).body(Vec::new()).map_err(|_| KubeError::Invalid("request path"))?;
        self.json(req).await
    }

    /// `POST path` with a JSON body → JSON.
    pub(crate) async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, KubeError> {
        let bytes = serde_json::to_vec(body).map_err(|_| KubeError::Invalid("request body"))?;
        let req = Request::post(path)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(bytes)
            .map_err(|_| KubeError::Invalid("request path"))?;
        self.json(req).await
    }

    async fn json<T: DeserializeOwned>(&self, req: Request<Vec<u8>>) -> Result<T, KubeError> {
        let resp = self.send(req, false).await?;
        let buf = read_capped(resp.into_body(), MAX_JSON_BODY).await?;
        serde_json::from_slice(&buf).map_err(|_| KubeError::Protocol("response JSON invalid"))
    }

    /// WebSocket upgrade on `path`, offering `protocols`; returns the stream and the selected
    /// protocol (which must be one of those offered).
    pub(crate) async fn upgrade(
        &self,
        path: &str,
        protocols: &[&'static str],
    ) -> Result<(KubeWs, &'static str), KubeError> {
        let key = generate_key();
        let offer = HeaderValue::from_str(&protocols.join(", "))
            .map_err(|_| KubeError::Invalid("sub-protocol"))?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header(SEC_WEBSOCKET_VERSION, "13")
            .header(SEC_WEBSOCKET_KEY, key.as_str())
            .header(SEC_WEBSOCKET_PROTOCOL, offer)
            .body(Vec::new())
            .map_err(|_| KubeError::Invalid("request path"))?;
        let resp = self.send(req, true).await?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(KubeError::Protocol("server did not switch protocols"));
        }
        let h = resp.headers();
        if h.get(SEC_WEBSOCKET_ACCEPT).map(HeaderValue::as_bytes)
            != Some(derive_accept_key(key.as_bytes()).as_bytes())
        {
            return Err(KubeError::Protocol("bad Sec-WebSocket-Accept"));
        }
        let selected = h.get(SEC_WEBSOCKET_PROTOCOL).and_then(|v| v.to_str().ok());
        let Some(proto) = protocols.iter().copied().find(|p| Some(*p) == selected) else {
            return Err(KubeError::Protocol("server selected no offered sub-protocol"));
        };
        let up =
            hyper::upgrade::on(resp).await.map_err(|_| KubeError::Protocol("upgrade failed"))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_WS_MESSAGE))
            .max_frame_size(Some(MAX_WS_MESSAGE));
        let ws =
            WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Client, Some(config)).await;
        Ok((ws, proto))
    }
}

/// Read a body into a zeroizing buffer, failing above `cap` before copying the frame.
pub(crate) async fn read_capped(
    mut body: Body,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, KubeError> {
    let mut out = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(KubeError::from_kube)?;
        if let Ok(data) = frame.into_data() {
            append(&mut out, &data, cap)?;
        }
    }
    Ok(out)
}

fn append(out: &mut Zeroizing<Vec<u8>>, data: &Bytes, cap: usize) -> Result<(), KubeError> {
    if data.len() > cap - out.len() {
        return Err(KubeError::Protocol("response body exceeds the cap"));
    }
    if out.capacity() - out.len() < data.len() {
        let want = (out.len() + data.len()).max(out.capacity() * 2).min(cap);
        let mut bigger = Zeroizing::new(Vec::with_capacity(want));
        bigger.extend_from_slice(out);
        *out = bigger;
    }
    out.extend_from_slice(data);
    Ok(())
}
