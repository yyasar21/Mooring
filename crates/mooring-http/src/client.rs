//! [`HttpClient`]: one origin, one pool, our verifier, caps, rate limit, retries, redirects.

use std::sync::Arc;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::body::{read_capped, BodyStream};
use crate::config::{Base, HttpConfig, RedirectPolicy, MAX_BODY_CEILING};
use crate::connect::Connector;
use crate::error::{ConnectFailure, HttpError};
use crate::headers::{Headers, Redacted};
use crate::parse::{content_length, decode_json, retry_after, same_origin_location};
use crate::policy::{backoff, TokenBucket};
use crate::verify::TrustDecision;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ReqBody = UnsyncBoxBody<Bytes, BoxError>;

pub(crate) struct Inner {
    pub(crate) cfg: HttpConfig,
    pub(crate) base: Base,
    pub(crate) client: Client<Connector, ReqBody>,
    pub(crate) bucket: TokenBucket,
    pub(crate) slots: Semaphore,
}

/// HTTPS client bound to one origin (`HttpConfig::base_url`). Cheap to clone.
#[derive(Clone)]
pub struct HttpClient {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("protocol", &self.inner.cfg.protocol)
            .field("port", &self.inner.base.port)
            .finish_non_exhaustive()
    }
}

/// A buffered response: status, headers (redacted in `Debug`) and a zeroizing body.
pub struct RawResponse {
    /// Status.
    pub status: StatusCode,
    /// Response headers (`ETag`, …).
    pub headers: HeaderMap,
    /// The body, at most the cap.
    pub body: Zeroizing<Vec<u8>>,
    /// The decision of the connection that served it (`None` for loopback plaintext).
    pub trust: Option<TrustDecision>,
}

impl std::fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawResponse")
            .field("status", &self.status)
            .field("headers", &Redacted(&self.headers))
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl RawResponse {
    /// `Err(Status)` unless 2xx.
    pub fn error_for_status(self) -> Result<Self, HttpError> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(HttpError::Status { status: self.status })
        }
    }

    /// A header as text, if present and visible ASCII.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// One request as the core loop sees it (the body is re-sendable for retries).
pub(crate) struct Spec<'a> {
    pub(crate) method: Method,
    pub(crate) path: &'a str,
    pub(crate) headers: &'a Headers,
    pub(crate) body: Option<(Bytes, Option<&'static str>)>,
    /// Retries allowed (idempotent method and a replayable body).
    pub(crate) retry: bool,
    pub(crate) extra: HeaderMap,
}

fn idempotent(m: &Method) -> bool {
    [Method::GET, Method::HEAD, Method::OPTIONS, Method::PUT, Method::DELETE].contains(m)
}

impl HttpClient {
    /// Validate `cfg` and build the pool. No I/O happens until the first request.
    pub fn new(cfg: HttpConfig) -> Result<Self, HttpError> {
        let base = cfg.validate()?;
        let connector = Connector::new(cfg.clone(), base.clone())?;
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new())
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .pool_max_idle_per_host(cfg.max_concurrent)
            .http1_max_buf_size(64 * 1024)
            .http1_max_headers(128)
            .retry_canceled_requests(false)
            .build(connector);
        let bucket = TokenBucket::new(cfg.rate);
        let slots = Semaphore::new(cfg.max_concurrent);
        Ok(Self { inner: Arc::new(Inner { cfg, base, client, bucket, slots }) })
    }

    /// The configured body cap.
    pub fn max_body(&self) -> usize {
        self.inner.cfg.max_body
    }

    /// Send one request through rate limit, concurrency slot and request deadline; map
    /// connector failures to their [`HttpError`]. No retry, no redirect.
    pub(crate) async fn send_once(
        &self,
        req: Request<ReqBody>,
    ) -> Result<Response<Incoming>, HttpError> {
        self.inner.bucket.acquire().await;
        let _slot = self.inner.slots.acquire().await.map_err(|_| HttpError::Protocol)?;
        let deadline = self.inner.cfg.timeouts.request;
        match tokio::time::timeout(deadline, self.inner.client.request(req)).await {
            Err(_) => Err(HttpError::Timeout),
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(unpack(&e)),
        }
    }

    fn build(&self, spec: &Spec<'_>, uri: http::Uri) -> Result<Request<ReqBody>, HttpError> {
        let mut req = Request::builder().method(spec.method.clone()).uri(uri);
        let headers = req.headers_mut().ok_or(HttpError::InvalidRequest("request"))?;
        headers.extend(spec.headers.0.clone());
        headers.extend(spec.extra.clone());
        let ua = HeaderValue::from_str(&self.inner.cfg.user_agent)
            .map_err(|_| HttpError::InvalidConfig("user_agent"))?;
        headers.insert(USER_AGENT, ua);
        let body: ReqBody = match &spec.body {
            Some((bytes, ctype)) => {
                if let Some(ct) = ctype {
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static(ct));
                }
                Full::new(bytes.clone()).map_err(|never| match never {}).boxed_unsync()
            }
            None => Empty::new().map_err(|never| match never {}).boxed_unsync(),
        };
        req.body(body).map_err(|_| HttpError::InvalidRequest("request"))
    }

    /// The core loop: retries (idempotent, bounded, jittered) and the redirect policy.
    pub(crate) async fn execute(&self, spec: &Spec<'_>) -> Result<Response<Incoming>, HttpError> {
        let policy = self.inner.cfg.retry;
        let attempts = if spec.retry && idempotent(&spec.method) { policy.max_attempts } else { 1 };
        let mut uri = self.inner.base.uri(spec.path)?;
        let mut hops = 0u8;
        let mut attempt = 1u32;
        loop {
            let result = self.send_once(self.build(spec, uri.clone())?).await;
            let wait = match &result {
                Err(HttpError::Connect(_) | HttpError::Timeout) => Some(None),
                Ok(r) if matches!(r.status().as_u16(), 429 | 502 | 503 | 504) => {
                    Some(retry_after(r.headers(), policy.max_delay))
                }
                _ => None,
            };
            if let (Some(server_wait), true) = (wait, attempt < attempts) {
                let delay = server_wait.unwrap_or_else(|| backoff(&policy, attempt));
                tracing::debug!(
                    attempt,
                    delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "http retry"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }
            let resp = result?;
            log(&spec.method, &resp);
            if resp.status().is_redirection() && resp.status() != StatusCode::NOT_MODIFIED {
                let follow = matches!(spec.method, Method::GET | Method::HEAD);
                match self.inner.cfg.redirects {
                    RedirectPolicy::SameOrigin { max } if follow && hops < max => {
                        if let Some(next) = same_origin_location(&self.inner.base, resp.headers()) {
                            hops += 1;
                            uri = next;
                            continue;
                        }
                        return Err(HttpError::Redirect { status: resp.status() });
                    }
                    _ => return Err(HttpError::Redirect { status: resp.status() }),
                }
            }
            return Ok(resp);
        }
    }

    /// Any method; the body is read up to `cap` (≤ 256 MiB) for **any** status, so callers
    /// can read error documents or `ETag`s. 3xx follow the redirect policy.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Option<Bytes>,
        cap: usize,
    ) -> Result<RawResponse, HttpError> {
        if cap == 0 || cap > MAX_BODY_CEILING {
            return Err(HttpError::InvalidRequest("cap must be 1..=256 MiB"));
        }
        let spec = Spec {
            method,
            path,
            headers,
            body: body.map(|b| (b, None)),
            retry: true,
            extra: HeaderMap::new(),
        };
        self.buffered(&spec, cap).await
    }

    async fn buffered(&self, spec: &Spec<'_>, cap: usize) -> Result<RawResponse, HttpError> {
        let resp = self.execute(spec).await?;
        content_length(resp.headers(), cap)?;
        let (parts, body) = resp.into_parts();
        let deadline = self.inner.cfg.timeouts.request;
        let body = tokio::time::timeout(deadline, read_capped(body, cap))
            .await
            .map_err(|_| HttpError::Timeout)??;
        let trust = parts.extensions.get::<TrustDecision>().cloned();
        Ok(RawResponse { status: parts.status, headers: parts.headers, body, trust })
    }

    fn json_spec<'a>(method: Method, path: &'a str, headers: &'a Headers) -> Spec<'a> {
        let mut extra = HeaderMap::new();
        extra.insert(ACCEPT, HeaderValue::from_static("application/json"));
        Spec { method, path, headers, body: None, retry: true, extra }
    }

    /// `GET` → 2xx → JSON (body ≤ `max_body`).
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        headers: &Headers,
    ) -> Result<T, HttpError> {
        let spec = Self::json_spec(Method::GET, path, headers);
        let r = self.buffered(&spec, self.max_body()).await?.error_for_status()?;
        decode_json(&r.body)
    }

    /// `POST` a JSON body → 2xx → JSON. Never retried (not idempotent). An empty 2xx body
    /// decodes as `null` (use `Option<T>` / `()`-like types for 204).
    pub async fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        headers: &Headers,
        body: &B,
    ) -> Result<T, HttpError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(body).map_err(|_| HttpError::InvalidRequest("body is not JSON"))?,
        );
        let mut spec = Self::json_spec(Method::POST, path, headers);
        spec.body = Some((Bytes::copy_from_slice(&bytes), Some("application/json")));
        spec.retry = false;
        let r = self.buffered(&spec, self.max_body()).await?.error_for_status()?;
        if r.body.is_empty() {
            return decode_json(b"null");
        }
        decode_json(&r.body)
    }

    /// `DELETE` → 2xx status (body ≤ 64 KiB, discarded).
    pub async fn delete(&self, path: &str, headers: &Headers) -> Result<StatusCode, HttpError> {
        let spec = Self::json_spec(Method::DELETE, path, headers);
        Ok(self.buffered(&spec, 64 * 1024).await?.error_for_status()?.status)
    }

    /// `PUT` raw bytes with caller headers (S3 `If-None-Match: *` / `If-Match: <etag>`); the
    /// response is returned for any status (`412` → the caller pulls and merges).
    pub async fn put_raw(
        &self,
        path: &str,
        headers: &Headers,
        body: Bytes,
        content_type: Option<&'static str>,
    ) -> Result<RawResponse, HttpError> {
        let spec = Spec {
            method: Method::PUT,
            path,
            headers,
            body: Some((body, content_type)),
            retry: true,
            extra: HeaderMap::new(),
        };
        self.buffered(&spec, 64 * 1024).await
    }

    /// `GET` as a stream of ≤ 64 KiB chunks, at most `total_cap` bytes (logs, watches).
    /// Non-2xx → `Err(Status)`; a declared length above the cap still streams (and truncates).
    pub async fn get_stream(
        &self,
        path: &str,
        headers: &Headers,
        total_cap: usize,
    ) -> Result<BodyStream, HttpError> {
        if total_cap == 0 || total_cap > MAX_BODY_CEILING {
            return Err(HttpError::InvalidRequest("total_cap must be 1..=256 MiB"));
        }
        let spec = Spec {
            method: Method::GET,
            path,
            headers,
            body: None,
            retry: true,
            extra: HeaderMap::new(),
        };
        let resp = self.execute(&spec).await?;
        if !resp.status().is_success() {
            return Err(HttpError::Status { status: resp.status() });
        }
        Ok(BodyStream::new(resp.into_body(), total_cap))
    }
}

/// Status line only: method and status; never headers, query or body.
pub(crate) fn log(method: &Method, resp: &Response<Incoming>) {
    tracing::debug!(method = %method, status = resp.status().as_u16(), "http response");
}

/// Find our [`ConnectFailure`] in hyper-util's error chain.
pub(crate) fn unpack(e: &hyper_util::client::legacy::Error) -> HttpError {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(ConnectFailure(inner)) = err.downcast_ref::<ConnectFailure>() {
            return clone_error(inner);
        }
        cur = err.source();
    }
    if e.is_connect() {
        HttpError::Connect(std::io::ErrorKind::Other)
    } else {
        HttpError::Protocol
    }
}

fn clone_error(e: &HttpError) -> HttpError {
    match e {
        HttpError::InvalidConfig(s) => HttpError::InvalidConfig(s),
        HttpError::InvalidRequest(s) => HttpError::InvalidRequest(s),
        HttpError::PlaintextRefused => HttpError::PlaintextRefused,
        HttpError::TrustStore => HttpError::TrustStore,
        HttpError::TrustPrompt(d) => HttpError::TrustPrompt(d.clone()),
        HttpError::TrustMismatch(d) => HttpError::TrustMismatch(d.clone()),
        HttpError::TrustRejected(d) => HttpError::TrustRejected(d.clone()),
        HttpError::Tls(s) => HttpError::Tls(s.clone()),
        HttpError::Connect(k) => HttpError::Connect(*k),
        HttpError::Timeout => HttpError::Timeout,
        _ => HttpError::Protocol,
    }
}
