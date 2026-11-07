//! [`HttpConfig`] and its policies (ADR-0014 §1 `HttpPolicy`), validated once in
//! [`crate::HttpClient::new`].

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use mooring_core::known_certs::CertProtocol;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::error::HttpError;
use crate::verify::TrustDecision;

/// Default response body cap of the buffered helpers.
pub const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;
/// Hard ceiling for any configured body cap.
pub const MAX_BODY_CEILING: usize = 256 * 1024 * 1024;
/// Largest chunk a [`crate::BodyStream`] yields.
pub const STREAM_CHUNK: usize = 64 * 1024;
/// Largest `extra_ca_pem` accepted.
pub const MAX_CA_PEM: usize = 64 * 1024;

/// Connect and request deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP connect plus TLS handshake.
    pub connect: Duration,
    /// Per phase: sending the request until the response head, and again for reading the
    /// body of a buffered helper. Streams and websockets have no body deadline.
    pub request: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { connect: Duration::from_secs(10), request: Duration::from_secs(30) }
    }
}

/// Token bucket per client (one client = one origin).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    /// Sustained requests per second (`0.1..=1000`).
    pub rps: f64,
    /// Bucket size (`1..=1000`).
    pub burst: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self { rps: 10.0, burst: 10 }
    }
}

/// Retries of idempotent requests (GET, HEAD, OPTIONS, PUT, DELETE) after a connect failure,
/// `429`, `502`, `503` or `504`. Trust, cap and decode failures are never retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts including the first (`1..=5`; `1` disables retries).
    pub max_attempts: u32,
    /// Backoff base; attempt `n` waits a uniformly random time in `0..=min(max, base·2ⁿ)`.
    pub base_delay: Duration,
    /// Backoff ceiling, also the ceiling for a server `Retry-After`.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        }
    }
}

/// What a `3xx` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedirectPolicy {
    /// Fail with [`HttpError::Redirect`] (default).
    #[default]
    Refuse,
    /// Follow up to `max` redirects of GET / HEAD whose `Location` has the base origin.
    SameOrigin {
        /// Most hops (`1..=10`).
        max: u8,
    },
}

/// A TLS client certificate (kubeconfig `client-certificate-data` / `client-key-data`).
#[derive(Clone)]
pub struct ClientIdentity {
    /// Leaf first, DER.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8, PKCS#1 or SEC1 DER.
    pub key_der: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("certs", &self.cert_chain_der.len())
            .finish_non_exhaustive()
    }
}

/// Everything one [`crate::HttpClient`] needs. Build with [`HttpConfig::new`] and adjust the
/// public fields.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Pin store, TOFU file and audit protocol.
    pub protocol: CertProtocol,
    /// `https://host[:port][/prefix]`; every request path is appended to it.
    pub base_url: String,
    /// `$APP_DATA/known_<protocol>_certs` (read only; the Gate writes pins). Unreadable →
    /// every connect fails with [`HttpError::TrustStore`] (fail closed).
    pub known_certs_path: PathBuf,
    /// Extra PEM roots (`caPem`, kubeconfig CA data), certificates only, ≤ 64 KiB.
    pub extra_ca_pem: Option<String>,
    /// Anchored mode (ADR-0014 §3): the chain must validate against `extra_ca_pem` alone; no
    /// system roots, no pins, no TOFU. Requires `extra_ca_pem`.
    pub ca_exclusive: bool,
    /// Load the OS trust store (ignored in anchored mode). Default `true`.
    pub use_system_roots: bool,
    /// A leaf the user accepted for this client only (prompt "yes, once"); never overrides a
    /// pin of the host.
    pub trusted_once: Option<[u8; 32]>,
    /// SNI / name-check override (kubeconfig `tls-server-name`); pins stay keyed by the URL.
    pub tls_server_name: Option<String>,
    /// mTLS identity.
    pub client_identity: Option<ClientIdentity>,
    /// Deadlines.
    pub timeouts: Timeouts,
    /// Body cap of the buffered helpers (default 8 MiB, ≤ 256 MiB).
    pub max_body: usize,
    /// Rate limit.
    pub rate: RateLimit,
    /// Requests in flight at once (`1..=64`, default 4).
    pub max_concurrent: usize,
    /// Retries.
    pub retry: RetryPolicy,
    /// Redirects.
    pub redirects: RedirectPolicy,
    /// `User-Agent` (visible ASCII, ≤ 128).
    pub user_agent: String,
    /// Permit `http://` — only to a loopback IP literal, and never to a host with a pin or a
    /// "TLS seen" marker. Not exposed to the UI by default.
    pub allow_plaintext: bool,
    /// Non-blocking feed of every handshake decision (`try_send`; dropped when full).
    pub trust_events: Option<mpsc::Sender<TrustDecision>>,
    /// ADR-0025: reach the origin through this dialer (a jump-host chain) instead of direct
    /// TCP; TLS, pins and the verifier are unchanged (the page keeps its host name). `None` =
    /// direct TCP. Every pooled connection dials again.
    pub dialer: Option<mooring_core::SharedDialer>,
}

impl HttpConfig {
    /// Defaults of ADR-0014 §1 for `base_url`.
    pub fn new(protocol: CertProtocol, base_url: &str, known_certs_path: PathBuf) -> Self {
        Self {
            protocol,
            base_url: base_url.to_owned(),
            known_certs_path,
            extra_ca_pem: None,
            ca_exclusive: false,
            use_system_roots: true,
            trusted_once: None,
            tls_server_name: None,
            client_identity: None,
            timeouts: Timeouts::default(),
            max_body: DEFAULT_MAX_BODY,
            rate: RateLimit::default(),
            max_concurrent: 4,
            retry: RetryPolicy::default(),
            redirects: RedirectPolicy::Refuse,
            user_agent: format!("Mooring/{}", env!("CARGO_PKG_VERSION")),
            allow_plaintext: false,
            trust_events: None,
            dialer: None,
        }
    }

    /// Reach the origin through `dialer` (ADR-0025 jump hosts).
    #[must_use]
    pub fn via(mut self, dialer: mooring_core::SharedDialer) -> Self {
        self.dialer = Some(dialer);
        self
    }

    pub(crate) fn validate(&self) -> Result<Base, HttpError> {
        let bad = HttpError::InvalidConfig;
        let base = Base::parse(&self.base_url)?;
        if !(base.tls || self.allow_plaintext && base.loopback_ip()) {
            return Err(HttpError::PlaintextRefused);
        }
        if self.extra_ca_pem.as_ref().is_some_and(|p| p.len() > MAX_CA_PEM) {
            return Err(bad("extra_ca_pem exceeds 64 KiB"));
        }
        if self.ca_exclusive && self.extra_ca_pem.is_none() {
            return Err(bad("ca_exclusive needs extra_ca_pem"));
        }
        if self.max_body == 0 || self.max_body > MAX_BODY_CEILING {
            return Err(bad("max_body must be 1..=256 MiB"));
        }
        if !(0.1..=1000.0).contains(&self.rate.rps) || !(1..=1000).contains(&self.rate.burst) {
            return Err(bad("rate limit out of range"));
        }
        if !(1..=64).contains(&self.max_concurrent) {
            return Err(bad("max_concurrent must be 1..=64"));
        }
        if !(1..=5).contains(&self.retry.max_attempts)
            || self.retry.max_delay > Duration::from_secs(60)
        {
            return Err(bad("retry policy out of range"));
        }
        if let RedirectPolicy::SameOrigin { max } = self.redirects {
            if !(1..=10).contains(&max) {
                return Err(bad("redirect hops must be 1..=10"));
            }
        }
        let zero = Duration::ZERO;
        if self.timeouts.connect == zero || self.timeouts.request == zero {
            return Err(bad("timeouts must be positive"));
        }
        let ua = &self.user_agent;
        if ua.is_empty() || ua.len() > 128 || !ua.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(bad("user_agent must be visible ASCII, at most 128 bytes"));
        }
        if let Some(name) = &self.tls_server_name {
            if crate::verify::server_name(name).is_none() {
                return Err(bad("tls_server_name is not a DNS name or IP address"));
            }
        }
        Ok(base)
    }
}

/// The parsed base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Base {
    pub(crate) tls: bool,
    /// Lowercase; IPv6 without brackets.
    pub(crate) host: String,
    pub(crate) port: u16,
    /// `host:port` as it goes into the URI authority (IPv6 bracketed).
    pub(crate) authority: http::uri::Authority,
    /// Path prefix without a trailing `/` (may be empty).
    pub(crate) prefix: String,
}

impl Base {
    pub(crate) fn parse(url: &str) -> Result<Self, HttpError> {
        let bad = HttpError::InvalidConfig;
        if url.len() > 2048 {
            return Err(bad("base_url too long"));
        }
        let uri: http::Uri = url.parse().map_err(|_| bad("base_url is not a URL"))?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(bad("base_url must be https://")),
        };
        let auth = uri.authority().ok_or(bad("base_url has no host"))?;
        if auth.as_str().contains('@') {
            return Err(bad("base_url must not carry user info"));
        }
        let host = auth.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        if host.is_empty() {
            return Err(bad("base_url has no host"));
        }
        let port = auth.port_u16().unwrap_or(if tls { 443 } else { 80 });
        if port == 0 {
            return Err(bad("base_url port must be 1..=65535"));
        }
        let authority =
            if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        let authority = authority.parse().map_err(|_| bad("base_url host is invalid"))?;
        let pq = uri.path_and_query().map_or("", |p| p.as_str());
        if pq.contains('?') {
            return Err(bad("base_url must not carry a query"));
        }
        let prefix = pq.trim_end_matches('/').to_owned();
        Ok(Self { tls, host, port, authority, prefix })
    }

    pub(crate) fn loopback_ip(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    pub(crate) fn scheme(&self) -> &'static str {
        if self.tls {
            "https"
        } else {
            "http"
        }
    }

    /// `path` (with an optional query) appended to the prefix. `path` must start with `/` and
    /// contain no fragment, whitespace or control characters.
    pub(crate) fn uri(&self, path: &str) -> Result<http::Uri, HttpError> {
        crate::parse::check_path(path)?;
        let full = format!("{}{path}", self.prefix);
        http::Uri::builder()
            .scheme(self.scheme())
            .authority(self.authority.clone())
            .path_and_query(full)
            .build()
            .map_err(|_| HttpError::InvalidRequest("path is not a valid URI path"))
    }

    /// Whether `uri` names this origin (scheme, host, port).
    pub(crate) fn same_origin(&self, uri: &http::Uri) -> bool {
        let Some(auth) = uri.authority() else { return false };
        let host = auth.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let port = auth.port_u16().unwrap_or(if self.tls { 443 } else { 80 });
        uri.scheme_str() == Some(self.scheme()) && host == self.host && port == self.port
    }
}
