//! Request recorder: the "never mutates / never calls X" gate of ADR-0014..0017.
//!
//! Every request a mock server receives becomes one [`RecordedRequest`]: method, raw path,
//! decoded query, headers, body size, response status, and a violation reason when the
//! request hit a server's forbidden-call trap. Credentials never reach the record:
//! [`REDACTED`] replaces the value of every auth-bearing header and query parameter, and
//! bodies are only counted, never kept.

use std::sync::{Arc, Mutex, MutexGuard};

use http::{HeaderMap, Method, Uri};

/// Placeholder for redacted header / query values.
pub const REDACTED: &str = "<redacted>";

/// Records kept per server; older entries are dropped (and counted) past this.
const MAX_RECORDS: usize = 100_000;

const SECRET_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-vault-token",
    "vmware-api-session-id",
    "x-amz-security-token",
];

const SECRET_QUERY: &[&str] = &[
    "code",
    "state",
    "client_nonce",
    "token",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
];

/// One recorded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    /// Raw path as sent (percent-encoding preserved).
    pub path: String,
    /// Decoded query pairs, secret values redacted.
    pub query: Vec<(String, String)>,
    /// Lowercase header names with values; secret values redacted.
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
    pub status: u16,
    /// Set when the request hit the forbidden-call trap (answered 500).
    pub violation: Option<String>,
    /// The request asked for a protocol upgrade (WebSocket).
    pub upgrade: bool,
}

impl RecordedRequest {
    pub(crate) fn new(method: &Method, uri: &Uri, headers: &HeaderMap, upgrade: bool) -> Self {
        let query = super::parse_query(uri.query().unwrap_or(""))
            .into_iter()
            .map(|(k, v)| {
                let secret = SECRET_QUERY.contains(&k.to_ascii_lowercase().as_str());
                (k, if secret { REDACTED.to_owned() } else { v })
            })
            .collect();
        let headers = headers
            .iter()
            .map(|(k, v)| {
                let name = k.as_str().to_owned();
                let value = if SECRET_HEADERS.contains(&name.as_str()) {
                    REDACTED.to_owned()
                } else {
                    String::from_utf8_lossy(v.as_bytes()).into_owned()
                };
                (name, value)
            })
            .collect();
        Self {
            method: method.as_str().to_owned(),
            path: uri.path().to_owned(),
            query,
            headers,
            body_len: 0,
            status: 0,
            violation: None,
            upgrade,
        }
    }

    /// First value of header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn query_get(&self, key: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// `"GET /api/v1/namespaces"`: handy for `assert_eq!` on a whole call sequence.
    pub fn line(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

#[derive(Debug, Default)]
struct Inner {
    records: Vec<RecordedRequest>,
    dropped: usize,
}

/// Shared, cloneable request log of one server.
#[derive(Debug, Clone, Default)]
pub struct Recorder(Arc<Mutex<Inner>>);

impl Recorder {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn push(&self, r: RecordedRequest) {
        let mut g = self.lock();
        if g.records.len() >= MAX_RECORDS {
            g.records.remove(0);
            g.dropped += 1;
        }
        g.records.push(r);
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.lock().records.clone()
    }

    /// `"METHOD /path"` of every request, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.lock().records.iter().map(RecordedRequest::line).collect()
    }

    /// Requests that hit the forbidden-call trap.
    pub fn violations(&self) -> Vec<RecordedRequest> {
        self.lock().records.iter().filter(|r| r.violation.is_some()).cloned().collect()
    }

    /// Panics with the offending requests if any request hit the trap.
    pub fn assert_no_violations(&self) {
        let v = self.violations();
        assert!(v.is_empty(), "forbidden calls reached the mock server: {v:#?}");
    }

    /// Requests whose method equals `method` and whose path starts with `path_prefix`.
    pub fn count(&self, method: &str, path_prefix: &str) -> usize {
        self.lock()
            .records
            .iter()
            .filter(|r| r.method == method && r.path.starts_with(path_prefix))
            .count()
    }

    pub fn len(&self) -> usize {
        self.lock().records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().records.is_empty()
    }

    /// Records dropped because the log was full.
    pub fn dropped(&self) -> usize {
        self.lock().dropped
    }

    pub fn clear(&self) {
        let mut g = self.lock();
        g.records.clear();
        g.dropped = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordedRequest, Recorder, REDACTED};

    #[test]
    fn redacts_secret_headers_and_query() {
        let mut h = http::HeaderMap::new();
        h.insert("authorization", "Bearer s3cr3t".parse().expect("hv"));
        h.insert("x-vault-token", "hvs.x".parse().expect("hv"));
        h.insert("accept", "application/json".parse().expect("hv"));
        let uri: http::Uri = "/cb?code=abc&state=xyz&role=r".parse().expect("uri");
        let r = RecordedRequest::new(&http::Method::GET, &uri, &h, false);
        assert_eq!(r.header("authorization"), Some(REDACTED));
        assert_eq!(r.header("x-vault-token"), Some(REDACTED));
        assert_eq!(r.header("accept"), Some("application/json"));
        assert_eq!(r.query_get("code"), Some(REDACTED));
        assert_eq!(r.query_get("role"), Some("r"));
        assert!(!format!("{r:?}").contains("s3cr3t"));
        let rec = Recorder::default();
        rec.push(r);
        assert_eq!(rec.count("GET", "/cb"), 1);
        rec.assert_no_violations();
    }
}
