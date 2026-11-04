//! Request headers with redaction: credentials are marked sensitive (hyper never logs them,
//! HPACK never indexes them) and every `Debug` of ours prints `<redacted>` for them.

use http::header::{HeaderName, HeaderValue, AUTHORIZATION};
use http::HeaderMap;

use crate::error::HttpError;

/// Header names whose values are never logged or shown (lowercase).
pub const SENSITIVE: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-vault-token",
    "vmware-api-session-id",
    "x-amz-security-token",
    "x-api-key",
];

/// Whether `name` carries a credential (case-insensitive; also any `*-token` / `*-secret`).
pub fn is_sensitive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SENSITIVE.contains(&n.as_str()) || n.ends_with("-token") || n.ends_with("-secret")
}

/// Headers of one request. `Debug` redacts credentials.
#[derive(Clone, Default)]
pub struct Headers(pub(crate) HeaderMap);

impl Headers {
    /// No headers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `name: value`; a credential header is marked sensitive automatically.
    pub fn insert(mut self, name: &str, value: &str) -> Result<Self, HttpError> {
        let n = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpError::InvalidRequest("invalid header name"))?;
        if n == http::header::HOST || n == http::header::CONNECTION || n == http::header::UPGRADE {
            return Err(HttpError::InvalidRequest(
                "host / connection / upgrade are set by the client",
            ));
        }
        let mut v = HeaderValue::from_str(value)
            .map_err(|_| HttpError::InvalidRequest("invalid header value"))?;
        if is_sensitive(n.as_str()) {
            v.set_sensitive(true);
        }
        self.0.append(n, v);
        Ok(self)
    }

    /// `Authorization: Bearer <token>` (sensitive).
    pub fn bearer(self, token: &str) -> Result<Self, HttpError> {
        self.insert(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
    }

    /// The underlying map.
    pub fn as_map(&self) -> &HeaderMap {
        &self.0
    }
}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Redacted(&self.0).fmt(f)
    }
}

/// `Debug` view of a [`HeaderMap`] with credentials and sensitive values redacted.
pub struct Redacted<'a>(pub &'a HeaderMap);

impl std::fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (k, v) in self.0 {
            if v.is_sensitive() || is_sensitive(k.as_str()) {
                m.entry(&k.as_str(), &"<redacted>");
            } else {
                m.entry(&k.as_str(), &v.to_str().unwrap_or("<binary>"));
            }
        }
        m.finish()
    }
}

/// Mark every credential header of `map` sensitive (requests arriving through the tower
/// service come from kube with plain values).
pub(crate) fn mark_sensitive(map: &mut HeaderMap) {
    for (k, v) in map.iter_mut() {
        if is_sensitive(k.as_str()) {
            v.set_sensitive(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_show_in_debug() {
        let h = Headers::new()
            .bearer("tok-SECRET-1")
            .and_then(|h| h.insert("X-Vault-Token", "hvs.SECRET2"))
            .and_then(|h| h.insert("Cookie", "a=SECRET3"))
            .and_then(|h| h.insert("vmware-api-session-id", "SECRET4"))
            .and_then(|h| h.insert("If-Match", "\"etag-1\""))
            .expect("headers");
        let dbg = format!("{h:?}");
        assert!(!dbg.contains("SECRET"), "{dbg}");
        assert!(dbg.contains("etag-1") && dbg.contains("<redacted>"), "{dbg}");
        assert!(h.as_map().get("authorization").is_some_and(HeaderValue::is_sensitive));
        assert!(Headers::new().insert("Host", "x").is_err());
        assert!(Headers::new().insert("bad name", "x").is_err());
        assert!(Headers::new().insert("x-a", "line\nbreak").is_err());
    }
}
