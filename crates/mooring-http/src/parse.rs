//! Pure parsers of server-controlled response parts. None of them panics or allocates beyond
//! its input; each has a proptest below and a `fuzz_*` entry in [`crate::fuzz`].

use std::time::Duration;

use http::header::{CONTENT_LENGTH, LOCATION, RETRY_AFTER};
use http::HeaderMap;
use serde::de::DeserializeOwned;

use crate::config::Base;
use crate::error::HttpError;

/// Longest request path (with query) accepted.
pub const MAX_PATH: usize = 8 * 1024;

/// A request path: starts with `/`, ≤ 8 KiB, no fragment, no space, no control character,
/// not `//…` (which a server could read as an authority).
pub(crate) fn check_path(path: &str) -> Result<(), HttpError> {
    let bad = HttpError::InvalidRequest;
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(bad("path must start with a single /"));
    }
    if path.len() > MAX_PATH {
        return Err(bad("path too long"));
    }
    if path.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'#' || b >= 0x80) {
        return Err(bad("path contains a forbidden character (percent-encode it)"));
    }
    Ok(())
}

/// The declared `Content-Length`: `None` when absent; an error when it is malformed, repeated
/// with different values, or above `cap` (checked before any body byte is read).
pub fn content_length(headers: &HeaderMap, cap: usize) -> Result<Option<u64>, HttpError> {
    let mut seen: Option<u64> = None;
    for v in headers.get_all(CONTENT_LENGTH) {
        let s = v.to_str().map_err(|_| HttpError::Protocol)?;
        if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HttpError::Protocol);
        }
        let n: u64 = s.parse().map_err(|_| HttpError::Protocol)?;
        if seen.is_some_and(|p| p != n) {
            return Err(HttpError::Protocol);
        }
        seen = Some(n);
    }
    if let Some(n) = seen {
        if usize::try_from(n).map_or(true, |n| n > cap) {
            return Err(HttpError::BodyTooLarge { cap });
        }
    }
    Ok(seen)
}

/// `Retry-After` in delta-seconds form (an HTTP date is ignored), at most `ceiling`.
pub fn retry_after(headers: &HeaderMap, ceiling: Duration) -> Option<Duration> {
    let s = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs: u64 = s.parse().ok()?;
    Some(Duration::from_secs(secs).min(ceiling))
}

/// The redirect target of a `3xx`, if it stays on `base`'s origin. Relative references
/// (`/path`) resolve against the base; anything else → [`HttpError::Redirect`]-worthy `None`.
pub(crate) fn same_origin_location(base: &Base, headers: &HeaderMap) -> Option<http::Uri> {
    let raw = headers.get(LOCATION)?.to_str().ok()?;
    if raw.len() > MAX_PATH {
        return None;
    }
    if raw.starts_with('/') && !raw.starts_with("//") {
        check_path(raw).ok()?;
        return http::Uri::builder()
            .scheme(base.scheme())
            .authority(base.authority.clone())
            .path_and_query(raw)
            .build()
            .ok();
    }
    let uri: http::Uri = raw.parse().ok()?;
    if !base.same_origin(&uri) || uri.authority()?.as_str().contains('@') {
        return None;
    }
    let pq = uri.path_and_query().map_or("/", |p| p.as_str());
    check_path(pq).ok()?;
    Some(uri)
}

/// Decode a capped body as JSON. The error names the position only (no content).
pub fn decode_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, HttpError> {
    serde_json::from_slice(body)
        .map_err(|e| HttpError::Decode { line: e.line(), column: e.column() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use proptest::prelude::*;

    fn base() -> Base {
        Base::parse("https://api.example.test:6443/prefix/").expect("base")
    }

    fn map(name: http::HeaderName, v: &[u8]) -> Option<HeaderMap> {
        let mut h = HeaderMap::new();
        h.append(name, HeaderValue::from_bytes(v).ok()?);
        Some(h)
    }

    #[test]
    fn paths() {
        assert!(check_path("/api/v1/namespaces?limit=500").is_ok());
        for bad in ["", "api", "//evil.example.test/x", "/a b", "/a#f", "/a\u{7f}", "/é"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        let b = base();
        assert_eq!(b.prefix, "/prefix");
        assert_eq!(
            b.uri("/x?y=1").expect("uri").to_string(),
            "https://api.example.test:6443/prefix/x?y=1"
        );
    }

    #[test]
    fn content_length_rules() {
        let cap = 100;
        assert_eq!(content_length(&HeaderMap::new(), cap).expect("none"), None);
        let ok = map(CONTENT_LENGTH, b"100").expect("h");
        assert_eq!(content_length(&ok, cap).expect("ok"), Some(100));
        let over = map(CONTENT_LENGTH, b"101").expect("h");
        assert!(matches!(content_length(&over, cap), Err(HttpError::BodyTooLarge { cap: 100 })));
        let huge = map(CONTENT_LENGTH, b"99999999999999999999").expect("h");
        assert!(content_length(&huge, cap).is_err());
        for bad in [&b"-1"[..], b"+5", b"1,1", b" 5", b"0x10"] {
            assert!(content_length(&map(CONTENT_LENGTH, bad).expect("h"), cap).is_err());
        }
        let mut two = ok.clone();
        two.append(CONTENT_LENGTH, HeaderValue::from_static("5"));
        assert!(content_length(&two, cap).is_err(), "conflicting lengths");
    }

    #[test]
    fn retry_after_rules() {
        let ceil = Duration::from_secs(2);
        let h = map(RETRY_AFTER, b"1").expect("h");
        assert_eq!(retry_after(&h, ceil), Some(Duration::from_secs(1)));
        let h = map(RETRY_AFTER, b"3600").expect("h");
        assert_eq!(retry_after(&h, ceil), Some(ceil));
        let h = map(RETRY_AFTER, b"Wed, 21 Oct 2015 07:28:00 GMT").expect("h");
        assert_eq!(retry_after(&h, ceil), None);
    }

    #[test]
    fn location_rules() {
        let b = base();
        let rel = map(LOCATION, b"/other").expect("h");
        assert_eq!(
            same_origin_location(&b, &rel).expect("rel").to_string(),
            "https://api.example.test:6443/other"
        );
        let abs = map(LOCATION, b"https://API.example.test:6443/x").expect("h");
        assert!(same_origin_location(&b, &abs).is_some());
        for bad in [
            &b"https://evil.example.test:6443/x"[..],
            b"http://api.example.test:6443/x",
            b"https://api.example.test/x",
            b"//evil.example.test/x",
            b"https://user@api.example.test:6443/x",
            b"javascript:alert(1)",
        ] {
            assert!(same_origin_location(&b, &map(LOCATION, bad).expect("h")).is_none());
        }
    }

    proptest! {
        #[test]
        fn hostile_headers_never_panic(v in proptest::collection::vec(any::<u8>(), 0..64)) {
            let b = base();
            if let Some(h) = map(CONTENT_LENGTH, &v) {
                let _ = content_length(&h, 1024);
            }
            if let Some(h) = map(RETRY_AFTER, &v) {
                prop_assert!(retry_after(&h, Duration::from_secs(2)).is_none_or(|d| d <= Duration::from_secs(2)));
            }
            if let Some(h) = map(LOCATION, &v) {
                if let Some(u) = same_origin_location(&b, &h) {
                    prop_assert!(b.same_origin(&u));
                }
            }
        }

        #[test]
        fn hostile_json_never_panics(v in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode_json::<serde_json::Value>(&v);
        }
    }
}
