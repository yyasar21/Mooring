//! Pure, panic-free entry points for QA's cargo-fuzz targets (ADR-0014 §Test plan). Each takes
//! arbitrary bytes and must never panic, hang or allocate beyond the input bounds.
//!
//! | target | entry |
//! | --- | --- |
//! | `http_certificate_info` (hostile leaf DER) | [`fuzz_certificate_info`] |
//! | `http_response_headers` (`Content-Length`, `Retry-After`, `Location`) | [`fuzz_response_headers`] |
//! | `http_json_body` (capped body → `serde_json::Value`) | [`fuzz_json_body`] |
//! | `known_certs_parse` lives in `mooring-core` | — |

use std::time::Duration;

use http::header::{CONTENT_LENGTH, LOCATION, RETRY_AFTER};
use http::{HeaderMap, HeaderValue};
use mooring_core::known_certs::CertProblem;
use time::OffsetDateTime;

use crate::config::Base;
use crate::parse;

/// Leaf DER → `CertificateInfo`.
pub fn fuzz_certificate_info(data: &[u8]) {
    let _ = crate::cert::certificate_info(
        data,
        vec![CertProblem::UnknownIssuer],
        OffsetDateTime::UNIX_EPOCH,
    );
}

/// The first byte selects the header, the rest is its value.
pub fn fuzz_response_headers(data: &[u8]) {
    let Some((sel, value)) = data.split_first() else { return };
    let Ok(v) = HeaderValue::from_bytes(value) else { return };
    let name = match sel % 3 {
        0 => CONTENT_LENGTH,
        1 => RETRY_AFTER,
        _ => LOCATION,
    };
    let mut h = HeaderMap::new();
    h.append(name, v);
    let _ = parse::content_length(&h, 8 * 1024 * 1024);
    let _ = parse::retry_after(&h, Duration::from_secs(2));
    if let Ok(base) = Base::parse("https://api.example.test:6443/p") {
        if let Some(u) = parse::same_origin_location(&base, &h) {
            assert!(base.same_origin(&u), "redirect left the origin");
        }
    }
}

/// A body (already within the cap) → JSON value.
pub fn fuzz_json_body(data: &[u8]) {
    if data.len() <= 1024 * 1024 {
        let _ = parse::decode_json::<serde_json::Value>(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn entries_never_panic(v in proptest::collection::vec(any::<u8>(), 0..1024)) {
            fuzz_certificate_info(&v);
            fuzz_response_headers(&v);
            fuzz_json_body(&v);
        }
    }
}
