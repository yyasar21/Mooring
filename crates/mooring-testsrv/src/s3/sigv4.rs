//! AWS Signature Version 4 for the S3 mock: verification of header-signed and presigned
//! (query-string) requests, and the matching signers for tests and manual runs. HMAC-SHA256 /
//! SHA-256 from RustCrypto; checked against the AWS S3 documentation examples (unit tests).

use std::fmt::Write as _;

use hmac::{Hmac, KeyInit, Mac as _};
use sha2::{Digest as _, Sha256};

use crate::http::{hex, pct_decode, pct_encode, time};

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const UNSIGNED: &str = "UNSIGNED-PAYLOAD";
/// Allowed clock skew for header-signed requests (S3: 15 minutes).
pub const MAX_SKEW: i64 = 15 * 60;

/// The access key the mock accepts.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub region: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key", &self.access_key)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

/// Why a request was refused (each maps to an S3 error code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` header and no `X-Amz-Signature` query (`AccessDenied`).
    Missing,
    /// `AuthorizationHeaderMalformed` / `AuthorizationQueryParametersError`.
    Malformed(&'static str),
    /// `InvalidAccessKeyId`.
    UnknownKey,
    /// `SignatureDoesNotMatch`.
    BadSignature,
    /// Presigned URL past `X-Amz-Expires` (`AccessDenied`, "Request has expired").
    Expired,
    /// `RequestTimeTooSkewed`.
    Skewed,
    /// `XAmzContentSHA256Mismatch`.
    PayloadMismatch,
    /// Session token missing or wrong (`InvalidToken`).
    Token,
}

impl AuthError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing | Self::Expired => "AccessDenied",
            Self::Malformed(_) => "AuthorizationHeaderMalformed",
            Self::UnknownKey => "InvalidAccessKeyId",
            Self::BadSignature => "SignatureDoesNotMatch",
            Self::Skewed => "RequestTimeTooSkewed",
            Self::PayloadMismatch => "XAmzContentSHA256Mismatch",
            Self::Token => "InvalidToken",
        }
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length, so this never fails; an empty MAC would only make the
    // signature comparison fail.
    let Ok(mut m) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else { return Vec::new() };
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// `kSigning = HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), "s3"), "aws4_request")`.
pub fn signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, b"s3");
    hmac(&k, b"aws4_request")
}

/// URI-encoded path, `/` kept; the incoming path is decoded first so both encodings compare.
pub fn canonical_uri(raw_path: &str) -> String {
    pct_encode(&pct_decode(raw_path, false), true)
}

/// Sorted, encoded query (`X-Amz-Signature` left out).
pub fn canonical_query(raw_query: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct_encode(&pct_decode(k, false), false), pct_encode(&pct_decode(v, false), false))
        })
        .filter(|(k, _)| k != "X-Amz-Signature")
        .collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// The canonical request; `headers` are `(lowercase name, value)` of the signed headers.
pub fn canonical_request(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> String {
    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.split_whitespace().collect::<Vec<_>>().join(" ")))
        .collect();
    h.sort();
    let canon = h.iter().fold(String::new(), |mut s, (k, v)| {
        let _ = writeln!(s, "{k}:{v}");
        s
    });
    let signed = h.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    format!(
        "{method}\n{}\n{}\n{canon}\n{signed}\n{payload_hash}",
        canonical_uri(raw_path),
        canonical_query(raw_query)
    )
}

/// Hex signature of a canonical request at `amz_date` (`YYYYMMDDTHHMMSSZ`).
pub fn signature(secret: &str, region: &str, amz_date: &str, canonical: &str) -> String {
    let date = amz_date.get(..8).unwrap_or("");
    let scope = format!("{date}/{region}/s3/aws4_request");
    let sts = format!("{ALGORITHM}\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    hex(&hmac(&signing_key(secret, date, region), sts.as_bytes()))
}

/// A request as the verifier needs it.
#[derive(Clone, Copy)]
pub struct Signed<'a> {
    pub method: &'a str,
    pub raw_path: &'a str,
    pub raw_query: &'a str,
    /// Header lookup by lowercase name.
    pub header: &'a dyn Fn(&str) -> Option<String>,
    pub body: &'a [u8],
}

impl std::fmt::Debug for Signed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
            .field("method", &self.method)
            .field("raw_path", &self.raw_path)
            .finish_non_exhaustive()
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verifies a header-signed or presigned request against `creds` at time `now`.
pub fn verify(req: &Signed<'_>, creds: &Credentials, now: i64) -> Result<(), AuthError> {
    let query: Vec<(String, String)> = crate::http::parse_query(req.raw_query);
    let q = |k: &str| query.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.clone());
    let (credential, signed_headers, sig, amz_date, payload, token);
    if let Some(auth) = (req.header)("authorization") {
        let rest = auth.strip_prefix(ALGORITHM).ok_or(AuthError::Malformed("algorithm"))?;
        let field = |name: &str| {
            rest.split(',').map(str::trim).find_map(|p| p.strip_prefix(name)).map(str::to_owned)
        };
        credential = field("Credential=").ok_or(AuthError::Malformed("Credential"))?;
        signed_headers = field("SignedHeaders=").ok_or(AuthError::Malformed("SignedHeaders"))?;
        sig = field("Signature=").ok_or(AuthError::Malformed("Signature"))?;
        amz_date = (req.header)("x-amz-date").ok_or(AuthError::Malformed("x-amz-date"))?;
        payload = (req.header)("x-amz-content-sha256")
            .ok_or(AuthError::Malformed("x-amz-content-sha256"))?;
        token = (req.header)("x-amz-security-token");
        let t = time::parse_amz_date(&amz_date).ok_or(AuthError::Malformed("x-amz-date"))?;
        if (now - t).abs() > MAX_SKEW {
            return Err(AuthError::Skewed);
        }
        if payload != UNSIGNED
            && !payload.starts_with("STREAMING-")
            && !ct_eq(&payload, &sha256_hex(req.body))
        {
            return Err(AuthError::PayloadMismatch);
        }
    } else if let Some(s) = q("X-Amz-Signature") {
        if q("X-Amz-Algorithm").as_deref() != Some(ALGORITHM) {
            return Err(AuthError::Malformed("X-Amz-Algorithm"));
        }
        sig = s;
        credential = q("X-Amz-Credential").ok_or(AuthError::Malformed("X-Amz-Credential"))?;
        signed_headers =
            q("X-Amz-SignedHeaders").ok_or(AuthError::Malformed("X-Amz-SignedHeaders"))?;
        amz_date = q("X-Amz-Date").ok_or(AuthError::Malformed("X-Amz-Date"))?;
        let expires = q("X-Amz-Expires")
            .and_then(|e| e.parse::<i64>().ok())
            .filter(|e| (1..=604_800).contains(e));
        let expires = expires.ok_or(AuthError::Malformed("X-Amz-Expires"))?;
        let t = time::parse_amz_date(&amz_date).ok_or(AuthError::Malformed("X-Amz-Date"))?;
        if now > t + expires {
            return Err(AuthError::Expired);
        }
        if t > now + MAX_SKEW {
            return Err(AuthError::Skewed);
        }
        payload = UNSIGNED.to_owned();
        token = q("X-Amz-Security-Token");
    } else {
        return Err(AuthError::Missing);
    }
    let parts: Vec<&str> = credential.split('/').collect();
    let [key, date, region, service, term] = parts.as_slice() else {
        return Err(AuthError::Malformed("credential scope"));
    };
    if *key != creds.access_key {
        return Err(AuthError::UnknownKey);
    }
    if *region != creds.region
        || *service != "s3"
        || *term != "aws4_request"
        || !amz_date.starts_with(date)
    {
        return Err(AuthError::Malformed("credential scope"));
    }
    if creds.session_token.is_some() && token != creds.session_token {
        return Err(AuthError::Token);
    }
    let names: Vec<&str> = signed_headers.split(';').collect();
    if !names.contains(&"host") {
        return Err(AuthError::Malformed("host must be signed"));
    }
    let mut headers = Vec::with_capacity(names.len());
    for n in names {
        headers.push((n.to_owned(), (req.header)(n).ok_or(AuthError::BadSignature)?));
    }
    let canonical = canonical_request(req.method, req.raw_path, req.raw_query, &headers, &payload);
    if ct_eq(&signature(&creds.secret_key, &creds.region, &amz_date, &canonical), &sig) {
        Ok(())
    } else {
        Err(AuthError::BadSignature)
    }
}

/// Header-signs a request (the parameters mirror the parts SigV4 covers): returns `x-amz-date`, `x-amz-content-sha256` (and the session token)
/// plus `authorization`, to add next to `host` and `extra` (which are signed too).
#[allow(clippy::too_many_arguments)]
pub fn sign_headers(
    creds: &Credentials,
    method: &str,
    host: &str,
    raw_path: &str,
    raw_query: &str,
    extra: &[(String, String)],
    body: &[u8],
    now: i64,
) -> Vec<(String, String)> {
    let amz = time::amz_date(now);
    let payload = sha256_hex(body);
    let mut out = vec![
        ("x-amz-date".to_owned(), amz.clone()),
        ("x-amz-content-sha256".to_owned(), payload.clone()),
    ];
    if let Some(t) = &creds.session_token {
        out.push(("x-amz-security-token".to_owned(), t.clone()));
    }
    let mut signed: Vec<(String, String)> = vec![("host".to_owned(), host.to_owned())];
    signed.extend(extra.iter().cloned());
    signed.extend(out.iter().cloned());
    let canonical = canonical_request(method, raw_path, raw_query, &signed, &payload);
    let mut names: Vec<String> = signed.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    names.sort();
    let auth = format!(
        "{ALGORITHM} Credential={}/{}/{}/s3/aws4_request, SignedHeaders={}, Signature={}",
        creds.access_key,
        &amz[..8],
        creds.region,
        names.join(";"),
        signature(&creds.secret_key, &creds.region, &amz, &canonical)
    );
    out.push(("authorization".to_owned(), auth));
    out
}

/// A presigned path + query (signed header: `host` only, `UNSIGNED-PAYLOAD`), as rusty-s3 makes.
pub fn presign(
    creds: &Credentials,
    method: &str,
    host: &str,
    raw_path: &str,
    raw_query: &str,
    expires: u32,
    now: i64,
) -> String {
    let amz = time::amz_date(now);
    let cred = format!("{}/{}/{}/s3/aws4_request", creds.access_key, &amz[..8], creds.region);
    let mut q = format!(
        "X-Amz-Algorithm={ALGORITHM}&X-Amz-Credential={}&X-Amz-Date={amz}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host",
        pct_encode(&cred, false)
    );
    if let Some(t) = &creds.session_token {
        let _ = write!(q, "&X-Amz-Security-Token={}", pct_encode(t, false));
    }
    if !raw_query.is_empty() {
        q = format!("{raw_query}&{q}");
    }
    let canonical =
        canonical_request(method, raw_path, &q, &[("host".to_owned(), host.to_owned())], UNSIGNED);
    let sig = signature(&creds.secret_key, &creds.region, &amz, &canonical);
    format!("{raw_path}?{q}&X-Amz-Signature={sig}")
}

#[cfg(test)]
mod tests {
    use super::{canonical_request, signature, Credentials};

    // Split so secret scanners do not match the public AWS documentation example key.
    const SECRET: &str = concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY");
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// AWS S3 docs, "Example: GET Object" (header-based authentication).
    #[test]
    fn aws_get_object_example() {
        let h = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        let headers = [
            h("host", "examplebucket.s3.amazonaws.com"),
            h("range", "bytes=0-9"),
            h("x-amz-content-sha256", EMPTY),
            h("x-amz-date", "20130524T000000Z"),
        ];
        let c = canonical_request("GET", "/test.txt", "", &headers, EMPTY);
        assert_eq!(
            signature(SECRET, "us-east-1", "20130524T000000Z", &c),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// AWS S3 docs, "Authenticating Requests: Using Query Parameters" example.
    #[test]
    fn aws_presigned_example() {
        let creds = Credentials {
            access_key: concat!("AKIA", "IOSFODNN7EXAMPLE").to_owned(),
            secret_key: SECRET.to_owned(),
            session_token: None,
            region: "us-east-1".to_owned(),
        };
        let t = crate::http::time::parse_amz_date("20130524T000000Z").expect("date");
        let url = super::presign(
            &creds,
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            "",
            86_400,
            t,
        );
        assert!(
            url.ends_with(
                "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "{url}"
        );
    }
}
