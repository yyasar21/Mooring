//! Routes of the S3 mock.

use std::fmt::Write as _;
use std::sync::Arc;

use http::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use http::{Method, Response, StatusCode};

use super::sigv4::{self, Signed};
use super::{Dynamic, ObjectVersion, S3State};
use crate::http::{
    bytes, empty, pct_decode, random_hex, time, Body, Ctx, Handler, HandlerFuture, HttpKnobs, Reply,
};

impl Handler for S3State {
    fn http_knobs(&self) -> HttpKnobs {
        self.lock().config.http.clone()
    }

    fn handle(self: Arc<Self>, ctx: Ctx) -> HandlerFuture {
        Box::pin(async move { route(&mut self.lock(), &ctx) })
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn s3_error(code: StatusCode, kind: &str, msg: &str, resource: &str) -> Reply {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{kind}</Code><Message>{}</Message>\
         <Resource>{}</Resource><RequestId>{}</RequestId></Error>",
        xml_escape(msg),
        xml_escape(resource),
        random_hex(8)
    );
    bytes(code, "application/xml", body).into()
}

fn with_object_headers(mut r: Response<Body>, v: &ObjectVersion) -> Response<Body> {
    let h = r.headers_mut();
    if let Ok(e) = HeaderValue::from_str(&v.etag) {
        h.insert(ETAG, e);
    }
    if let Ok(m) = HeaderValue::from_str(&time::http_date(v.modified)) {
        h.insert(LAST_MODIFIED, m);
    }
    r
}

/// `(bucket, key)` from virtual-host or path-style addressing.
fn address(d: &Dynamic, ctx: &Ctx) -> (String, String) {
    let bucket = &d.config.bucket;
    let host = ctx.header("host").unwrap_or("");
    let path = pct_decode(ctx.path.trim_start_matches('/'), false);
    if host.starts_with(&format!("{bucket}.")) {
        return (bucket.clone(), path);
    }
    let (b, k) = path.split_once('/').unwrap_or((path.as_str(), ""));
    (b.to_owned(), k.to_owned())
}

fn route(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let (bucket, key) = address(d, ctx);
    let m = ctx.method.clone();
    let query = ctx.query();
    let has = |k: &str| query.iter().any(|(qk, _)| qk == k);
    let auth_only = |k: &str| k.starts_with("X-Amz-");
    let sub = query.iter().map(|(k, _)| k.as_str()).find(|k| !auth_only(k) && *k != "versionId");
    let allowed = match (&m, key.is_empty()) {
        (&Method::GET, true) => {
            has("list-type")
                && query.iter().all(|(k, _)| {
                    auth_only(k)
                        || [
                            "list-type",
                            "prefix",
                            "delimiter",
                            "max-keys",
                            "continuation-token",
                            "start-after",
                            "encoding-type",
                        ]
                        .contains(&k.as_str())
                })
        }
        (&Method::HEAD, true) | (&Method::GET | &Method::HEAD | &Method::DELETE, false) => {
            sub.is_none()
        }
        (&Method::PUT, false) => sub.is_none() && ctx.header("x-amz-copy-source").is_none(),
        _ => false,
    };
    if !allowed {
        return Reply::violation(format!(
            "{m} {}{} is not an allow-listed S3 call",
            ctx.path,
            ctx.raw_query.as_deref().map(|q| format!("?{q}")).unwrap_or_default()
        ));
    }
    let header = |n: &str| ctx.header(n).map(str::to_owned);
    let req = Signed {
        method: m.as_str(),
        raw_path: &ctx.path,
        raw_query: ctx.raw_query.as_deref().unwrap_or(""),
        header: &header,
        body: &ctx.body,
    };
    if let Err(e) = sigv4::verify(&req, &d.config.credentials, time::now_unix()) {
        let code =
            if matches!(e, sigv4::AuthError::Malformed(_) | sigv4::AuthError::PayloadMismatch) {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FORBIDDEN
            };
        let msg = match e {
            sigv4::AuthError::Expired => "Request has expired".to_owned(),
            sigv4::AuthError::Malformed(what) => format!("malformed authorization: {what}"),
            other => format!("{other:?}"),
        };
        return s3_error(code, e.code(), &msg, &ctx.path);
    }
    if bucket != d.config.bucket {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }
    match (&m, key.is_empty()) {
        (&Method::HEAD, true) => empty(StatusCode::OK).into(),
        (&Method::GET, true) => list(d, ctx),
        (&Method::PUT, false) => put(d, ctx, &key),
        (&Method::DELETE, false) => {
            d.objects.remove(&key);
            empty(StatusCode::NO_CONTENT).into()
        }
        _ => get(d, ctx, &key, m == Method::HEAD),
    }
}

fn put(d: &mut Dynamic, ctx: &Ctx, key: &str) -> Reply {
    if ctx.body.len() > d.config.max_object_size {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "EntityTooLarge",
            "Your proposed upload exceeds the maximum allowed size",
            key,
        );
    }
    let current = d.objects.get(key).and_then(|v| v.last()).map(|v| v.etag.clone());
    if d.config.conditional_writes {
        if ctx.header("if-none-match").map(str::trim) == Some("*") && current.is_some() {
            return s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                key,
            );
        }
        if let Some(want) = ctx.header("if-match").map(str::trim) {
            match &current {
                None => {
                    return s3_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchKey",
                        "The specified key does not exist.",
                        key,
                    )
                }
                Some(etag) if want != "*" && want != etag => {
                    return s3_error(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "At least one of the pre-conditions you specified did not hold",
                        key,
                    );
                }
                Some(_) => {}
            }
        }
    }
    let v = ObjectVersion::new(ctx.body.clone());
    let r = with_object_headers(empty(StatusCode::OK), &v);
    d.objects.entry(key.to_owned()).or_default().push(v);
    r.into()
}

fn get(d: &Dynamic, ctx: &Ctx, key: &str, head: bool) -> Reply {
    let Some(v) = d.served(key) else {
        if head {
            return empty(StatusCode::NOT_FOUND).into();
        }
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist.",
            key,
        );
    };
    if ctx.header("if-none-match").map(str::trim) == Some(v.etag.as_str()) {
        return with_object_headers(empty(StatusCode::NOT_MODIFIED), &v).into();
    }
    if head {
        let mut r = with_object_headers(empty(StatusCode::OK), &v);
        if let Ok(len) = HeaderValue::from_str(&v.data.len().to_string()) {
            r.headers_mut().insert(CONTENT_LENGTH, len);
        }
        return r.into();
    }
    let mut r =
        with_object_headers(bytes(StatusCode::OK, "application/octet-stream", v.data.clone()), &v);
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    r.into()
}

fn list(d: &Dynamic, ctx: &Ctx) -> Reply {
    let q = |k: &str| ctx.query_get(k).unwrap_or_default();
    let (prefix, delim) = (q("prefix"), q("delimiter"));
    let max =
        ctx.query_get("max-keys").and_then(|m| m.parse::<usize>().ok()).unwrap_or(1000).min(1000);
    let token = q("continuation-token");
    let after = token.strip_prefix("ct-").map_or_else(|| q("start-after"), str::to_owned);
    let (mut contents, mut prefixes, mut last, mut truncated) =
        (String::new(), Vec::<String>::new(), None, false);
    let mut count = 0;
    for key in d.objects.keys().filter(|k| k.starts_with(&prefix) && **k > after) {
        if count == max {
            truncated = true;
            break;
        }
        let rest = &key[prefix.len()..];
        if let Some(i) = (!delim.is_empty()).then(|| rest.find(&delim)).flatten() {
            let p = format!("{prefix}{}", &rest[..i + delim.len()]);
            if prefixes.last() != Some(&p) {
                prefixes.push(p);
                count += 1;
            }
            last = Some(key.clone());
            continue;
        }
        let Some(v) = d.served(key) else { continue };
        let _ = write!(
            contents,
            "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size>\
             <StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(key),
            time::rfc3339_millis(v.modified),
            xml_escape(&v.etag),
            v.data.len()
        );
        last = Some(key.clone());
        count += 1;
    }
    let cps = prefixes.iter().fold(String::new(), |mut s, p| {
        let _ = write!(s, "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", xml_escape(p));
        s
    });
    let next = match (truncated, last) {
        (true, Some(k)) => {
            format!("<NextContinuationToken>ct-{}</NextContinuationToken>", xml_escape(&k))
        }
        _ => String::new(),
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Name>{}</Name><Prefix>{}</Prefix><KeyCount>{count}</KeyCount><MaxKeys>{max}</MaxKeys>\
         <IsTruncated>{truncated}</IsTruncated>{contents}{cps}{next}</ListBucketResult>",
        xml_escape(&d.config.bucket),
        xml_escape(&prefix)
    );
    bytes(StatusCode::OK, "application/xml", body).into()
}
