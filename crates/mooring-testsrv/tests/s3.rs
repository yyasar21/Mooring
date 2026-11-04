//! Self-tests of the S3 mock: `SigV4` (header and presigned), conditional writes, reads,
//! `ListObjectsV2`, rollback / fork knobs, size caps and the violation trap.

mod common;

use bytes::Bytes;
use common::http_client::{request, send, Resp};
use common::within;
use http::Method;
use mooring_testsrv::http::time::now_unix;
use mooring_testsrv::s3::{self, sigv4, S3Config, S3Knobs, S3Server};

async fn srv(config: S3Config) -> S3Server {
    s3::start(config, 0).await.expect("start")
}

/// Header-signed request (host `localhost`; `extra` headers are signed too).
async fn call(
    s: &S3Server,
    m: Method,
    path: &str,
    query: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Resp {
    call_as(s, &s.credentials(), m, path, query, extra, body, now_unix()).await
}

#[allow(clippy::too_many_arguments)]
async fn call_as(
    s: &S3Server,
    creds: &sigv4::Credentials,
    m: Method,
    path: &str,
    query: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    now: i64,
) -> Resp {
    let owned: Vec<(String, String)> =
        extra.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
    let signed =
        sigv4::sign_headers(creds, m.as_str(), "localhost", path, query, &owned, body, now);
    let mut h: Vec<(&str, &str)> = extra.to_vec();
    h.extend(signed.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let uri = if query.is_empty() { path.to_owned() } else { format!("{path}?{query}") };
    send(s.addr(), request(m, &uri, &h, Bytes::copy_from_slice(body)), None).await
}

fn code(r: &Resp) -> String {
    let t = r.text();
    t.split("<Code>").nth(1).and_then(|x| x.split("</Code>").next()).unwrap_or("").to_owned()
}

#[tokio::test]
async fn conditional_put_get_head_delete() {
    let s = srv(S3Config::default()).await;
    let key = "/mooring-sync/prefix/vault-1/current";
    within(async {
        let first = call(&s, Method::PUT, key, "", &[("if-none-match", "*")], b"blob-1").await;
        assert_eq!(first.status, 200);
        let etag = first.header("etag").expect("etag");
        let again = call(&s, Method::PUT, key, "", &[("if-none-match", "*")], b"blob-x").await;
        assert_eq!((again.status, code(&again)), (412, "PreconditionFailed".to_owned()));
        let get = call(&s, Method::GET, key, "", &[], b"").await;
        assert_eq!((get.body.as_slice(), get.header("etag")), (&b"blob-1"[..], Some(etag.clone())));
        let head = call(&s, Method::HEAD, key, "", &[], b"").await;
        assert_eq!(head.header("content-length").as_deref(), Some("6"));
        assert_eq!(
            call(&s, Method::GET, key, "", &[("if-none-match", &etag)], b"").await.status,
            304
        );
        let next = call(&s, Method::PUT, key, "", &[("if-match", &etag)], b"blob-2").await;
        assert_eq!(next.status, 200);
        let stale = call(&s, Method::PUT, key, "", &[("if-match", &etag)], b"blob-3").await;
        assert_eq!(stale.status, 412, "lost update refused");
        let missing =
            call(&s, Method::PUT, "/mooring-sync/none", "", &[("if-match", &etag)], b"x").await;
        assert_eq!((missing.status, code(&missing)), (404, "NoSuchKey".to_owned()));
        assert_eq!(call(&s, Method::DELETE, key, "", &[], b"").await.status, 204);
        assert_eq!(call(&s, Method::HEAD, key, "", &[], b"").await.status, 404);
        assert_eq!(call(&s, Method::HEAD, "/mooring-sync", "", &[], b"").await.status, 200);
        assert_eq!(
            code(&call(&s, Method::GET, "/other-bucket/k", "", &[], b"").await),
            "NoSuchBucket"
        );
    })
    .await;
    assert_eq!(s.versions("prefix/vault-1/current").len(), 0);
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn sigv4_refusals() {
    let s = srv(S3Config { objects: vec![("k".to_owned(), b"v".to_vec())], ..S3Config::default() })
        .await;
    within(async {
        let creds = s.credentials();
        let now = now_unix();
        let wrong = sigv4::Credentials { secret_key: "nope".to_owned(), ..creds.clone() };
        let r = call_as(&s, &wrong, Method::GET, "/mooring-sync/k", "", &[], b"", now).await;
        assert_eq!((r.status, code(&r)), (403, "SignatureDoesNotMatch".to_owned()));
        let unknown = sigv4::Credentials { access_key: "AKIDUNKNOWN".to_owned(), ..creds.clone() };
        assert_eq!(
            code(&call_as(&s, &unknown, Method::GET, "/mooring-sync/k", "", &[], b"", now).await),
            "InvalidAccessKeyId"
        );
        let skew =
            call_as(&s, &creds, Method::GET, "/mooring-sync/k", "", &[], b"", now - 3600).await;
        assert_eq!(code(&skew), "RequestTimeTooSkewed");
        let anon =
            send(s.addr(), request(Method::GET, "/mooring-sync/k", &[], Bytes::new()), None).await;
        assert_eq!((anon.status, code(&anon)), (403, "AccessDenied".to_owned()));
        // Signed for one body, sent with another.
        let mut signed = sigv4::sign_headers(
            &creds,
            "PUT",
            "localhost",
            "/mooring-sync/k",
            "",
            &[],
            b"aaa",
            now,
        );
        signed.push(("x".to_owned(), "y".to_owned()));
        let h: Vec<(&str, &str)> = signed.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let r = send(
            s.addr(),
            request(Method::PUT, "/mooring-sync/k", &h, Bytes::from_static(b"bbb")),
            None,
        )
        .await;
        assert_eq!((r.status, code(&r)), (400, "XAmzContentSHA256Mismatch".to_owned()));
        let tampered = call(&s, Method::GET, "/mooring-sync/k", "", &[], b"").await;
        assert_eq!(tampered.status, 200, "control: a correct signature passes");
    })
    .await;
    assert_eq!(s.object("k").as_deref(), Some(&b"v"[..]));
}

#[tokio::test]
async fn presigned_urls_like_rusty_s3() {
    let s = srv(S3Config::default()).await;
    within(async {
        let creds = s.credentials();
        let put = sigv4::presign(
            &creds,
            "PUT",
            "localhost",
            "/mooring-sync/p/k%20one",
            "",
            60,
            now_unix(),
        );
        let r = send(
            s.addr(),
            request(Method::PUT, &put, &[("if-none-match", "*")], Bytes::from_static(b"hi")),
            None,
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let get = sigv4::presign(
            &creds,
            "GET",
            "localhost",
            "/mooring-sync/p/k%20one",
            "",
            60,
            now_unix(),
        );
        assert_eq!(
            send(s.addr(), request(Method::GET, &get, &[], Bytes::new()), None).await.body,
            b"hi"
        );
        let old = sigv4::presign(
            &creds,
            "GET",
            "localhost",
            "/mooring-sync/p/k%20one",
            "",
            60,
            now_unix() - 120,
        );
        let r = send(s.addr(), request(Method::GET, &old, &[], Bytes::new()), None).await;
        assert_eq!((r.status, code(&r)), (403, "AccessDenied".to_owned()));
        assert!(r.text().contains("Request has expired"));
        let list = sigv4::presign(
            &creds,
            "GET",
            "localhost",
            "/mooring-sync",
            "list-type=2&prefix=p%2F",
            60,
            now_unix(),
        );
        assert!(send(s.addr(), request(Method::GET, &list, &[], Bytes::new()), None)
            .await
            .text()
            .contains("<Key>p/k one</Key>"));
    })
    .await;
    assert_eq!(s.keys(), ["p/k one"]);
    let rec = s.recorder().requests();
    assert!(rec.iter().all(|r| r
        .query_get("X-Amz-Signature")
        .is_none_or(|v| v == mooring_testsrv::http::REDACTED)));
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn list_objects_v2_prefix_delimiter_and_pages() {
    let objects = (0..5)
        .map(|i| (format!("v/history/{i}"), vec![b'x'; i]))
        .chain([("v/current".to_owned(), b"c".to_vec()), ("v/header".to_owned(), b"h".to_vec())])
        .collect();
    let s = srv(S3Config { objects, ..S3Config::default() }).await;
    within(async {
        let r = call(
            &s,
            Method::GET,
            "/mooring-sync",
            "list-type=2&prefix=v%2F&delimiter=%2F",
            &[],
            b"",
        )
        .await
        .text();
        assert!(r.contains("<Key>v/current</Key>") && r.contains("<Key>v/header</Key>"));
        assert!(r.contains("<CommonPrefixes><Prefix>v/history/</Prefix></CommonPrefixes>"));
        assert!(!r.contains("<Key>v/history/0</Key>"));
        let p1 = call(
            &s,
            Method::GET,
            "/mooring-sync",
            "list-type=2&prefix=v%2Fhistory%2F&max-keys=2",
            &[],
            b"",
        )
        .await
        .text();
        assert!(
            p1.contains("<IsTruncated>true</IsTruncated>") && p1.contains("<KeyCount>2</KeyCount>")
        );
        let token = p1
            .split("<NextContinuationToken>")
            .nth(1)
            .and_then(|t| t.split('<').next())
            .expect("token");
        let q = format!(
            "list-type=2&prefix=v%2Fhistory%2F&max-keys=10&continuation-token={}",
            mooring_testsrv::http::pct_encode(token, false)
        );
        let p2 = call(&s, Method::GET, "/mooring-sync", &q, &[], b"").await.text();
        assert!(
            p2.contains("<KeyCount>3</KeyCount>")
                && p2.contains("<IsTruncated>false</IsTruncated>")
        );
        assert!(
            p2.contains("<Key>v/history/4</Key><LastModified>") && p2.contains("<Size>4</Size>")
        );
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn rollback_fork_no_conditionals_and_caps() {
    let s = srv(S3Config { max_object_size: 1024, ..S3Config::default() }).await;
    let key = "/mooring-sync/cur";
    within(async {
        let e1 = s.put_object("cur", b"gen-1");
        let e2 = s.put_object("cur", b"gen-2");
        s.set_knobs(S3Knobs { rollback: 1, ..S3Knobs::default() });
        let old = call(&s, Method::GET, key, "", &[], b"").await;
        assert_eq!((old.body.as_slice(), old.header("etag")), (&b"gen-1"[..], Some(e1)));
        s.set_knobs(S3Knobs { fork: true, ..S3Knobs::default() });
        let forked = call(&s, Method::HEAD, key, "", &[], b"").await.header("etag").expect("etag");
        assert_ne!(forked, e2);
        assert_eq!(
            call(&s, Method::PUT, key, "", &[("if-match", &forked)], b"gen-3").await.status,
            412
        );
        s.set_knobs(S3Knobs::default());
        s.set_conditional_writes(false);
        for _ in 0..2 {
            let probe =
                call(&s, Method::PUT, "/mooring-sync/probe", "", &[("if-none-match", "*")], b"p")
                    .await;
            assert_eq!(probe.status, 200, "backend without conditional writes accepts both");
        }
        let big = call(&s, Method::PUT, key, "", &[], &[0u8; 2048]).await;
        assert_eq!((big.status, code(&big)), (400, "EntityTooLarge".to_owned()));
    })
    .await;
    assert_eq!(s.versions("cur").len(), 2);
    assert_eq!(s.versions("probe").len(), 2);
}

#[tokio::test]
async fn virtual_host_session_token_and_violations() {
    let mut cfg = S3Config::default();
    cfg.credentials.session_token = Some("test-session-token".to_owned());
    let s = srv(cfg).await;
    within(async {
        let creds = s.credentials();
        let host = "mooring-sync.s3.example.test";
        let signed = sigv4::sign_headers(&creds, "PUT", host, "/vh", "", &[], b"v", now_unix());
        let mut h: Vec<(&str, &str)> =
            signed.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        h.push(("host", host));
        assert_eq!(
            send(s.addr(), request(Method::PUT, "/vh", &h, Bytes::from_static(b"v")), None)
                .await
                .status,
            200
        );
        let no_token = sigv4::Credentials { session_token: None, ..creds.clone() };
        let r =
            call_as(&s, &no_token, Method::GET, "/mooring-sync/vh", "", &[], b"", now_unix()).await;
        assert_eq!(code(&r), "InvalidToken");
        for (m, p, q, extra) in [
            (Method::POST, "/mooring-sync/k", "uploads", vec![]),
            (Method::PUT, "/mooring-sync/k", "acl", vec![]),
            (Method::PUT, "/mooring-sync/k", "", vec![("x-amz-copy-source", "/mooring-sync/vh")]),
            (Method::GET, "/mooring-sync", "", vec![]),
            (Method::DELETE, "/mooring-sync", "", vec![]),
            (Method::POST, "/mooring-sync", "delete", vec![]),
        ] {
            assert_eq!(call(&s, m.clone(), p, q, &extra, b"").await.status, 500, "{m} {p}?{q}");
        }
    })
    .await;
    assert_eq!(s.object("vh").as_deref(), Some(&b"v"[..]));
    assert_eq!(s.recorder().violations().len(), 6);
}
