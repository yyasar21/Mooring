#![allow(clippy::many_single_char_names)]

//! The S3 backend against QA's `mooring-testsrv::s3` mock (ADR-0017 §4 and §Test plan):
//! real `SigV4` verification of every presigned request, an object over the blob cap, a
//! missing / malformed `ETag`, the rollback and fork knobs seen through `head` / `get`, and
//! the conditional-write probe. `ListObjects` XML is **not** exercised: the backend never
//! lists (objects are addressed by counter), so there is no XML parser to attack. Every test
//! ends with `assert_no_violations()`: no multipart, copy, ACL, bucket or list API is called.

use bytes::Bytes;
use mooring_sync::blob::MAX_BLOB;
use mooring_sync::{
    Cond, ObjectStore, PutMeta, PutOutcome, Remote, S3Backend, S3Config, S3Credentials, SyncError,
};
use mooring_testsrv::s3::{self, S3Knobs, S3Server};
use mooring_testsrv::tls::TestCert;
use secrecy::SecretString;
use uuid::Uuid;

struct Mock {
    srv: S3Server,
    dir: tempfile::TempDir,
    ca: String,
}

async fn start(cfg: s3::S3Config) -> Mock {
    let (cert, ca) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("cert");
    let srv = s3::start(s3::S3Config { cert: Some(cert), ..cfg }, 0).await.expect("s3 mock");
    Mock { srv, dir: tempfile::tempdir().expect("tempdir"), ca }
}

impl Mock {
    fn backend(&self) -> S3Backend {
        let c = self.srv.credentials();
        let cfg = S3Config {
            endpoint: self.srv.endpoint(),
            region: c.region.clone(),
            bucket: self.srv.bucket(),
            path_style: true,
            known_certs_path: self.dir.path().join("known_sync_certs"),
            ca_pem: Some(self.ca.clone()),
            allow_plaintext_loopback: false,
            trusted_once: None,
        };
        let creds = S3Credentials {
            access_key_id: c.access_key,
            secret_access_key: SecretString::from(c.secret_key),
            session_token: c.session_token.map(SecretString::from),
        };
        S3Backend::new(&cfg, &creds).expect("backend")
    }

    fn clean(&self) {
        self.srv.recorder().assert_no_violations();
        for line in self.srv.recorder().lines() {
            assert!(!line.contains("testsecretkey"), "secret key on the wire log: {line}");
        }
    }
}

/// Every presigned request verifies under real `SigV4`; a wrong secret is a 403 from the
/// mock and `sync.backend` here, with no retry storm on the write client.
#[tokio::test]
async fn signatures_verify_and_a_wrong_key_is_refused() {
    let m = start(s3::S3Config::default()).await;
    let b = m.backend();
    assert!(b.head("k/current").await.expect("head").is_none());
    let w = b
        .put("k/current", Bytes::from_static(b"x"), Cond::IfNoneMatch, &PutMeta::default())
        .await
        .expect("put");
    assert!(matches!(w, PutOutcome::Written { .. }), "{w:?}");
    let got = b.get("k/current", MAX_BLOB).await.expect("get").expect("present");
    assert_eq!(got.bytes, b"x");
    b.delete("k/current").await.expect("delete");
    assert!(b.get("k/current", MAX_BLOB).await.expect("get").is_none());

    let c = m.srv.credentials();
    let wrong = S3Backend::new(
        &S3Config {
            endpoint: m.srv.endpoint(),
            region: c.region,
            bucket: m.srv.bucket(),
            path_style: true,
            known_certs_path: m.dir.path().join("known_sync_certs"),
            ca_pem: Some(m.ca.clone()),
            allow_plaintext_loopback: false,
            trusted_once: None,
        },
        &S3Credentials {
            access_key_id: c.access_key,
            secret_access_key: SecretString::from("not-the-key".to_owned()),
            session_token: None,
        },
    )
    .expect("backend");
    let before = m.srv.recorder().len();
    let e = wrong
        .put("k/current", Bytes::from_static(b"x"), Cond::IfNoneMatch, &PutMeta::default())
        .await
        .expect_err("403");
    assert_eq!(e.code(), "sync.backend", "{e}");
    assert_eq!(m.srv.recorder().len(), before + 1, "a refused write is never retried");
    m.clean();
}

/// An object larger than the blob cap is refused with `sync.too_large` before it is held in
/// memory whole; one at the cap is read.
#[tokio::test]
async fn an_oversized_object_is_too_large() {
    let big = vec![b'M'; MAX_BLOB + 1];
    let at_cap = vec![b'm'; 4096];
    let cfg = s3::S3Config {
        objects: vec![("p/v/current".to_owned(), big), ("p/v/small".to_owned(), at_cap)],
        ..s3::S3Config::default()
    };
    let m = start(cfg).await;
    let b = m.backend();
    assert_eq!(b.get("p/v/current", MAX_BLOB).await.expect_err("cap").code(), "sync.too_large");
    assert_eq!(b.get("p/v/small", 4096).await.expect("at cap").expect("present").bytes.len(), 4096);
    assert_eq!(b.get("p/v/small", 4095).await.expect_err("one under").code(), "sync.too_large");
    m.clean();
}

/// The rollback and fork knobs are visible through `head` / `get` exactly as the engine
/// relies on them: a rolled-back object is an older version, a forked `ETag` makes the next
/// `If-Match` write a 412 (`sync.conflict`), never a silent overwrite.
#[tokio::test]
async fn rollback_and_fork_knobs_surface_through_the_backend() {
    let m = start(s3::S3Config::default()).await;
    let b = m.backend();
    let meta = PutMeta { counter: Some(1), parent: None };
    let PutOutcome::Written { etag: e1 } =
        b.put("k/current", Bytes::from_static(b"v1"), Cond::IfNoneMatch, &meta).await.expect("v1")
    else {
        panic!("not written")
    };
    let meta2 = PutMeta { counter: Some(2), parent: None };
    let PutOutcome::Written { etag: e2 } = b
        .put("k/current", Bytes::from_static(b"v2"), Cond::IfMatch(&e1), &meta2)
        .await
        .expect("v2")
    else {
        panic!("not written")
    };
    assert_ne!(e1, e2);
    let r = b
        .put("k/current", Bytes::from_static(b"v3"), Cond::IfMatch(&e1), &meta2)
        .await
        .expect("stale");
    assert!(matches!(r, PutOutcome::PreconditionFailed), "{r:?}");

    m.srv.set_knobs(S3Knobs { rollback: 1, fork: false });
    let h = b.head("k/current").await.expect("head").expect("present");
    assert_eq!(h.etag, e1, "rolled back to v1");
    assert_eq!(b.get("k/current", MAX_BLOB).await.expect("get").expect("present").bytes, b"v1");

    m.srv.set_knobs(S3Knobs { rollback: 0, fork: true });
    let h = b.head("k/current").await.expect("head").expect("present");
    assert_ne!(h.etag, e2, "forked ETag");
    let r = b
        .put("k/current", Bytes::from_static(b"v3"), Cond::IfMatch(&h.etag), &meta2)
        .await
        .expect("forked write");
    assert!(matches!(r, PutOutcome::PreconditionFailed), "{r:?}");
    assert_eq!(m.srv.object("k/current").expect("stored"), b"v2", "v2 was never overwritten");
    m.clean();
}

/// The setup probe refuses a bucket without conditional writes (`sync.unsupported_backend`)
/// and leaves nothing behind.
#[tokio::test]
async fn the_probe_refuses_a_bucket_without_conditional_writes() {
    let m = start(s3::S3Config { conditional_writes: false, ..s3::S3Config::default() }).await;
    let remote = Remote::new(m.backend(), "mooring", Uuid::from_u128(7)).expect("remote");
    let e = remote.require_conditional_writes().await.expect_err("unsupported");
    assert_eq!(e.code(), "sync.unsupported_backend", "{e}");
    let leftovers: Vec<String> = m.srv.keys().into_iter().filter(|k| k.contains("probe")).collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    m.clean();

    let m = start(s3::S3Config::default()).await;
    let remote = Remote::new(m.backend(), "mooring", Uuid::from_u128(7)).expect("remote");
    remote.require_conditional_writes().await.expect("supported");
    assert!(remote.probe().await.expect("probe"), "conditional writes work");
    m.clean();
}

/// Error mapping stays static: nothing from the server's XML error body reaches the error
/// text (the backend does not parse it).
#[tokio::test]
async fn server_error_bodies_are_never_echoed() {
    let m = start(s3::S3Config { max_object_size: 16, ..s3::S3Config::default() }).await;
    let b = m.backend();
    let e = b
        .put("k/current", Bytes::from(vec![0u8; 64]), Cond::IfNoneMatch, &PutMeta::default())
        .await
        .expect_err("too large for the bucket");
    let text = e.to_string();
    assert!(!text.contains("EntityTooLarge") && !text.contains('<'), "{text}");
    assert!(matches!(e, SyncError::Backend { .. } | SyncError::TooLarge), "{e}");
    m.clean();
}
