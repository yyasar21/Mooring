//! `S3Backend` against the loopback mock: presigned conditional writes, probe, two engines
//! racing over HTTP, caps, configuration validation.

use bytes::Bytes;
use secrecy::SecretString;

use super::s3_mock::{S3Mock, ACCESS_KEY, BUCKET};
use super::{vaults, Device};
use crate::backend::MAX_HEADER_OBJECT;
use crate::{
    Cond, ObjectStore, Outcome, PutMeta, PutOutcome, Remote, S3Backend, S3Config, S3Credentials,
    SyncEngine, SyncError, VecAudit,
};

fn config(endpoint: &str, dir: &std::path::Path) -> S3Config {
    S3Config {
        endpoint: endpoint.to_owned(),
        region: "us-east-1".to_owned(),
        bucket: BUCKET.to_owned(),
        path_style: true,
        known_certs_path: dir.join("known_sync_certs"),
        ca_pem: None,
        allow_plaintext_loopback: true,
        trusted_once: None,
    }
}

fn creds() -> S3Credentials {
    S3Credentials {
        access_key_id: ACCESS_KEY.to_owned(),
        secret_access_key: SecretString::from("test-only-secret-access-key".to_owned()),
        session_token: None,
    }
}

fn backend(mock: &S3Mock, dir: &std::path::Path) -> S3Backend {
    S3Backend::new(&config(&mock.endpoint(), dir), &creds()).expect("backend")
}

#[tokio::test]
async fn conditional_writes_head_get_delete() {
    let mock = S3Mock::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let s3 = backend(&mock, dir.path());
    let meta = PutMeta { counter: Some(1), parent: None };
    let body = || Bytes::from_static(b"blob");
    let PutOutcome::Written { etag } =
        s3.put("k", body(), Cond::IfNoneMatch, &meta).await.expect("put")
    else {
        panic!("first create must succeed")
    };
    assert_eq!(
        s3.put("k", body(), Cond::IfNoneMatch, &meta).await.expect("2"),
        PutOutcome::PreconditionFailed
    );
    assert_eq!(
        s3.put("k", body(), Cond::IfMatch("\"nope\""), &meta).await.expect("3"),
        PutOutcome::PreconditionFailed
    );
    assert!(matches!(
        s3.put("k", body(), Cond::IfMatch(&etag), &meta).await.expect("4"),
        PutOutcome::Written { .. }
    ));
    let head = s3.head("k").await.expect("head").expect("exists");
    assert_ne!(head.etag, etag, "a new version has a new ETag");
    assert_eq!(s3.get("k", 1024).await.expect("get").expect("obj").bytes, b"blob");
    assert!(matches!(s3.get("k", 2).await, Err(SyncError::TooLarge)), "Content-Length cap");
    s3.delete("k").await.expect("delete");
    assert!(s3.get("k", 1024).await.expect("get").is_none());
    assert!(s3.head("k").await.expect("head").is_none());
    assert!(mock.log().iter().all(|l| !l.ends_with(" 403")), "every request presigned correctly");
}

#[tokio::test]
async fn probe_passes_and_refuses_an_ignoring_backend() {
    let mock = S3Mock::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let v = vaults(1).remove(0);
    let remote = Remote::new(backend(&mock, dir.path()), "", v.vault_id()).expect("remote");
    remote.require_conditional_writes().await.expect("conditional writes work");
    mock.set_ignore_conditionals(true);
    let err = remote.require_conditional_writes().await.expect_err("refused");
    assert!(matches!(err, SyncError::UnsupportedBackend));
}

#[tokio::test]
async fn header_object_cap_is_enforced_before_reading() {
    let mock = S3Mock::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let v = vaults(1).remove(0);
    let remote = Remote::new(backend(&mock, dir.path()), "p", v.vault_id()).expect("remote");
    mock.put_raw(&format!("p/{}/header", v.vault_id()), vec![b'{'; MAX_HEADER_OBJECT + 1]);
    assert!(matches!(remote.get_header().await, Err(SyncError::TooLarge)));
    assert!(matches!(
        remote.put_header(&vec![0; MAX_HEADER_OBJECT + 1]).await,
        Err(SyncError::TooLarge)
    ));
}

#[tokio::test]
async fn two_devices_race_over_http_and_converge() {
    let mock = S3Mock::start().await;
    let mut vs = vaults(2);
    let b = Device::new(vs.remove(1), "laptop");
    let a = Device::new(vs.remove(0), "desktop");
    let audit = VecAudit::default();
    let ra = Remote::new(backend(&mock, a.dir.path()), "team", a.vault.vault_id()).expect("ra");
    let rb = Remote::new(backend(&mock, b.dir.path()), "team", b.vault.vault_id()).expect("rb");
    a.conn("from-a", "a.example.test");
    b.conn("from-b", "b.example.test");
    let e = SyncEngine::default();
    let (la, lb) = (a.local(), b.local());
    let (x, y) = tokio::join!(e.run(&la, &ra, &audit), e.run(&lb, &rb, &audit));
    let outs = [x.expect("a"), y.expect("b")];
    assert!(outs.iter().any(|o| matches!(o, Outcome::Pushed { counter: 1 })), "{outs:?}");
    assert!(outs.iter().any(|o| matches!(o, Outcome::Merged { counter: 2, .. })), "{outs:?}");
    e.run(&la, &ra, &audit).await.expect("a settles");
    e.run(&lb, &rb, &audit).await.expect("b settles");
    assert_eq!(a.names(), ["from-a", "from-b"]);
    assert_eq!(a.names(), b.names());
    assert!(mock.log().iter().any(|l| l == "PUT 412"), "the race hit a precondition");
}

#[test]
fn configuration_is_validated_without_io() {
    let dir = tempfile::tempdir().expect("dir");
    let mut c = config("http://s3.example.test", dir.path());
    assert!(matches!(S3Backend::new(&c, &creds()), Err(SyncError::Http(_))), "plaintext refused");
    c.endpoint = "not a url".to_owned();
    assert!(matches!(S3Backend::new(&c, &creds()), Err(SyncError::Invalid(_))));
    c.endpoint = "https://s3.example.test".to_owned();
    c.bucket = "Bad_Bucket".to_owned();
    assert!(S3Backend::new(&c, &creds()).is_err());
    c.bucket = BUCKET.to_owned();
    c.region = "us east".to_owned();
    assert!(S3Backend::new(&c, &creds()).is_err());
    c.region = "eu-central-1".to_owned();
    let s3 = S3Backend::new(&c, &creds()).expect("valid");
    assert!(!format!("{s3:?}").contains("test-only-secret"));
    assert_eq!(format!("{:?}", creds()), "S3Credentials(..)");
}
