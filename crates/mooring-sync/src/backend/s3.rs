//! S3-compatible [`ObjectStore`]: `rusty-s3` presigns (`SigV4`, sans-IO), `mooring-http` sends
//! (our TLS verifier and `known_sync_certs`, body caps, no proxy, `CertProtocol::Sync`).
//!
//! * Two clients on the same origin: reads (`GET`, `HEAD`, `DELETE`) retry with the shared
//!   bounded policy; writes (`PUT`) never retry, so a lost response can't turn our own
//!   successful conditional write into a spurious 412.
//! * Conditional and metadata headers are part of the signature (`X-Amz-SignedHeaders`), so a
//!   middlebox cannot strip `If-Match` without breaking the request.
//! * The access key lives only in this value (`s3_access_key` credential opened by the
//!   caller); the secret is zeroized on drop and never printed.
//! * Review 6 N-44 (R-EXT-STR): each presigned path carries the signature and, with STS, the
//!   session token, and the storage side logs it. Requests are sent at once, so the signature
//!   is valid for [`SIGN_TTL`] = 60 s only, and the signed path is `Zeroizing` on our side.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use mooring_http::{CertProtocol, Headers, HttpClient, HttpConfig, HttpError, Method, RawResponse};
use rusty_s3::actions::{DeleteObject, GetObject, HeadObject, PutObject};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{Cond, Object, ObjectStore, PutMeta, PutOutcome, RemoteHead};
use crate::error::{Result, SyncError};

/// Lifetime of each presigned request (N-44: a leaked signed path is useless after a minute).
pub const SIGN_TTL: Duration = Duration::from_secs(60);
const META_COUNTER: &str = "x-amz-meta-mooring-counter";
const META_PARENT: &str = "x-amz-meta-mooring-parent";

/// Where the bucket is.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// `https://s3.example.test` (custom endpoints allowed; plaintext only for loopback IP
    /// literals and only with `allow_plaintext_loopback`).
    pub endpoint: String,
    /// Region (`us-east-1` for most S3-compatible servers).
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    /// Path-style (`endpoint/bucket/key`) instead of virtual-host URLs.
    pub path_style: bool,
    /// `$APP_DATA/known_sync_certs`.
    pub known_certs_path: PathBuf,
    /// Extra CA (PEM) for a private endpoint.
    pub ca_pem: Option<String>,
    /// Loopback plaintext (tests, a local `MinIO` on 127.0.0.1).
    pub allow_plaintext_loopback: bool,
    /// A leaf the user trusted for this run only (certificate prompt "once").
    pub trusted_once: Option<[u8; 32]>,
}

/// `s3_access_key` secrets, in memory only.
pub struct S3Credentials {
    /// Access key id (not secret, still never logged).
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: SecretString,
    /// STS session token.
    pub session_token: Option<SecretString>,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3Credentials(..)")
    }
}

/// The S3 backend.
pub struct S3Backend {
    bucket: Bucket,
    creds: Credentials,
    read: HttpClient,
    write: HttpClient,
}

impl std::fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend").field("bucket", &self.bucket.name()).finish_non_exhaustive()
    }
}

fn status_err(r: &RawResponse) -> SyncError {
    SyncError::Backend { status: r.status.as_u16() }
}

fn too_large(e: HttpError) -> SyncError {
    match e {
        HttpError::BodyTooLarge { .. } => SyncError::TooLarge,
        other => SyncError::Http(other),
    }
}

impl S3Backend {
    /// Validate the configuration and build both clients. No I/O.
    pub fn new(cfg: &S3Config, creds: &S3Credentials) -> Result<Self> {
        let endpoint =
            cfg.endpoint.parse().map_err(|_| SyncError::Invalid("endpoint is not a URL"))?;
        let style = if cfg.path_style { UrlStyle::Path } else { UrlStyle::VirtualHost };
        let valid_name = (3..=63).contains(&cfg.bucket.len())
            && cfg
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b));
        let valid_region = !cfg.region.is_empty()
            && cfg.region.len() <= 64
            && cfg.region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid_name || !valid_region {
            return Err(SyncError::Invalid("bucket or region name"));
        }
        let bucket = Bucket::new(endpoint, style, cfg.bucket.clone(), cfg.region.clone())
            .map_err(|_| SyncError::Invalid("endpoint, bucket or URL style"))?;
        let origin = bucket.base_url().origin().ascii_serialization();
        let mut http = HttpConfig::new(CertProtocol::Sync, &origin, cfg.known_certs_path.clone());
        http.extra_ca_pem.clone_from(&cfg.ca_pem);
        http.allow_plaintext = cfg.allow_plaintext_loopback;
        http.trusted_once = cfg.trusted_once;
        http.max_body = crate::blob::MAX_BLOB;
        let read = HttpClient::new(http.clone())?;
        http.retry.max_attempts = 1;
        let write = HttpClient::new(http)?;
        let secret = creds.secret_access_key.expose_secret().to_owned();
        let creds = match &creds.session_token {
            Some(t) => Credentials::new_with_token(
                creds.access_key_id.clone(),
                secret,
                t.expose_secret().to_owned(),
            ),
            None => Credentials::new(creds.access_key_id.clone(), secret),
        };
        Ok(Self { bucket, creds, read, write })
    }
}

/// Sign `action` and return the path + query `mooring-http` sends to the bucket origin
/// (`Zeroizing` on our side: it carries the signature and the STS session token, N-44; the
/// signer's transient `Url` is dropped here).
macro_rules! signed_path {
    ($action:expr) => {{
        let url = $action.sign(SIGN_TTL);
        Zeroizing::new(match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        })
    }};
}

fn etag_of(r: &RawResponse) -> Result<String> {
    r.header("etag")
        .filter(|e| !e.is_empty() && e.len() <= 256 && e.is_ascii())
        .map(str::to_owned)
        .ok_or(SyncError::Format("missing or invalid ETag"))
}

#[async_trait]
impl ObjectStore for S3Backend {
    async fn head(&self, key: &str) -> Result<Option<RemoteHead>> {
        let path = signed_path!(HeadObject::new(&self.bucket, Some(&self.creds), key));
        // The body of a HEAD is empty; the cap only bounds the declared `Content-Length`.
        let r = self
            .read
            .request(Method::HEAD, &path, &Headers::new(), None, crate::blob::MAX_BLOB)
            .await
            .map_err(too_large)?;
        match r.status.as_u16() {
            200 => Ok(Some(RemoteHead {
                etag: etag_of(&r)?,
                counter: r.header(META_COUNTER).and_then(|v| v.parse().ok()),
                parent: r.header(META_PARENT).map(str::to_owned),
            })),
            404 => Ok(None),
            _ => Err(status_err(&r)),
        }
    }

    async fn get(&self, key: &str, cap: usize) -> Result<Option<Object>> {
        let path = signed_path!(GetObject::new(&self.bucket, Some(&self.creds), key));
        let r = self
            .read
            .request(Method::GET, &path, &Headers::new(), None, cap)
            .await
            .map_err(too_large)?;
        match r.status.as_u16() {
            200 => Ok(Some(Object { etag: etag_of(&r)?, bytes: r.body.to_vec() })),
            404 => Ok(None),
            _ => Err(status_err(&r)),
        }
    }

    async fn put(
        &self,
        key: &str,
        body: Bytes,
        cond: Cond<'_>,
        meta: &PutMeta,
    ) -> Result<PutOutcome> {
        let mut action = PutObject::new(&self.bucket, Some(&self.creds), key);
        let mut headers = Headers::new();
        let counter = meta.counter.map(|c| c.to_string());
        let mut pairs: Vec<(&'static str, &str)> = Vec::new();
        match cond {
            Cond::None => {}
            Cond::IfNoneMatch => pairs.push(("if-none-match", "*")),
            Cond::IfMatch(etag) => pairs.push(("if-match", etag)),
        }
        if let Some(c) = &counter {
            pairs.push((META_COUNTER, c));
        }
        if let Some(p) = &meta.parent {
            pairs.push((META_PARENT, p));
        }
        for (name, value) in &pairs {
            action.headers_mut().insert(*name, (*value).to_owned());
            headers = headers.insert(name, value)?;
        }
        let path = signed_path!(action);
        let r = self.write.put_raw(&path, &headers, body, Some("application/octet-stream")).await?;
        match r.status.as_u16() {
            200 | 201 | 204 => Ok(PutOutcome::Written { etag: etag_of(&r)? }),
            409 | 412 => Ok(PutOutcome::PreconditionFailed),
            _ => Err(status_err(&r)),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = signed_path!(DeleteObject::new(&self.bucket, Some(&self.creds), key));
        let r = self.read.request(Method::DELETE, &path, &Headers::new(), None, 64 * 1024).await?;
        match r.status.as_u16() {
            200 | 204 | 404 => Ok(()),
            _ => Err(status_err(&r)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review 6 N-44: presigned paths live 60 s and are `Zeroizing` on our side.
    #[test]
    fn presigned_paths_expire_after_a_minute() {
        assert_eq!(SIGN_TTL, Duration::from_secs(60));
        let cfg = S3Config {
            endpoint: "https://s3.example.test".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "mooring".to_owned(),
            path_style: true,
            known_certs_path: PathBuf::from("known_sync_certs"),
            ca_pem: None,
            allow_plaintext_loopback: false,
            trusted_once: None,
        };
        let creds = S3Credentials {
            access_key_id: "AKIATESTONLY".to_owned(),
            secret_access_key: SecretString::from("test-only-secret".to_owned()),
            session_token: Some(SecretString::from("test-only-session-token".to_owned())),
        };
        let s3 = S3Backend::new(&cfg, &creds).expect("backend");
        let path: Zeroizing<String> =
            signed_path!(HeadObject::new(&s3.bucket, Some(&s3.creds), "k"));
        assert!(
            path.contains("X-Amz-Expires=60"),
            "{}",
            path.replace("test-only-session-token", "<token>")
        );
        assert!(path.contains("X-Amz-Security-Token="), "the STS token is sent only when set");
    }
}
