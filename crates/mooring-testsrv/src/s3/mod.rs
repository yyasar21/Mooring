//! In-process mock S3-compatible object store (ADR-0017 §Test plan) on loopback TLS.
//!
//! One bucket, path-style (`/<bucket>/<key>`) or virtual-host (`Host: <bucket>.…`) addressing.
//! Every request must carry a valid SigV4 signature ([`sigv4`]: `Authorization` header or a
//! presigned query) for the test access key. `PutObject` honours `If-None-Match: *` and
//! `If-Match: <etag>` (412 on mismatch) unless [`S3Config::conditional_writes`] is off (the
//! "backend without conditional writes" mode); `GetObject` / `HeadObject` (with
//! `If-None-Match` → 304), `DeleteObject`, `ListObjectsV2` (`prefix`, `delimiter`,
//! `max-keys`, `continuation-token`, `start-after`), `HEAD /<bucket>`. Anything else
//! (multipart, copy, ACL, bucket APIs, `POST`) is a violation (500).
//! Every object keeps its version history so the rollback knob can serve an older one.

mod routes;
pub mod sigv4;

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;

pub use sigv4::Credentials;

use crate::http::{self, HttpKnobs, Recorder, Running};
use crate::tls::TestCert;

/// Hostile behaviour of the S3 mock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Knobs {
    /// GET / HEAD / List serve the version this many steps before the latest (rollback /
    /// freeze attack); clamped to the oldest version.
    pub rollback: usize,
    /// GET / HEAD / List report an ETag that differs from the stored one, so a later
    /// `If-Match` with it fails (fork / lost-update test).
    pub fork: bool,
}

/// Configuration of one S3 mock.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub credentials: Credentials,
    pub bucket: String,
    /// Honour `If-None-Match` / `If-Match` on PUT (off = the setup probe must refuse it).
    pub conditional_writes: bool,
    /// Largest object a PUT may store (`EntityTooLarge` above it).
    pub max_object_size: usize,
    /// Objects present at start.
    pub objects: Vec<(String, Vec<u8>)>,
    pub knobs: S3Knobs,
    pub http: HttpKnobs,
    pub cert: Option<TestCert>,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            credentials: Credentials {
                access_key: "AKIDMOORINGTEST0001".to_owned(),
                secret_key: "testsecretkey".to_owned(),
                session_token: None,
                region: "us-east-1".to_owned(),
            },
            bucket: "mooring-sync".to_owned(),
            conditional_writes: true,
            max_object_size: 64 * 1024 * 1024 + 4096,
            objects: Vec::new(),
            knobs: S3Knobs::default(),
            http: HttpKnobs { max_request_body: 80 * 1024 * 1024, ..HttpKnobs::default() },
            cert: None,
        }
    }
}

/// One stored version of an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersion {
    pub data: Bytes,
    /// Quoted, as sent in the `ETag` header.
    pub etag: String,
    pub modified: i64,
}

impl ObjectVersion {
    fn new(data: Bytes) -> Self {
        let etag = format!("\"{}\"", &sigv4::sha256_hex(&data)[..32]);
        Self { data, etag, modified: http::time::now_unix() }
    }
}

#[derive(Debug)]
struct Dynamic {
    config: S3Config,
    objects: BTreeMap<String, Vec<ObjectVersion>>,
}

impl Dynamic {
    /// The version GET / HEAD / List serve, with the knobs applied.
    fn served(&self, key: &str) -> Option<ObjectVersion> {
        let versions = self.objects.get(key)?;
        let idx = versions.len().checked_sub(1)?.saturating_sub(self.config.knobs.rollback);
        let mut v = versions.get(idx)?.clone();
        if self.config.knobs.fork {
            v.etag = format!(
                "\"{}\"",
                &sigv4::sha256_hex(&[b"fork".as_slice(), &v.data].concat())[..32]
            );
        }
        Some(v)
    }
}

#[derive(Debug)]
pub(crate) struct S3State {
    inner: Mutex<Dynamic>,
}

impl S3State {
    fn lock(&self) -> MutexGuard<'_, Dynamic> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Handle of a running S3 mock; dropping it stops the server.
#[derive(Debug)]
pub struct S3Server {
    running: Running,
    cert: TestCert,
    state: Arc<S3State>,
    recorder: Recorder,
}

/// Starts the mock on `127.0.0.1:port` (`0` = ephemeral). Needs a Tokio runtime.
pub async fn start(mut config: S3Config, port: u16) -> io::Result<S3Server> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(io::Error::other)?,
    };
    let tls = cert.server_config().map_err(io::Error::other)?;
    let objects = config
        .objects
        .iter()
        .map(|(k, v)| (k.clone(), vec![ObjectVersion::new(Bytes::from(v.clone()))]))
        .collect();
    let state = Arc::new(S3State { inner: Mutex::new(Dynamic { config, objects }) });
    let recorder = Recorder::default();
    let running = http::serve(tls, port, Arc::clone(&state), recorder.clone()).await?;
    Ok(S3Server { running, cert, state, recorder })
}

impl S3Server {
    pub fn addr(&self) -> SocketAddr {
        self.running.addr
    }

    /// `https://127.0.0.1:<port>` (custom endpoint, path-style).
    pub fn endpoint(&self) -> String {
        format!("https://{}", self.running.addr)
    }

    pub fn cert(&self) -> &TestCert {
        &self.cert
    }

    pub fn recorder(&self) -> &Recorder {
        &self.recorder
    }

    pub fn credentials(&self) -> Credentials {
        self.state.lock().config.credentials.clone()
    }

    pub fn bucket(&self) -> String {
        self.state.lock().config.bucket.clone()
    }

    /// Transport knobs (response delay, slow-loris drip, request-body cap) for later requests.
    pub fn set_http_knobs(&self, knobs: HttpKnobs) {
        self.state.lock().config.http = knobs;
    }

    pub fn set_knobs(&self, knobs: S3Knobs) {
        self.state.lock().config.knobs = knobs;
    }

    pub fn set_conditional_writes(&self, on: bool) {
        self.state.lock().config.conditional_writes = on;
    }

    /// Latest stored bytes of `key` (knobs not applied).
    pub fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.state.lock().objects.get(key)?.last().map(|v| v.data.to_vec())
    }

    /// Every stored version of `key`, oldest first.
    pub fn versions(&self, key: &str) -> Vec<ObjectVersion> {
        self.state.lock().objects.get(key).cloned().unwrap_or_default()
    }

    pub fn keys(&self) -> Vec<String> {
        self.state.lock().objects.keys().cloned().collect()
    }

    /// Stores `data` under `key` out of band ("another device pushed"); returns the ETag.
    pub fn put_object(&self, key: &str, data: &[u8]) -> String {
        let v = ObjectVersion::new(Bytes::copy_from_slice(data));
        let etag = v.etag.clone();
        self.state.lock().objects.entry(key.to_owned()).or_default().push(v);
        etag
    }
}
