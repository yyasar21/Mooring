//! In-process hyper test servers (TLS with rcgen certificates, or loopback plaintext).
//! Names are `example.test` / loopback only.

#![allow(dead_code, clippy::missing_panics_doc)]

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use mooring_core::known_certs::CertProtocol;
use mooring_http::HttpConfig;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;

pub type Body = BoxBody<Bytes, Infallible>;
pub type Handler = Arc<
    dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> + Send + Sync,
>;

pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response<Body>> + Send + 'static,
{
    Arc::new(move |r| Box::pin(f(r)))
}

pub fn full(status: u16, body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(Full::new(body.into()).boxed());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r
}

/// A chunked body (no `Content-Length`) of `n` chunks of `size` bytes.
pub fn chunked(n: usize, size: usize) -> Response<Body> {
    let frames =
        (0..n).map(move |_| Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b'a'; size]))));
    Response::new(StreamBody::new(futures_util::stream::iter(frames)).boxed())
}

/// A slow-loris body: `n` one-byte chunks, one every `every` (no `Content-Length`).
pub fn dripping(n: usize, every: std::time::Duration) -> Response<Body> {
    let frames = futures_util::stream::unfold(0usize, move |i| async move {
        if i >= n {
            return None;
        }
        tokio::time::sleep(every).await;
        Some((Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"a"))), i + 1))
    });
    Response::new(StreamBody::new(frames).boxed())
}

pub fn ok_json() -> Handler {
    handler(|_| async { full(200, r#"{"ok":true}"#) })
}

fn names(n: &[&str]) -> Vec<String> {
    n.iter().map(|s| (*s).to_owned()).collect()
}

pub fn self_signed(n: &[&str]) -> (Vec<u8>, KeyPair) {
    let key = KeyPair::generate().expect("key");
    let cert = CertificateParams::new(names(n)).expect("params").self_signed(&key).expect("cert");
    (cert.der().to_vec(), key)
}

pub fn ca() -> (String, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, "Mooring Test CA");
    let cert = params.self_signed(&key).expect("ca cert");
    (cert.pem(), Issuer::new(params, key))
}

pub fn signed_by(n: &[&str], issuer: &Issuer<'_, KeyPair>) -> (Vec<u8>, KeyPair) {
    let key = KeyPair::generate().expect("key");
    let cert =
        CertificateParams::new(names(n)).expect("params").signed_by(&key, issuer).expect("leaf");
    (cert.der().to_vec(), key)
}

pub struct Server {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    pub dir: tempfile::TempDir,
}

impl Server {
    pub fn https(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub fn http(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    pub fn known(&self) -> PathBuf {
        self.dir.path().join(CertProtocol::Kube.file_name())
    }

    /// Test defaults: no system roots, fast retries.
    pub fn config(&self) -> HttpConfig {
        let mut c = HttpConfig::new(CertProtocol::Kube, &self.https(), self.known());
        c.use_system_roots = false;
        c.retry.base_delay = std::time::Duration::from_millis(1);
        c.retry.max_delay = std::time::Duration::from_millis(5);
        c
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Serves `cert` but signs the handshake with `key` (which may not belong to `cert`).
#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

pub async fn serve_tls(cert: Vec<u8>, key: &KeyPair, h: Handler) -> Server {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing = provider.key_provider.load_private_key(der).expect("signing key");
    let ck = Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert)], signing));
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(ck)));
    serve(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))), h).await
}

pub async fn serve_plain(h: Handler) -> Server {
    serve(None, h).await
}

async fn serve(tls: Option<tokio_rustls::TlsAcceptor>, h: Handler) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (tls, h, counter) = (tls.clone(), Arc::clone(&h), Arc::clone(&counter));
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let fut = h(req);
                    async move { Ok::<_, Infallible>(fut.await) }
                });
                let builder = hyper::server::conn::http1::Builder::new();
                match tls {
                    Some(acc) => {
                        let Ok(stream) = acc.accept(tcp).await else { return };
                        let _ = builder
                            .serve_connection(TokioIo::new(stream), svc)
                            .with_upgrades()
                            .await;
                    }
                    None => {
                        let _ =
                            builder.serve_connection(TokioIo::new(tcp), svc).with_upgrades().await;
                    }
                }
            });
        }
    });
    Server { addr, hits, dir: tempfile::tempdir().expect("tmp") }
}

/// A TLS server with a self-signed certificate for 127.0.0.1; returns its leaf DER too.
pub async fn self_signed_server(h: Handler) -> (Server, Vec<u8>) {
    let (der, key) = self_signed(&["127.0.0.1"]);
    (serve_tls(der.clone(), &key, h).await, der)
}

/// Pin `der` for the server in its store (what the Gate does after a "yes").
pub fn pin(server: &Server, der: &[u8]) {
    let fp = mooring_core::known_certs::fingerprint(der);
    mooring_core::known_certs::KnownCerts::add_and_save(
        &server.known(),
        "127.0.0.1",
        server.addr.port(),
        &fp,
        time::OffsetDateTime::now_utc(),
    )
    .expect("pin");
}
