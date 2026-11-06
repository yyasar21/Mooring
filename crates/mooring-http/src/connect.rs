//! The hyper-util connector: `TcpStream` + `tokio-rustls` with [`HttpVerifier`]. No proxy, no
//! environment variables, no `hyper-rustls`. Every new connection reloads the pin store (the
//! Gate may have written a pin since) and fails closed when it cannot be read.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use mooring_core::known_certs::KnownCerts;
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use tokio_rustls::client::TlsStream;

use crate::config::{Base, HttpConfig};
use crate::error::{ConnectFailure, HttpError};
use crate::verify::{
    chain_verifier, provider, root_store, server_name, system_roots, take_decision, DecisionSlot,
    HttpVerifier, TrustDecision, TrustVerdict,
};

pub(crate) type Chain = Option<Arc<WebPkiServerVerifier>>;

/// The chain verifier of one client: system roots (unless anchored) plus `extra_ca_pem`.
/// Blocking work runs on the blocking pool. Shared with [`crate::tls`].
pub(crate) async fn build_chain(
    use_system_roots: bool,
    ca_exclusive: bool,
    extra_ca_pem: Option<String>,
) -> Result<Chain, HttpError> {
    tokio::task::spawn_blocking(move || {
        let use_system = use_system_roots && !ca_exclusive;
        let system = if use_system { system_roots() } else { &[] };
        let (roots, added) = root_store(system, extra_ca_pem.as_deref());
        if ca_exclusive && added == 0 {
            return Err(HttpError::InvalidConfig("extra_ca_pem holds no certificate"));
        }
        Ok(chain_verifier(roots))
    })
    .await
    .map_err(|_| HttpError::TrustStore)?
}

/// The pin store for one connect, reloaded every time (the Gate may have written a pin since)
/// and failing closed when unreadable; `trusted_once` is added as a pin of this load only
/// unless the host already has one. Shared with [`crate::tls`].
pub(crate) async fn load_known(
    path: std::path::PathBuf,
    host: String,
    port: u16,
    trusted_once: Option<[u8; 32]>,
) -> Result<KnownCerts, HttpError> {
    tokio::task::spawn_blocking(move || {
        let mut known = KnownCerts::load(&path).map_err(|e| {
            tracing::warn!(error = %e, "certificate trust store unreadable");
            HttpError::TrustStore
        })?;
        if let Some(fp) = trusted_once {
            if !known.has_pin(&host, port) {
                known.add(&host, port, &fp, time::OffsetDateTime::now_utc());
            }
        }
        Ok(known)
    })
    .await
    .map_err(|_| HttpError::TrustStore)?
}

struct Inner {
    cfg: HttpConfig,
    base: Base,
    sni: ServerName<'static>,
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    chain: OnceCell<Chain>,
}

/// Connector for one origin (the client refuses other authorities before they get here).
#[derive(Clone)]
pub(crate) struct Connector(Arc<Inner>);

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector").field("protocol", &self.0.cfg.protocol).finish_non_exhaustive()
    }
}

impl Connector {
    pub(crate) fn new(cfg: HttpConfig, base: Base) -> Result<Self, HttpError> {
        let sni = server_name(cfg.tls_server_name.as_deref().unwrap_or(&base.host))
            .ok_or(HttpError::InvalidConfig("host is not a valid TLS server name"))?;
        let identity = match &cfg.client_identity {
            None => None,
            Some(id) => {
                let key = PrivateKeyDer::try_from(id.key_der.as_slice())
                    .map_err(|_| HttpError::InvalidConfig("client key is not PKCS#8/PKCS#1/SEC1"))?
                    .clone_key();
                if id.cert_chain_der.is_empty() {
                    return Err(HttpError::InvalidConfig("client certificate missing"));
                }
                let certs =
                    id.cert_chain_der.iter().map(|c| CertificateDer::from(c.clone())).collect();
                Some((certs, key))
            }
        };
        Ok(Self(Arc::new(Inner { cfg, base, sni, identity, chain: OnceCell::new() })))
    }

    async fn chain(&self) -> Result<Chain, HttpError> {
        let inner = Arc::clone(&self.0);
        self.0
            .chain
            .get_or_try_init(|| async move {
                build_chain(
                    inner.cfg.use_system_roots,
                    inner.cfg.ca_exclusive,
                    inner.cfg.extra_ca_pem.clone(),
                )
                .await
            })
            .await
            .cloned()
    }

    async fn load_known(&self) -> Result<KnownCerts, HttpError> {
        load_known(
            self.0.cfg.known_certs_path.clone(),
            self.0.base.host.clone(),
            self.0.base.port,
            self.0.cfg.trusted_once,
        )
        .await
    }

    async fn tcp(&self) -> Result<TcpStream, HttpError> {
        let addrs = tokio::net::lookup_host((self.0.base.host.as_str(), self.0.base.port))
            .await
            .map_err(|e| HttpError::Connect(e.kind()))?;
        let mut last = io::ErrorKind::NotFound;
        for addr in addrs.take(8) {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = e.kind(),
            }
        }
        Err(HttpError::Connect(last))
    }

    async fn connect(self) -> Result<MaybeTls, HttpError> {
        let base = &self.0.base;
        let known = self.load_known().await?;
        if !base.tls {
            // Validated: allow_plaintext + loopback. Downgrade guard: a pin or marker wins.
            if known.tls_expected(&base.host, base.port) {
                return Err(HttpError::PlaintextRefused);
            }
            return Ok(MaybeTls { io: Io::Plain(self.tcp().await?), decision: None });
        }
        let slot = DecisionSlot::default();
        let verifier = Arc::new(HttpVerifier {
            protocol: self.0.cfg.protocol,
            host: base.host.clone(),
            port: base.port,
            known,
            chain: self.chain().await?,
            anchored: self.0.cfg.ca_exclusive,
            slot: Arc::clone(&slot),
        });
        let builder = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| HttpError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let mut config = match &self.0.identity {
            None => builder.with_no_client_auth(),
            Some((certs, key)) => builder
                .with_client_auth_cert(certs.clone(), key.clone_key())
                .map_err(|_| HttpError::InvalidConfig("client certificate and key do not match"))?,
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Every connection runs the verifier (a resumed session would skip the pin check).
        config.resumption = Resumption::disabled();
        let tcp = self.tcp().await?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
        match tls.connect(self.0.sni.clone(), tcp).await {
            Ok(stream) => {
                let decision = take_decision(&slot);
                if let (Some(d), Some(tx)) = (&decision, &self.0.cfg.trust_events) {
                    let _ = tx.try_send(d.clone());
                }
                Ok(MaybeTls { io: Io::Tls(Box::new(stream)), decision })
            }
            Err(e) => {
                Err(take_decision(&slot).and_then(trust_error).unwrap_or_else(|| tls_error(&e)))
            }
        }
    }
}

/// The `Trust*` error of a failed handshake whose verifier recorded `d`, or `None` when the
/// verifier accepted (the failure is elsewhere). Shared with [`crate::tls`].
pub(crate) fn trust_error(d: TrustDecision) -> Option<HttpError> {
    match d.verdict {
        TrustVerdict::Prompt => Some(HttpError::TrustPrompt(Box::new(d))),
        TrustVerdict::Mismatch { .. } => Some(HttpError::TrustMismatch(Box::new(d))),
        TrustVerdict::Rejected => Some(HttpError::TrustRejected(Box::new(d))),
        TrustVerdict::Conflict => Some(HttpError::TrustConflict(Box::new(d))),
        TrustVerdict::Pinned { .. } | TrustVerdict::CaValid => None,
    }
}

fn tls_error(e: &io::Error) -> HttpError {
    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(r) => HttpError::Tls(r.to_string()),
        None => HttpError::Tls(format!("{:?}", e.kind())),
    }
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = TokioIo<MaybeTls>;
    type Error = ConnectFailure;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            if !this.0.base.same_origin(&uri) {
                return Err(ConnectFailure(HttpError::InvalidRequest("other origin")));
            }
            let deadline = this.0.cfg.timeouts.connect;
            match tokio::time::timeout(deadline, this.connect()).await {
                Ok(Ok(io)) => Ok(TokioIo::new(io)),
                Ok(Err(e)) => Err(ConnectFailure(e)),
                Err(_) => Err(ConnectFailure(HttpError::Timeout)),
            }
        })
    }
}

enum Io {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

/// A connection: TLS (or validated loopback plaintext) plus its handshake decision.
pub(crate) struct MaybeTls {
    io: Io,
    decision: Option<TrustDecision>,
}

impl Connection for MaybeTls {
    fn connected(&self) -> Connected {
        let c = Connected::new();
        match &self.decision {
            Some(d) => c.extra(d.clone()),
            None => c,
        }
    }
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            Io::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().io {
            Io::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            Io::Plain(s) => Pin::new(s).poll_flush(cx),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            Io::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
