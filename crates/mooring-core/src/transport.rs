//! How a protocol crate reaches its peer (ADR-0025 §2): a [`Dialer`] hands out a byte stream
//! for `host:port`. [`TcpDialer`] is the direct path; `mooring_proto_ssh::HopChain` is the
//! jump-host path (every target of a connection with `via` is a `direct-tcpip` channel of the
//! last hop, no local listener). RDP, VNC and `mooring-http` only ever see a [`BoxedStream`],
//! so a chain and a plain socket are the same to them.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Anything a protocol can run over.
pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> Stream for T {}

/// A type-erased byte stream (TCP, TLS or an SSH `direct-tcpip` channel).
pub type BoxedStream = Box<dyn Stream>;

/// A [`BoxedStream`] behind a concrete type. Generic code (`IronRDP`'s framing, hyper) that
/// holds the stream across `await`s inside a `select!` must see a nominal type: a bare
/// `Box<dyn Stream>` trips rustc's higher-ranked `Send` check there.
pub struct Erased(BoxedStream);

impl Erased {
    /// Wrap a boxed stream.
    #[must_use]
    pub fn new(stream: BoxedStream) -> Self {
        Self(stream)
    }
}

impl std::fmt::Debug for Erased {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Erased(stream)")
    }
}

impl AsyncRead for Erased {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Erased {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// A dialed connection.
pub struct Dialed {
    /// The stream.
    pub stream: BoxedStream,
    /// Our side of a TCP socket; `None` through a hop (the hop's address is not ours).
    pub local_addr: Option<SocketAddr>,
}

impl std::fmt::Debug for Dialed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialed").field("local_addr", &self.local_addr).finish_non_exhaustive()
    }
}

/// The future of one dial. It owns everything it needs (`'static`), so a caller's future
/// stays `Send` however it is combined (`select!` over a boxed `dyn Future` with a borrowed
/// lifetime trips rustc's higher-ranked `Send` check).
pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<Dialed>> + Send + 'static>>;

/// Opens a byte stream to `host:port`. Implemented by [`TcpDialer`] and by the SSH hop chain.
/// A dialer may be called more than once (RDP and VNC reconnect after a trust prompt).
pub trait Dialer: Send + Sync + std::fmt::Debug + 'static {
    /// Connect to `host:port`. Errors are `io::Error`s whose text is safe to log (kind only is
    /// shown to the user by the callers). Takes `Arc<Self>` so the future owns its dialer.
    fn dial(self: Arc<Self>, host: &str, port: u16) -> DialFuture;

    /// Short name for logs and the audit (`tcp` or `via`).
    fn kind(&self) -> &'static str;
}

/// Shared handle to a dialer.
pub type SharedDialer = Arc<dyn Dialer>;

/// Most resolved addresses tried for one host.
pub const MAX_ADDRS: usize = 8;

/// Direct TCP with a connect timeout and `TCP_NODELAY`. Every address of the host is tried in
/// turn (at most [`MAX_ADDRS`]), the whole dial bounded by `timeout`.
#[derive(Debug, Clone)]
pub struct TcpDialer {
    /// Whole-dial deadline (resolution + connect).
    pub timeout: Duration,
}

impl TcpDialer {
    /// A dialer with `timeout`.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Shared, boxed.
    #[must_use]
    pub fn shared(timeout: Duration) -> SharedDialer {
        Arc::new(Self::new(timeout))
    }

    async fn connect(host: String, port: u16) -> io::Result<Dialed> {
        let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for addr in addrs.take(MAX_ADDRS) {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    let local_addr = s.local_addr().ok();
                    return Ok(Dialed { stream: Box::new(s), local_addr });
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

impl Dialer for TcpDialer {
    fn dial(self: Arc<Self>, host: &str, port: u16) -> DialFuture {
        let host = host.to_owned();
        Box::pin(async move {
            tokio::time::timeout(self.timeout, Self::connect(host, port))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))?
        })
    }

    fn kind(&self) -> &'static str {
        "tcp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_dialer_connects_and_reports_local_addr() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.expect("read");
            s.write_all(&b).await.expect("write");
        });
        let d = Arc::new(TcpDialer::new(Duration::from_secs(5)));
        assert_eq!(d.kind(), "tcp");
        let mut got = Arc::clone(&d).dial("127.0.0.1", port).await.expect("dial");
        assert!(got.local_addr.is_some());
        got.stream.write_all(b"hi").await.expect("w");
        let mut b = [0u8; 2];
        got.stream.read_exact(&mut b).await.expect("r");
        assert_eq!(&b, b"hi");
    }

    #[tokio::test]
    async fn tcp_dialer_reports_refused_and_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let d = TcpDialer::shared(Duration::from_secs(5));
        assert!(Arc::clone(&d).dial("127.0.0.1", port).await.is_err());
        // RFC 5737 TEST-NET-1 never answers (or is unroutable in a sandbox): either way the
        // dial fails within the deadline, never hangs.
        let d = TcpDialer::shared(Duration::from_millis(50));
        let started = std::time::Instant::now();
        assert!(d.dial("192.0.2.1", 22).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
