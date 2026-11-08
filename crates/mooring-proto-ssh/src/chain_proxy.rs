//! ADR-0025 §3: the SOCKS5 forward a web window behind jump hosts browses through.
//!
//! A `WebView` cannot consume an in-process stream, so this is the one loopback listener of a
//! chain: bound to `127.0.0.1` on a random port, SOCKS5 "no auth", `CONNECT` only (the same
//! front as a dynamic forward, [`crate::socks`]), each request a `direct-tcpip` channel of the
//! chain's **last** hop (host names are resolved there, so the page keeps its real name and
//! TLS validation is unchanged). It lives with the window: dropping or closing the proxy stops
//! the accept loop and every spliced connection (R-WEB-VIA).

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

use crate::forward::MAX_CONNECTIONS_PER_FORWARD;
use crate::hops::HopChain;

/// A running SOCKS5 proxy over a [`HopChain`].
pub struct ChainProxy {
    addr: SocketAddr,
    cancel: watch::Sender<bool>,
    limit: Arc<Semaphore>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for ChainProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainProxy").field("addr", &self.addr).finish_non_exhaustive()
    }
}

impl ChainProxy {
    /// Bind `127.0.0.1:0` and serve SOCKS5 through the last hop of `chain`. Fails when the
    /// chain has no live hop or the bind fails.
    pub async fn open(chain: &HopChain) -> io::Result<Self> {
        let handle = chain
            .last_handle()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "jump host lost"))?;
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let addr = listener.local_addr()?;
        let (cancel, rx) = watch::channel(false);
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_FORWARD));
        let task =
            tokio::spawn(crate::forward_io::dynamic_loop(listener, handle, rx, Arc::clone(&limit)));
        Ok(Self { addr, cancel, limit, task })
    }

    /// The bound loopback address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `socks5://127.0.0.1:<port>` for `WebviewWindowBuilder::proxy_url`.
    #[must_use]
    pub fn url(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    /// Connections being served right now.
    #[must_use]
    pub fn connections(&self) -> usize {
        MAX_CONNECTIONS_PER_FORWARD.saturating_sub(self.limit.available_permits())
    }

    /// Stop accepting and end every spliced connection. Idempotent.
    pub fn close(&self) {
        let _ = self.cancel.send(true);
        self.task.abort();
    }

    /// Whether [`close`](Self::close) ran (or the accept loop ended).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.cancel.borrow() || self.task.is_finished()
    }
}

impl Drop for ChainProxy {
    fn drop(&mut self) {
        self.close();
    }
}
