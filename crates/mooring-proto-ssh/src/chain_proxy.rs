//! ADR-0025 §3: the SOCKS5 forward a web window behind jump hosts browses through.
//!
//! A `WebView` cannot consume an in-process stream, so this is the one loopback listener of a
//! chain: bound to `127.0.0.1` on a random port, SOCKS5 "no auth", `CONNECT` only (the same
//! front as a dynamic forward, [`crate::socks`]), each request a `direct-tcpip` channel of the
//! chain's **last** hop (host names are resolved there, so the page keeps its real name and
//! TLS validation is unchanged). It lives with the window: dropping or closing the proxy stops
//! the accept loop and every spliced connection (R-WEB-VIA).
//!
//! Review 9 L-48: CONNECTs are limited to a [`ProxyAllow`] list (the start URL's host and port
//! plus the hosts of the window's navigation allow-list); others get SOCKS reply `0x02`, are
//! counted, and the first [`MAX_AUDITED_REFUSALS`] are kept for the owner to audit.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

use crate::forward::MAX_CONNECTIONS_PER_FORWARD;
use crate::hops::HopChain;

/// Refused CONNECT targets kept for the audit log per proxy; later ones are only counted.
pub const MAX_AUDITED_REFUSALS: usize = 16;

/// The `host:port` pairs a [`ChainProxy`] may CONNECT to. Hosts compare case-insensitively,
/// without IPv6 brackets or a trailing dot; nothing else matches (no wildcards, no
/// resolution: the name the page asks for must be the listed name).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyAllow {
    targets: BTreeSet<(String, u16)>,
}

fn norm(host: &str) -> String {
    host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase()
}

impl ProxyAllow {
    /// An empty list (refuses everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `host:port`.
    pub fn allow(&mut self, host: &str, port: u16) {
        self.targets.insert((norm(host), port));
    }

    /// Whether `host:port` is allowed.
    #[must_use]
    pub fn permits(&self, host: &str, port: u16) -> bool {
        self.targets.contains(&(norm(host), port))
    }

    /// Number of allowed targets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Whether nothing is allowed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// The allow-list plus the refusal tally of one proxy.
#[derive(Debug)]
pub(crate) struct Gate {
    allow: ProxyAllow,
    refused: AtomicU64,
    /// Refused targets not yet taken, and how many were ever kept (≤ the cap).
    pending: Mutex<(Vec<String>, usize)>,
}

impl Gate {
    /// `true` when the CONNECT may proceed; a refusal is counted (and kept while under cap).
    pub(crate) fn admit(&self, host: &str, port: u16) -> bool {
        if self.allow.permits(host, port) {
            return true;
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("web SOCKS CONNECT outside the allow-list refused");
        if let Ok(mut p) = self.pending.lock() {
            if p.1 < MAX_AUDITED_REFUSALS {
                p.1 += 1;
                p.0.push(mooring_core::known_certs::host_key(host, port));
            }
        }
        false
    }
}

/// A running SOCKS5 proxy over a [`HopChain`].
pub struct ChainProxy {
    addr: SocketAddr,
    cancel: watch::Sender<bool>,
    limit: Arc<Semaphore>,
    gate: Arc<Gate>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for ChainProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainProxy").field("addr", &self.addr).finish_non_exhaustive()
    }
}

impl ChainProxy {
    /// Bind `127.0.0.1:0` and serve SOCKS5 through the last hop of `chain`, CONNECT limited
    /// to `allow`. Fails when the chain has no live hop or the bind fails.
    pub async fn open(chain: &HopChain, allow: ProxyAllow) -> io::Result<Self> {
        let handle = chain
            .last_handle()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "jump host lost"))?;
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let addr = listener.local_addr()?;
        let (cancel, rx) = watch::channel(false);
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_FORWARD));
        let gate = Arc::new(Gate {
            allow,
            refused: AtomicU64::new(0),
            pending: Mutex::new((Vec::new(), 0)),
        });
        let task = tokio::spawn(crate::forward_io::dynamic_loop(
            listener,
            handle,
            rx,
            Arc::clone(&limit),
            Some(Arc::clone(&gate)),
        ));
        Ok(Self { addr, cancel, limit, gate, task })
    }

    /// CONNECTs refused by the allow-list so far.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.gate.refused.load(Ordering::Relaxed)
    }

    /// Refused `host:port` targets not yet taken (at most [`MAX_AUDITED_REFUSALS`] over the
    /// proxy's life), for the owner's audit log.
    #[must_use]
    pub fn take_refused(&self) -> Vec<String> {
        self.gate.pending.lock().map(|mut p| std::mem::take(&mut p.0)).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_is_exact_and_refusals_are_capped() {
        let mut allow = ProxyAllow::new();
        allow.allow("App.Example.Test", 443);
        allow.allow("[2001:db8::1]", 8443);
        assert!(allow.permits("app.example.test.", 443));
        assert!(allow.permits("2001:db8::1", 8443));
        assert!(!allow.permits("app.example.test", 80));
        assert!(!allow.permits("x.app.example.test", 443));
        assert_eq!(allow.len(), 2);
        let gate = Gate { allow, refused: AtomicU64::new(0), pending: Mutex::new((Vec::new(), 0)) };
        assert!(gate.admit("APP.example.test", 443));
        for port in 1..=20 {
            assert!(!gate.admit("192.0.2.1", port));
        }
        assert_eq!(gate.refused.load(Ordering::Relaxed), 20);
        let kept = std::mem::take(&mut gate.pending.lock().expect("lock").0);
        assert_eq!(kept.len(), MAX_AUDITED_REFUSALS);
        assert_eq!(kept[0], "192.0.2.1:1");
        assert!(!gate.admit("192.0.2.1", 21));
        assert!(gate.pending.lock().expect("lock").0.is_empty(), "cap is over the proxy's life");
    }
}
