//! Port forwarding (ADR-0007 §Channels and flow): local (`-L`), remote (`-R`) and dynamic
//! SOCKS5 (`-D`) forwards on top of the authenticated russh handle.
//!
//! Every forward has a session-local [`ForwardId`], is listed by [`SshSession::forwards`],
//! audits `session.forward.open` / `session.forward.close`, and is closed with the session.
//! Each forward accepts at most [`MAX_CONNECTIONS_PER_FORWARD`] concurrent connections and
//! copies through fixed [`COPY_BUFFER`]-sized buffers, so memory per forward is bounded.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use mooring_core::{validate_host, MooringError};
use russh::client::Handle;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

use crate::audit::{AuditLog, TrustEvent};
use crate::forward_io::{dynamic_loop, local_loop, Route};
use crate::handler::ClientHandler;
use crate::session::SshSession;

/// Most forwards one session may hold at a time.
pub const MAX_FORWARDS: usize = 64;
/// Most concurrent connections through one forward; further connections are dropped.
pub const MAX_CONNECTIONS_PER_FORWARD: usize = 128;
/// Copy buffer per direction per connection.
pub const COPY_BUFFER: usize = 32 * 1024;

/// Session-local forward id, shown as `fwd-<n>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForwardId(u64);

impl ForwardId {
    /// The numeric id.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ForwardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fwd-{}", self.0)
    }
}

/// Which way a forward runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    /// Local listener → `direct-tcpip` to a target reached from the server.
    Local,
    /// Server listener (`tcpip-forward`) → a target reached from this machine.
    Remote,
    /// Local SOCKS5 listener → `direct-tcpip` to the requested target.
    Dynamic,
}

impl ForwardKind {
    /// Stable name for audit and UI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Dynamic => "dynamic",
        }
    }
}

/// A live forward as listed by [`SshSession::forwards`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    /// Id.
    pub id: ForwardId,
    /// Kind.
    pub kind: ForwardKind,
    /// Bound address: local for local/dynamic, server side for remote.
    pub bind: String,
    /// Bound port (the allocated one when port 0 was requested).
    pub port: u16,
    /// Target `host:port`, or `socks5` for dynamic forwards.
    pub target: String,
}

/// `host:port`, bracketing IPv6 literals.
pub(crate) fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) struct Entry {
    info: ForwardInfo,
    cancel: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    /// Remote forwards: (requested address, bound port, route for incoming channels).
    remote: Option<(String, u32, Route)>,
}

impl Entry {
    /// Stop the listener and every connection of this forward, and audit the close.
    fn shutdown(self, audit: &AuditLog) {
        let _ = self.cancel.send(true);
        if let Some(task) = self.task {
            task.abort();
        }
        let ForwardInfo { id, kind, bind, target, .. } = self.info;
        audit.push(TrustEvent::ForwardClosed {
            id: id.to_string(),
            kind: kind.as_str(),
            bind,
            target,
        });
    }
}

#[derive(Default)]
struct State {
    entries: HashMap<u64, Entry>,
    closed: bool,
}

/// All forwards of one session. Lives in `Shared` so the handler can route incoming
/// `forwarded-tcpip` channels and the driver can close everything when the session ends.
#[derive(Default)]
pub(crate) struct ForwardRegistry {
    next: AtomicU64,
    state: Mutex<State>,
}

impl fmt::Debug for ForwardRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("ForwardRegistry")
            .field("forwards", &state.entries.len())
            .field("closed", &state.closed)
            .finish()
    }
}

impl ForwardRegistry {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_id(&self) -> ForwardId {
        ForwardId(self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1))
    }

    /// Register a started forward. On refusal (session closing, too many forwards) the
    /// forward is stopped without an audit event, since it never opened.
    fn insert(&self, entry: Entry, audit: &AuditLog) -> Result<ForwardId, MooringError> {
        let mut state = self.lock();
        let refusal = if state.closed {
            Some(MooringError::Closed)
        } else if state.entries.len() >= MAX_FORWARDS {
            Some(MooringError::Invalid {
                field: "forward",
                reason: format!("at most {MAX_FORWARDS} forwards per session"),
            })
        } else {
            None
        };
        if let Some(err) = refusal {
            drop(state);
            let _ = entry.cancel.send(true);
            if let Some(task) = entry.task {
                task.abort();
            }
            return Err(err);
        }
        let ForwardInfo { id, kind, bind, target, .. } = entry.info.clone();
        state.entries.insert(id.0, entry);
        drop(state);
        audit.push(TrustEvent::ForwardOpened {
            id: id.to_string(),
            kind: kind.as_str(),
            bind,
            target,
        });
        Ok(id)
    }

    fn remove(&self, id: ForwardId) -> Option<Entry> {
        self.lock().entries.remove(&id.0)
    }

    pub(crate) fn list(&self) -> Vec<ForwardInfo> {
        let mut list: Vec<_> = self.lock().entries.values().map(|e| e.info.clone()).collect();
        list.sort_by_key(|i| i.id);
        list
    }

    /// Route for a `forwarded-tcpip` channel the server opened. Exact (address, port) match
    /// first; servers that rewrite the address are matched by port when that is unique.
    pub(crate) fn route(&self, address: &str, port: u32) -> Option<Route> {
        let state = self.lock();
        let remotes = || state.entries.values().filter_map(|e| e.remote.as_ref());
        if let Some((_, _, route)) = remotes().find(|(a, p, _)| a == address && *p == port) {
            return Some(route.clone());
        }
        let mut by_port = remotes().filter(|(_, p, _)| *p == port);
        match (by_port.next(), by_port.next()) {
            (Some((_, _, route)), None) => Some(route.clone()),
            _ => None,
        }
    }

    /// Close every forward and refuse new ones. Idempotent.
    pub(crate) fn close_all(&self, audit: &AuditLog) {
        let entries: Vec<Entry> = {
            let mut state = self.lock();
            state.closed = true;
            let mut entries: Vec<_> = state.entries.drain().map(|(_, e)| e).collect();
            entries.sort_by_key(|e| e.info.id);
            entries
        };
        for entry in entries {
            entry.shutdown(audit);
        }
    }
}

fn not_connected() -> MooringError {
    MooringError::Protocol { protocol: "ssh", reason: "not connected".to_owned() }
}

fn validate_target(host: &str, port: u16) -> Result<String, MooringError> {
    if port == 0 {
        return Err(MooringError::Invalid {
            field: "target port",
            reason: "must be 1-65535".into(),
        });
    }
    validate_host(host)
}

async fn bind(addr: SocketAddr) -> Result<(TcpListener, SocketAddr), MooringError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| MooringError::Transport(format!("bind failed: {}", e.kind())))?;
    let bound = listener
        .local_addr()
        .map_err(|e| MooringError::Transport(format!("bind failed: {}", e.kind())))?;
    Ok((listener, bound))
}

impl SshSession {
    /// The authenticated handle, or an error when the session is not (or no longer) usable.
    pub(crate) fn live_handle(&self) -> Result<Arc<Handle<ClientHandler>>, MooringError> {
        if self.shared.is_closing() {
            return Err(MooringError::Closed);
        }
        self.handle().ok_or_else(not_connected)
    }

    fn start(
        &self,
        kind: ForwardKind,
        bound: SocketAddr,
        target: String,
        task: impl FnOnce(watch::Receiver<bool>) -> JoinHandle<()>,
    ) -> Result<ForwardId, MooringError> {
        let registry = &self.shared.forwards;
        let id = registry.next_id();
        let (cancel, cancel_rx) = watch::channel(false);
        let task = Some(task(cancel_rx));
        let info = ForwardInfo { id, kind, bind: bound.to_string(), port: bound.port(), target };
        registry.insert(Entry { info, cancel, task, remote: None }, &self.shared.audit)
    }

    /// Listen on `bind` and tunnel each accepted connection to `target` as seen from the
    /// server (`direct-tcpip`). Port 0 picks a free port; see [`ForwardInfo::port`].
    pub async fn forward_local(
        &self,
        bind_addr: SocketAddr,
        target: (String, u16),
    ) -> Result<ForwardId, MooringError> {
        let handle = self.live_handle()?;
        let host = validate_target(&target.0, target.1)?;
        let port = target.1;
        let (listener, bound) = bind(bind_addr).await?;
        let shown = host_port(&host, port);
        self.start(ForwardKind::Local, bound, shown, move |cancel| {
            tokio::spawn(local_loop(listener, handle, host, port, cancel))
        })
    }

    /// Run a SOCKS5 proxy (no auth, CONNECT only) on `bind`; each request becomes a
    /// `direct-tcpip` channel. Binds other than loopback are refused unless
    /// `allow_external` is true, because anyone who reaches the port uses the tunnel.
    pub async fn forward_dynamic(
        &self,
        bind_addr: SocketAddr,
        allow_external: bool,
    ) -> Result<ForwardId, MooringError> {
        if !allow_external && !bind_addr.ip().is_loopback() {
            return Err(MooringError::Invalid {
                field: "bind",
                reason: "dynamic forwards bind to loopback unless external access is allowed"
                    .into(),
            });
        }
        let handle = self.live_handle()?;
        let (listener, bound) = bind(bind_addr).await?;
        self.start(ForwardKind::Dynamic, bound, "socks5".to_owned(), move |cancel| {
            tokio::spawn(dynamic_loop(listener, handle, cancel))
        })
    }

    /// Ask the server to listen on `remote_bind` (`tcpip-forward`); each connection it
    /// accepts is connected to `target` from this machine. Port 0 lets the server choose.
    pub async fn forward_remote(
        &self,
        remote_bind: (String, u16),
        target: SocketAddr,
    ) -> Result<ForwardId, MooringError> {
        let handle = self.live_handle()?;
        let address = validate_host(&remote_bind.0)?;
        let allocated =
            handle.tcpip_forward(address.clone(), u32::from(remote_bind.1)).await.map_err(|e| {
                tracing::debug!(error = %e, "tcpip-forward refused");
                MooringError::Protocol { protocol: "ssh", reason: "remote forward refused".into() }
            })?;
        let port = if remote_bind.1 == 0 {
            u16::try_from(allocated).ok().filter(|p| *p != 0).ok_or_else(|| {
                MooringError::Protocol {
                    protocol: "ssh",
                    reason: "server allocated no port".into(),
                }
            })?
        } else {
            remote_bind.1
        };
        let registry = &self.shared.forwards;
        let id = registry.next_id();
        let (cancel, cancel_rx) = watch::channel(false);
        let route = Route {
            target,
            cancel: cancel_rx,
            limit: Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_FORWARD)),
        };
        let info = ForwardInfo {
            id,
            kind: ForwardKind::Remote,
            bind: host_port(&address, port),
            port,
            target: target.to_string(),
        };
        let remote = Some((address.clone(), u32::from(port), route));
        let entry = Entry { info, cancel, task: None, remote };
        let result = registry.insert(entry, &self.shared.audit);
        if result.is_err() {
            let _ = handle.cancel_tcpip_forward(address, u32::from(port)).await;
        }
        result
    }

    /// Stop one forward: its listener and all of its connections.
    pub async fn forward_close(&self, id: ForwardId) -> Result<(), MooringError> {
        let entry = self
            .shared
            .forwards
            .remove(id)
            .ok_or_else(|| MooringError::NotFound { kind: "forward", id: id.to_string() })?;
        let remote = entry.remote.as_ref().map(|(a, p, _)| (a.clone(), *p));
        entry.shutdown(&self.shared.audit);
        if let (Some((address, port)), Ok(handle)) = (remote, self.live_handle()) {
            if let Err(e) = handle.cancel_tcpip_forward(address, port).await {
                tracing::debug!(error = %e, "cancel-tcpip-forward failed");
            }
        }
        Ok(())
    }

    /// Live forwards, ordered by id.
    pub fn forwards(&self) -> Vec<ForwardInfo> {
        self.shared.forwards.list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(registry: &ForwardRegistry, remote: Option<(&str, u32)>) -> Entry {
        let (cancel, rx) = watch::channel(false);
        let id = registry.next_id();
        let route = Route {
            target: SocketAddr::from(([127, 0, 0, 1], 9)),
            cancel: rx,
            limit: Arc::new(Semaphore::new(1)),
        };
        Entry {
            info: ForwardInfo {
                id,
                kind: ForwardKind::Remote,
                bind: "b".into(),
                port: 1,
                target: "t".into(),
            },
            cancel,
            task: None,
            remote: remote.map(|(a, p)| (a.to_owned(), p, route)),
        }
    }

    #[test]
    fn ids_display_and_order() {
        let r = ForwardRegistry::default();
        let (a, b) = (r.next_id(), r.next_id());
        assert_eq!(a.to_string(), "fwd-1");
        assert!(a < b);
        assert_eq!(b.get(), 2);
        assert_eq!(host_port("::1", 22), "[::1]:22");
        assert_eq!(host_port("h", 22), "h:22");
    }

    #[test]
    fn routes_and_close_all() {
        let r = ForwardRegistry::default();
        let audit = AuditLog::default();
        r.insert(entry(&r, Some(("127.0.0.1", 4000))), &audit).expect("insert");
        r.insert(entry(&r, Some(("localhost", 4001))), &audit).expect("insert");
        assert!(r.route("127.0.0.1", 4000).is_some());
        assert!(r.route("0.0.0.0", 4001).is_some(), "unique port fallback");
        assert!(r.route("127.0.0.1", 4002).is_none());
        assert_eq!(r.list().len(), 2);
        r.close_all(&audit);
        r.close_all(&audit);
        assert!(r.list().is_empty());
        let actions: Vec<_> = audit.take().iter().map(TrustEvent::action).collect();
        assert_eq!(actions.iter().filter(|a| **a == "session.forward.close").count(), 2);
        assert!(matches!(r.insert(entry(&r, None), &audit), Err(MooringError::Closed)));
    }

    #[test]
    fn caps_forward_count() {
        let r = ForwardRegistry::default();
        let audit = AuditLog::default();
        for _ in 0..MAX_FORWARDS {
            r.insert(entry(&r, None), &audit).expect("insert");
        }
        assert!(matches!(r.insert(entry(&r, None), &audit), Err(MooringError::Invalid { .. })));
    }
}
