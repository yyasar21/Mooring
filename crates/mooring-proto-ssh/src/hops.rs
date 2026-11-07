//! Jump hosts (ADR-0025 §2): a [`HopChain`] is SSH-over-SSH. Hop 0 is reached over TCP, every
//! later hop through a `direct-tcpip` channel of the previous one, and the target through one
//! more `direct-tcpip` of the last hop. No local listener: bytes stay inside the process.
//!
//! Every hop is a full SSH connection with its own host-key trust (`known_hosts`, TOFU or
//! mismatch hard stop), its own credentials (dropped after its auth round) and its own
//! keepalive. Progress reaches the UI as `SessionEvent::HopStatus`; prompts carry
//! `hop: Some(i)` and are answered through the chain's [`PromptBroker`]. A chain holds at
//! most [`MAX_HOPS`] hops and must be up within [`CHAIN_DEADLINE`].

use std::io;
use std::sync::Arc;
use std::time::Duration;

use mooring_core::session::{CloseCode, ConnectParams, HopState, SessionEvent};
use mooring_core::transport::{DialFuture, Dialed, Dialer};
use mooring_core::{validate_host, SessionAudit};
use russh::client::{Handle, Msg};
use russh::{ChannelStream, Disconnect};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::algos::client_config;
use crate::audit::AuditLog;
use crate::auth::{authenticate, AuthError, Credentials};
use crate::handler::ClientHandler;
use crate::session::SshOptions;
use crate::shared::{PromptBroker, Shared, HOP_PROMPT_ID_BASE};

#[path = "hop_stream.rs"]
mod hop_stream;
pub use hop_stream::HopStream;

/// Most hops in a chain (owner decision 31).
pub const MAX_HOPS: usize = 3;
/// Whole chain deadline: every hop up and the target channel open.
pub const CHAIN_DEADLINE: Duration = Duration::from_secs(90);

/// One jump host: where, how to log in, and its position.
pub struct Hop {
    /// Host, port, username and the vault-resolved secret of the hop (`become` is ignored).
    pub params: ConnectParams,
    /// Trust store, agent policy, keepalive and connect timeout of the hop.
    pub options: SshOptions,
    /// 0-based position in the chain.
    pub index: u8,
    /// The hop's connection id (or another safe label) for the audit log.
    pub connection: String,
}

impl std::fmt::Debug for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hop")
            .field("index", &self.index)
            .field("host", &self.params.host)
            .field("port", &self.params.port)
            .finish_non_exhaustive()
    }
}

/// Where the chain reports: the session's event channel, the broker that answers hop prompts
/// (ids from [`HOP_PROMPT_ID_BASE`] up) and the audit buffer trust / hop events go to.
#[derive(Debug, Clone)]
pub struct HopEvents {
    /// Event channel of the owning session.
    pub events: mpsc::Sender<SessionEvent>,
    /// Answers `Prompt { hop: Some(_) }` events.
    pub broker: PromptBroker,
    /// Trust, auth and `session.hop.*` events.
    pub audit: AuditLog,
}

impl HopEvents {
    /// A fresh event channel of `capacity`, a hop broker and an empty audit buffer.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<SessionEvent>) {
        let (events, rx) = mpsc::channel(capacity);
        let broker = PromptBroker::starting_after(HOP_PROMPT_ID_BASE);
        (Self { events, broker, audit: AuditLog::default() }, rx)
    }
}

/// Why a chain could not be opened. Never carries secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopError {
    /// The hop list or a hop's parameters were refused before any I/O.
    Invalid(&'static str),
    /// Hop `hop` failed: `code` is the hop's own close code (`network`, `auth_failed`,
    /// `trust_rejected`, `trust_mismatch`, ...); the session reports `hop_failed`.
    Failed {
        /// 0-based hop.
        hop: u8,
        /// What went wrong on that hop.
        code: CloseCode,
        /// Safe text.
        reason: String,
    },
    /// The user closed the session while a hop was being opened.
    Cancelled,
    /// [`CHAIN_DEADLINE`] passed.
    Deadline,
}

impl HopError {
    /// Safe text for `Closed.reason`.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid(r) => format!("jump host chain refused: {r}"),
            Self::Failed { hop, reason, .. } => format!("hop {} failed: {reason}", hop + 1),
            Self::Cancelled => "closed by user".to_owned(),
            Self::Deadline => "the jump host chain did not come up in time".to_owned(),
        }
    }

    /// The code the owning session closes with.
    #[must_use]
    pub const fn close_code(&self) -> CloseCode {
        match self {
            Self::Cancelled => CloseCode::User,
            Self::Invalid(_) | Self::Failed { .. } | Self::Deadline => CloseCode::HopFailed,
        }
    }
}

impl std::fmt::Display for HopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

impl std::error::Error for HopError {}

/// One open hop.
struct HopHandle {
    index: u8,
    connection: String,
    handle: Arc<Handle<ClientHandler>>,
}

/// An open chain. Kept alive by the session that uses it; `close` tears it down in reverse.
pub struct HopChain {
    hops: Vec<HopHandle>,
    audit: AuditLog,
    closed: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for HopChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopChain").field("hops", &self.hops.len()).finish_non_exhaustive()
    }
}

fn status(
    hop: u8,
    of: u8,
    host: &str,
    state: HopState,
    peer_identity: Option<String>,
) -> SessionEvent {
    SessionEvent::HopStatus { hop, of, state, host: host.to_owned(), peer_identity }
}

fn failed(hop: u8, code: CloseCode, reason: impl Into<String>) -> HopError {
    HopError::Failed { hop, code, reason: reason.into() }
}

/// `direct-tcpip` from `handle` to `host:port` (`host` is sent as given, the hop resolves it).
async fn open_channel(
    handle: &Handle<ClientHandler>,
    host: &str,
    port: u16,
) -> Result<ChannelStream<Msg>, russh::Error> {
    let ch = handle.channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0).await?;
    Ok(ch.into_stream())
}

impl HopChain {
    /// Open hop 0 over TCP, hops 1.. over `direct-tcpip` of the previous one, then one more
    /// `direct-tcpip` to `target`. Emits `HopStatus` per hop; prompts go through `ev.broker`.
    /// On failure every opened hop is closed again and nothing was sent to the target.
    pub async fn open(
        hops: Vec<Hop>,
        target: (&str, u16),
        ev: &HopEvents,
    ) -> Result<(Self, HopStream), HopError> {
        Self::open_inner(hops, target, ev, true)
            .await
            .and_then(|(c, s)| s.map(|s| (c, s)).ok_or(HopError::Invalid("no target stream")))
    }

    /// Like [`open`](Self::open) but stops after the last hop: the caller dials the target
    /// itself through the chain's [`Dialer`] (RDP, VNC and `mooring-http` connect again on
    /// every attempt). `target` is still validated so a bad leaf fails before any I/O.
    pub async fn open_hops(
        hops: Vec<Hop>,
        target: (&str, u16),
        ev: &HopEvents,
    ) -> Result<Self, HopError> {
        Self::open_inner(hops, target, ev, false).await.map(|(c, _)| c)
    }

    async fn open_inner(
        hops: Vec<Hop>,
        target: (&str, u16),
        ev: &HopEvents,
        to_target: bool,
    ) -> Result<(Self, Option<HopStream>), HopError> {
        if hops.is_empty() {
            return Err(HopError::Invalid("no jump host"));
        }
        if hops.len() > MAX_HOPS {
            return Err(HopError::Invalid("at most 3 jump hosts"));
        }
        if target.1 == 0 || validate_host(target.0).is_err() {
            return Err(HopError::Invalid("target host or port"));
        }
        for (i, h) in hops.iter().enumerate() {
            if usize::from(h.index) != i {
                return Err(HopError::Invalid("hop indices must be 0, 1, 2 in order"));
            }
            if h.params.port == 0 || validate_host(&h.params.host).is_err() {
                return Err(HopError::Invalid("hop host or port"));
            }
        }
        let mut chain = Self {
            hops: Vec::with_capacity(hops.len()),
            audit: ev.audit.clone(),
            closed: std::sync::atomic::AtomicBool::new(false),
        };
        let run = chain.open_all(hops, to_target.then_some(target), ev);
        match tokio::time::timeout(CHAIN_DEADLINE, run).await {
            Ok(Ok(stream)) => Ok((chain, stream)),
            Ok(Err(e)) => {
                chain.close_with("hop_failed").await;
                Err(e)
            }
            Err(_) => {
                chain.close_with("hop_failed").await;
                Err(HopError::Deadline)
            }
        }
    }

    async fn open_all(
        &mut self,
        hops: Vec<Hop>,
        target: Option<(&str, u16)>,
        ev: &HopEvents,
    ) -> Result<Option<HopStream>, HopError> {
        let of = u8::try_from(hops.len()).unwrap_or(u8::MAX);
        for hop in hops {
            let label = format!("{}:{}", hop.params.host, hop.params.port);
            let index = hop.index;
            let _ = ev.events.send(status(index, of, &label, HopState::Connecting, None)).await;
            let outcome = self.step(hop, of, ev).await;
            if let Err(HopError::Failed { .. }) = &outcome {
                let _ = ev.events.send(status(index, of, &label, HopState::Failed, None)).await;
            }
            outcome?;
        }
        let Some(target) = target else { return Ok(None) };
        let last = self.hops.last().ok_or(HopError::Invalid("no jump host"))?;
        let ch = open_channel(&last.handle, target.0, target.1).await.map_err(|e| {
            tracing::debug!(error = %e, "direct-tcpip to the target refused");
            failed(
                last.index,
                CloseCode::Network,
                "the jump host refused the connection to the target",
            )
        })?;
        Ok(Some(HopStream::Channel(ch)))
    }

    /// Reach one hop (TCP for hop 0, `direct-tcpip` of the previous hop otherwise), then
    /// handshake, trust and authentication.
    async fn step(&mut self, hop: Hop, of: u8, ev: &HopEvents) -> Result<(), HopError> {
        let index = hop.index;
        let stream = match self.hops.last() {
            None => {
                let addr = (hop.params.host.as_str(), hop.params.port);
                let tcp =
                    tokio::time::timeout(hop.options.connect_timeout, TcpStream::connect(addr))
                        .await
                        .map_err(|_| failed(index, CloseCode::Network, "connection timed out"))?
                        .map_err(|e| {
                            failed(
                                index,
                                CloseCode::Network,
                                format!("connection failed: {}", e.kind()),
                            )
                        })?;
                let _ = tcp.set_nodelay(true);
                HopStream::Tcp(tcp)
            }
            Some(prev) => {
                let ch = open_channel(&prev.handle, &hop.params.host, hop.params.port).await;
                HopStream::Channel(ch.map_err(|e| {
                    tracing::debug!(error = %e, hop = index, "direct-tcpip to the next hop refused");
                    failed(index, CloseCode::Network, "the previous jump host refused the connection")
                })?)
            }
        };
        self.open_one(hop, stream, of, ev).await
    }

    /// Handshake, trust and authentication of one hop over `stream`.
    async fn open_one(
        &mut self,
        hop: Hop,
        stream: HopStream,
        of: u8,
        ev: &HopEvents,
    ) -> Result<(), HopError> {
        let Hop { params, options, index, connection } = hop;
        let ConnectParams { host, port, username, secret, .. } = params;
        let user = match (&secret, username) {
            (_, Some(u)) if !u.is_empty() && !u.chars().any(char::is_control) => u,
            (mooring_core::session::ConnectSecret::Prompt(_), _) => String::new(),
            _ => return Err(failed(index, CloseCode::AuthFailed, "the jump host has no username")),
        };
        let shared = Arc::new(Shared::with_parts(
            ev.events.clone(),
            ev.broker.clone(),
            ev.audit.clone(),
            Some(index),
        ));
        let handler = ClientHandler::new(
            host.clone(),
            port,
            options.known_hosts_path.clone(),
            Arc::clone(&shared),
        );
        let config = Arc::new(client_config(options.keepalive, options.keepalive_max));
        let mut handle = match russh::client::connect_stream(config, stream, handler).await {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = %e, hop = index, "hop handshake failed");
                let (code, reason) = shared
                    .take_reason()
                    .unwrap_or_else(|| (CloseCode::Network, "connection failed".to_owned()));
                return Err(failed(index, code, reason));
            }
        };
        let up = SessionEvent::HopStatus {
            hop: index,
            of,
            state: HopState::Authenticating,
            host: format!("{host}:{port}"),
            peer_identity: shared.peer(),
        };
        let _ = ev.events.send(up).await;
        let creds = Credentials { user, secret, allow_agent: options.allow_agent };
        let method = match authenticate(&mut handle, creds, &shared).await {
            Ok(m) => m,
            Err(e) => {
                let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                return Err(match e {
                    AuthError::Cancelled | AuthError::PromptCancelled => HopError::Cancelled,
                    other => failed(index, other.code(), other.reason()),
                });
            }
        };
        self.audit.push(SessionAudit::HopOpened {
            hop: index,
            connection: connection.clone(),
            peer_identity: shared.peer(),
            auth_method: method,
        });
        let up = SessionEvent::HopStatus {
            hop: index,
            of,
            state: HopState::Up,
            host: format!("{host}:{port}"),
            peer_identity: shared.peer(),
        };
        let _ = ev.events.send(up).await;
        self.hops.push(HopHandle { index, connection, handle: Arc::new(handle) });
        Ok(())
    }

    /// Number of open hops.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// `true` when no hop is open (only after `close`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// The first hop whose SSH connection has gone away, if any (ADR-0025 `hop_lost`).
    #[must_use]
    pub fn lost_hop(&self) -> Option<u8> {
        self.hops.iter().find(|h| h.handle.is_closed()).map(|h| h.index)
    }

    /// Close every hop in reverse order and audit `session.hop.close { code }`. Idempotent.
    pub async fn close_with(&self, code: &'static str) {
        if self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        for h in self.hops.iter().rev() {
            let _ = h.handle.disconnect(Disconnect::ByApplication, "", "").await;
            self.audit.push(SessionAudit::HopClosed {
                hop: h.index,
                connection: h.connection.clone(),
                code,
            });
        }
    }

    /// Close every hop in reverse order (`closed`).
    pub async fn close(self) {
        self.close_with("closed").await;
    }
}

impl Dialer for HopChain {
    /// A new `direct-tcpip` of the last hop to `host:port` (RDP / VNC reconnect after a trust
    /// prompt, `mooring-http` connections).
    fn dial(self: Arc<Self>, host: &str, port: u16) -> DialFuture {
        let host = host.to_owned();
        Box::pin(async move {
            let last = self
                .hops
                .last()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "chain closed"))?;
            if last.handle.is_closed() {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "jump host lost"));
            }
            let ch = open_channel(&last.handle, &host, port).await.map_err(|e| {
                tracing::debug!(error = %e, "direct-tcpip through the chain refused");
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "the jump host refused the connection",
                )
            })?;
            Ok(Dialed { stream: Box::new(HopStream::Channel(ch)), local_addr: None })
        })
    }

    fn kind(&self) -> &'static str {
        "via"
    }
}

#[cfg(test)]
#[path = "hops_tests.rs"]
mod tests;
