//! ADR-0025 §3: a web connection with `via` browses through a SOCKS5 forward on the last hop
//! of its own jump-host chain. The chain opens **before** the window exists (the window is
//! built with `proxy_url`, so not one request leaves directly), lives in the window's
//! registry entry, and is closed with the window. The listener is the only loopback port a
//! chain has (R-WEB-VIA): `127.0.0.1`, random port, no auth, audited
//! `forward_opened { reason: web_via }`. Review 9 L-48: it CONNECTs only to the start URL's
//! host and the hosts of the navigation allow-list (ports 80, 443, their own and the start
//! port); other targets are refused with SOCKS `0x02` and the first 16 audited
//! `forward_refused`.
//!
//! The chain opens unattended: the web channel has no prompt answer path, so a hop that asks
//! (an unknown host key, keyboard-interactive, a `prompt` credential) ends the open with
//! `session.hop_failed`, never with a guessed answer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::session::SessionEvent;
use mooring_core::{CloseCode, Protocol};
use mooring_proto_ssh::{ChainProxy, Hop, HopChain, HopEvents, ProxyAllow};
use tauri::Url;

use super::policy::NavPolicy;
use super::StorageOs;
use crate::error::{IpcError, IpcResult};
use crate::state::{record_audit, AppState};

/// `forward_opened.id` and `reason` of the web SOCKS forward.
pub const FORWARD_ID: &str = "web-via";
/// See [`FORWARD_ID`].
pub const REASON: &str = "web_via";

/// macOS needs Tauri's `macos-proxy` feature (and macOS 14) for `proxy_url`; without the
/// feature the setting is silently ignored, which would send the page around the chain. The
/// feature is not enabled in this build (`src-tauri/Cargo.toml`, orchestrator), so macOS
/// refuses. Flip this together with the feature.
pub const MACOS_PROXY_FEATURE: bool = false;

/// Whether this OS can put a web window behind a proxy (`web.via_unsupported` otherwise).
pub fn supported(os: StorageOs) -> IpcResult<()> {
    match os {
        StorageOs::Windows | StorageOs::Linux => Ok(()),
        StorageOs::MacOs { major } if MACOS_PROXY_FEATURE && major >= 14 => Ok(()),
        StorageOs::MacOs { .. } => Err(IpcError::new(
            "web.via_unsupported",
            "web pages through jump hosts need macOS 14 and a build with proxy support",
        )),
    }
}

/// `host` and port of the start URL, as the last hop dials them (IPv6 without brackets).
pub fn target_of(url: &Url) -> IpcResult<(String, u16)> {
    let host = url.host_str().ok_or_else(|| IpcError::invalid("url", "no host"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    let port = url.port_or_known_default().ok_or_else(|| IpcError::invalid("url", "no port"))?;
    Ok((host, port))
}

/// Review 9 L-48: the CONNECT targets of a web window's SOCKS forward — the start URL's host
/// and every allowed origin's host, each on ports 80, 443, its own port and the start port.
pub fn proxy_allow(url: &Url, policy: &NavPolicy) -> ProxyAllow {
    let mut allow = ProxyAllow::new();
    let start_port = target_of(url).ok().map(|(_, p)| p);
    let origins = policy.allowed().iter().filter_map(|o| Url::parse(o).ok());
    for u in std::iter::once(url.clone()).chain(origins) {
        if let Ok((host, port)) = target_of(&u) {
            for p in [80, 443, port].into_iter().chain(start_port) {
                allow.allow(&host, p);
            }
        }
    }
    allow
}

fn hop_failed(reason: String) -> IpcError {
    IpcError::new("session.hop_failed", reason)
}

/// Open `hops` towards `target` without a human: progress is logged, the first prompt shuts
/// the broker (the pending question resolves as "no answer") and the open fails.
pub async fn open_chain(
    hops: Vec<Hop>,
    target: (&str, u16),
    audit: &mooring_proto_ssh::AuditLog,
) -> IpcResult<HopChain> {
    let (ev, mut events) = HopEvents::new(64);
    let ev = HopEvents { audit: audit.clone(), ..ev };
    let broker = ev.broker.clone();
    let opening = HopChain::open_hops(hops, target, &ev);
    tokio::pin!(opening);
    let mut asked: Option<u8> = None;
    loop {
        tokio::select! {
            r = &mut opening => {
                return r.map_err(|e| match asked {
                    Some(hop) => hop_failed(format!(
                        "jump host {} asked a question a web window cannot answer (an unknown host key or a password); open it once as an SSH session, then try again",
                        hop + 1
                    )),
                    None => hop_failed(e.reason()),
                });
            }
            Some(e) = events.recv() => match e {
                SessionEvent::Prompt { hop, .. } => {
                    asked.get_or_insert(hop.unwrap_or(0));
                    broker.shutdown();
                }
                SessionEvent::HopStatus { hop, state, .. } => {
                    tracing::info!(hop, ?state, "web jump host");
                }
                _ => {}
            },
        }
    }
}

/// The chain and SOCKS forward of one web window.
pub struct WebVia {
    connection: String,
    chain: Arc<HopChain>,
    proxy: ChainProxy,
    hop_audit: mooring_proto_ssh::AuditLog,
    closed: AtomicBool,
}

impl std::fmt::Debug for WebVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebVia").field("hops", &self.chain.len()).finish_non_exhaustive()
    }
}

impl WebVia {
    /// Put the SOCKS forward on `chain` and audit the hops and `forward_opened`.
    pub async fn start(
        audit: &Mutex<AuditLog>,
        connection: &str,
        chain: HopChain,
        hop_audit: mooring_proto_ssh::AuditLog,
        allow: ProxyAllow,
    ) -> IpcResult<Self> {
        let proxy = match ChainProxy::open(&chain, allow).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(kind = ?e.kind(), "web SOCKS forward not opened");
                chain.close_with("hop_failed").await;
                flush(audit, connection, &hop_audit);
                return Err(hop_failed("the web forward through the jump hosts could not be opened".to_owned()));
            }
        };
        flush(audit, connection, &hop_audit);
        record_audit(audit, AuditEvent::ForwardOpened {
            connection: connection.to_owned(),
            id: FORWARD_ID.to_owned(),
            kind: "dynamic".to_owned(),
            bind: proxy.addr().to_string(),
            target: "socks5".to_owned(),
            exposure: "loopback".to_owned(),
            reason: Some(REASON.to_owned()),
        });
        Ok(Self { connection: connection.to_owned(), chain: Arc::new(chain), proxy, hop_audit, closed: AtomicBool::new(false) })
    }

    /// `socks5://127.0.0.1:<port>` for the window builder.
    pub fn proxy_url(&self) -> IpcResult<Url> {
        Url::parse(&self.proxy.url()).map_err(|_| IpcError::new("window.failed", "the web forward address is not a URL"))
    }

    /// Hops in the chain.
    pub fn hops(&self) -> u8 {
        u8::try_from(self.chain.len()).unwrap_or(u8::MAX)
    }

    /// The first lost hop, if any (the window's watch closes it, `hop_lost`).
    pub fn lost_hop(&self) -> Option<u8> {
        self.chain.lost_hop()
    }

    /// Stop the forward and close the chain (`code`: `closed` | `hop_lost`), audit
    /// `forward_closed` and the hop closes. Idempotent.
    pub async fn shutdown(&self, audit: &Mutex<AuditLog>, code: &'static str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.proxy.close();
        self.audit_refused(audit);
        record_audit(audit, AuditEvent::ForwardClosed {
            connection: self.connection.clone(),
            id: FORWARD_ID.to_owned(),
            kind: "dynamic".to_owned(),
            bind: self.proxy.addr().to_string(),
            target: "socks5".to_owned(),
            reason: Some(REASON.to_owned()),
        });
        self.chain.close_with(code).await;
        flush(audit, &self.connection, &self.hop_audit);
    }

    /// Audit the CONNECTs the allow-list refused since the last call (at most 16 per window).
    pub fn audit_refused(&self, audit: &Mutex<AuditLog>) {
        for target in self.proxy.take_refused() {
            record_audit(audit, AuditEvent::ForwardRefused {
                connection: self.connection.clone(),
                id: FORWARD_ID.to_owned(),
                target,
            });
        }
    }

    /// CONNECTs refused so far (counted past the audit cap).
    pub fn refused(&self) -> u64 {
        self.proxy.refused()
    }

    /// [`shutdown`](Self::shutdown) off the caller (window events are synchronous).
    pub fn shutdown_later(self: Arc<Self>, audit: Arc<Mutex<AuditLog>>, code: &'static str) {
        self.proxy.close();
        tauri::async_runtime::spawn(async move { self.shutdown(&audit, code).await });
    }
}

fn flush(audit: &Mutex<AuditLog>, connection: &str, hop_audit: &mooring_proto_ssh::AuditLog) {
    let events = hop_audit.take();
    if !events.is_empty() {
        crate::session_audit::audit_session(audit, connection, Protocol::Web, events);
    }
}

/// Resolve the hops of web connection `connection_id` (their own credentials, audited
/// `credential_used`), open the chain unattended and put the SOCKS forward on it, limited to
/// [`proxy_allow`] of `url` and `policy`.
pub async fn open(state: &AppState, connection_id: &str, url: &Url, policy: &NavPolicy) -> IpcResult<WebVia> {
    let id = crate::dto::connection_id("connectionId", connection_id)?;
    let mut used = Vec::new();
    let plans = state.with_ready(|vault, store| {
        let c = store.get_connection(id)?;
        crate::commands::connect_plan::hops_of(store, vault, &c, &mut used)
    })?;
    for cred in used {
        state.audit(AuditEvent::CredentialUsed {
            credential: cred,
            purpose: "connect".to_owned(),
            connection: Some(connection_id.to_owned()),
        });
    }
    let hops = crate::commands::sessions::hop_settings(state).hops(plans);
    let (host, port) = target_of(url)?;
    let hop_audit = mooring_proto_ssh::AuditLog::default();
    let chain = match open_chain(hops, (&host, port), &hop_audit).await {
        Ok(c) => c,
        Err(e) => {
            flush(&state.audit, connection_id, &hop_audit);
            return Err(e);
        }
    };
    WebVia::start(&state.audit, connection_id, chain, hop_audit, proxy_allow(url, policy)).await
}

/// Watch `via` once a second; a lost hop closes the window through `destroy` (its
/// `Destroyed` event then forgets the entry). Ends when the entry is gone.
pub fn watch(via: &Arc<WebVia>, audit: Arc<Mutex<AuditLog>>, destroy: impl Fn() + Send + 'static) {
    let weak = Arc::downgrade(via);
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let Some(via) = weak.upgrade() else { return };
            if via.closed.load(Ordering::Acquire) {
                return;
            }
            via.audit_refused(&audit);
            if let Some(hop) = via.lost_hop() {
                tracing::warn!(hop, code = ?CloseCode::HopLost, "web jump host lost; closing the window");
                via.shutdown(&audit, "hop_lost").await;
                destroy();
                return;
            }
        }
    });
}

#[cfg(test)]
#[path = "via_tests.rs"]
mod tests;
