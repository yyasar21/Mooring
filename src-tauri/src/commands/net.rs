//! `net_tools` / `net_port_check` / `net_ping` / `net_traceroute` / `net_wg_show`
//! (ADR-0020 §6, A4 N1). Every command needs an unlocked vault (the target may come from a
//! connection, and a locked screen must not drive probes). The OS tools run through
//! `mooring_net::Runner` over the fixed path table of the running OS; at most
//! [`MAX_PROCESSES`] tool processes run at a time (`net.busy`), and port checks are rate
//! limited to one per [`NetRuntime::tcp_interval`] (`net.rate_limited`). Audit rows carry
//! host names and counts only, never tool output, and are bounded per process (review 7
//! N-52): the first [`NET_AUDITED`] runs of an hour of uptime get a row each, the rest are
//! counted and written as one `net_suppressed { count }` row when the next hour starts.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use mooring_audit::AuditEvent;
use mooring_core::Protocol;
use mooring_net::runner::{PingRun, Tools, TraceRun};
use mooring_net::tools::{DEFAULT_HOPS, DEFAULT_PING_COUNT, MAX_HOPS, MAX_PING_COUNT};
use mooring_net::{NetError, Os, Runner, Target, TcpResult, ToolPaths, WgStatus};
use serde::Deserialize;
use tauri::State;
use tokio::sync::Semaphore;

use crate::audit_budget::{AuditBudget, NET_AUDITED, WINDOW};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// OS-tool processes allowed at once.
pub const MAX_PROCESSES: usize = 2;
/// Default spacing between two port checks.
pub const TCP_INTERVAL: Duration = Duration::from_secs(1);

/// Runner, process cap and port-check rate limiter; one per app (`tauri::State`).
#[derive(Debug)]
pub struct NetRuntime {
    runner: Runner,
    procs: Semaphore,
    last_tcp: Mutex<Option<Instant>>,
    tcp_interval: Duration,
    budget: AuditBudget,
}

impl NetRuntime {
    /// The fixed path table of the running OS.
    #[must_use]
    pub fn production() -> Self {
        Self::with_paths(ToolPaths::for_os(Os::current()), TCP_INTERVAL)
    }

    /// A runtime over `paths` (tests: shims) with `tcp_interval` between port checks.
    #[must_use]
    pub fn with_paths(paths: ToolPaths, tcp_interval: Duration) -> Self {
        Self {
            runner: Runner::new(paths),
            procs: Semaphore::new(MAX_PROCESSES),
            last_tcp: Mutex::new(None),
            tcp_interval,
            budget: AuditBudget::new(NET_AUDITED, WINDOW),
        }
    }

    /// Write `event` within the per-process budget (N-52): its own row for the first
    /// [`NET_AUDITED`] of the hour, otherwise counted into the next `net_suppressed` row.
    fn audit(&self, state: &AppState, event: AuditEvent) {
        self.audit_at(state, event, Instant::now());
    }

    /// [`audit`](Self::audit) at a simulated `now` (tests).
    pub fn audit_at(&self, state: &AppState, event: AuditEvent, now: Instant) {
        let accounted = self.budget.account(now);
        if let Some(count) = accounted.summary {
            state.audit(AuditEvent::NetSuppressed { count });
        }
        if accounted.own_row {
            state.audit(event);
        } else {
            tracing::debug!("net audit row suppressed (budget)");
        }
    }

    /// Spacing between two port checks.
    #[must_use]
    pub fn tcp_interval(&self) -> Duration {
        self.tcp_interval
    }

    fn permit(&self) -> IpcResult<tokio::sync::SemaphorePermit<'_>> {
        self.procs.try_acquire().map_err(|_| {
            IpcError::new("net.busy", "two network tools are already running; wait for one")
        })
    }

    fn rate_check(&self) -> IpcResult<()> {
        let mut last = self.last_tcp.lock().map_err(|_| IpcError::poisoned())?;
        if last.is_some_and(|t| t.elapsed() < self.tcp_interval) {
            return Err(IpcError::new("net.rate_limited", "one port check per second"));
        }
        *last = Some(Instant::now());
        Ok(())
    }
}

/// `{ connectionId }` or `{ host, port? }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TargetArg {
    /// A stored connection's host (and port).
    #[serde(rename_all = "camelCase")]
    Connection {
        /// Connection id.
        connection_id: String,
    },
    /// A typed host, validated like a connection host and then as a `Target`.
    Host {
        /// Host name or IP literal.
        host: String,
        /// Port (port check only).
        #[serde(default)]
        port: Option<i64>,
    },
}

/// A resolved target: host, port when known, and the connection it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Validated host.
    pub target: Target,
    /// Port from the argument or the connection's effective port.
    pub port: Option<u16>,
}

fn net_error(e: &NetError) -> IpcError {
    match e {
        NetError::InvalidHost(reason) => IpcError::new("net.invalid_host", format!("invalid host: {reason}")),
        NetError::InvalidPort => IpcError::invalid("port", "must be 1..=65535"),
        NetError::ToolMissing => IpcError::new("net.tool_missing", "the tool is not installed at a known path"),
        NetError::PermissionDenied => IpcError::new("net.permission_denied", e.to_string()),
        NetError::Spawn | NetError::InvalidInterface => IpcError::new("net.spawn", "the tool could not be started"),
    }
}

fn port_arg(port: Option<i64>) -> IpcResult<Option<u16>> {
    port.map(|p| u16::try_from(p).ok().filter(|p| *p != 0).ok_or_else(|| IpcError::invalid("port", "must be 1..=65535")))
        .transpose()
}

/// Resolve the argument against the store (vault-gated). Kubernetes and vSphere-console
/// connections have no network host (ADR-0020 §7) and are refused with `net.invalid_host`.
pub fn resolve(state: &AppState, arg: &TargetArg) -> IpcResult<Resolved> {
    match arg {
        TargetArg::Host { host, port } => {
            state.with_ready(|_, _| Ok(()))?;
            let host = mooring_core::validate_host(host)?;
            let target = Target::parse(&host).map_err(|e| net_error(&e))?;
            Ok(Resolved { target, port: port_arg(*port)? })
        }
        TargetArg::Connection { connection_id } => {
            let id = dto::connection_id("connectionId", connection_id)?;
            let conn = state.with_ready(|_, store| Ok(store.get_connection(id)?))?;
            let (host, port) = match conn.protocol {
                Protocol::Ssh | Protocol::Rdp | Protocol::Vnc => (conn.host.clone(), conn.effective_port()),
                Protocol::Web => url_host(&conn.host)?,
                Protocol::Kubernetes | Protocol::VsphereConsole => {
                    return Err(IpcError::new("net.invalid_host", "this connection has no network host"));
                }
            };
            let target = Target::parse(&host).map_err(|e| net_error(&e))?;
            Ok(Resolved { target, port })
        }
    }
}

/// Host and port of a web connection's URL.
fn url_host(url: &str) -> IpcResult<(String, Option<u16>)> {
    let parsed = tauri::Url::parse(url).map_err(|_| IpcError::new("net.invalid_host", "the URL has no host"))?;
    let host = parsed
        .host_str()
        .map(|h| h.trim_matches(|c| c == '[' || c == ']').to_owned())
        .ok_or_else(|| IpcError::new("net.invalid_host", "the URL has no host"))?;
    Ok((host, parsed.port_or_known_default()))
}

/// `net_tools()`: which tools exist (the card greys missing buttons).
pub fn tools(state: &AppState, rt: &NetRuntime) -> IpcResult<Tools> {
    state.with_ready(|_, _| Ok(()))?;
    Ok(rt.runner.tools())
}

/// `net_port_check({ target, timeoutMs? })`.
pub async fn port_check(
    state: &AppState,
    rt: &NetRuntime,
    target: &TargetArg,
    timeout_ms: Option<i64>,
) -> IpcResult<TcpResult> {
    let r = resolve(state, target)?;
    let port = r.port.ok_or_else(|| IpcError::invalid("port", "required for a port check"))?;
    let timeout = match timeout_ms {
        None => mooring_net::tcp::DEFAULT_TIMEOUT,
        Some(ms) => Duration::from_millis(u64::try_from(ms).map_err(|_| IpcError::invalid("timeoutMs", "must be 100..=10000"))?),
    };
    rt.rate_check()?;
    let result = mooring_net::tcp_check(&r.target, port, timeout).await;
    let outcome = match &result {
        TcpResult::Open { .. } => "open",
        TcpResult::Closed => "closed",
        TcpResult::Timeout => "timeout",
        TcpResult::Unreachable => "unreachable",
        TcpResult::DnsFailed => "dns_failed",
    };
    rt.audit(state, AuditEvent::NetTcpCheck { host: r.target.to_string(), port, outcome: outcome.into() });
    Ok(result)
}

fn small(n: Option<i64>, default: u8, max: u8, field: &str) -> IpcResult<u8> {
    match n {
        None => Ok(default),
        Some(v) => u8::try_from(v)
            .ok()
            .filter(|v| (1..=max).contains(v))
            .ok_or_else(|| IpcError::invalid(field, &format!("must be 1..={max}"))),
    }
}

/// `net_ping({ target, count? })`.
pub async fn ping(state: &AppState, rt: &NetRuntime, target: &TargetArg, count: Option<i64>) -> IpcResult<PingRun> {
    let r = resolve(state, target)?;
    let count = small(count, DEFAULT_PING_COUNT, MAX_PING_COUNT, "count")?;
    let _permit = rt.permit()?;
    let run = rt.runner.ping(&r.target, count).await.map_err(|e| net_error(&e))?;
    rt.audit(state, AuditEvent::NetPing { host: r.target.to_string(), sent: run.result.sent, received: run.result.received });
    Ok(run)
}

/// `net_traceroute({ target, maxHops? })`.
pub async fn traceroute(
    state: &AppState,
    rt: &NetRuntime,
    target: &TargetArg,
    max_hops: Option<i64>,
) -> IpcResult<TraceRun> {
    let r = resolve(state, target)?;
    let max_hops = small(max_hops, DEFAULT_HOPS, MAX_HOPS, "maxHops")?;
    let _permit = rt.permit()?;
    let run = rt.runner.traceroute(&r.target, max_hops).await.map_err(|e| net_error(&e))?;
    let hops = u32::try_from(run.result.hops.len()).unwrap_or(u32::MAX);
    rt.audit(state, AuditEvent::NetTraceroute { host: r.target.to_string(), hops });
    Ok(run)
}

/// `net_wg_show()`: read-only `WireGuard` status.
pub async fn wg_show(state: &AppState, rt: &NetRuntime) -> IpcResult<WgStatus> {
    state.with_ready(|_, _| Ok(()))?;
    let _permit = rt.permit()?;
    let status = rt.runner.wg_status().await.map_err(|e| net_error(&e))?;
    let interfaces = status.interfaces.iter().map(|i| i.name.clone()).collect();
    rt.audit(state, AuditEvent::NetWgStatus { interfaces });
    Ok(status)
}

// ------------------------------------------------------------------ Tauri wrappers

/// `net_tools()`.
#[tauri::command]
pub fn net_tools(state: State<'_, AppState>, rt: State<'_, NetRuntime>) -> IpcResult<Tools> {
    tools(&state, &rt)
}

/// `net_port_check({ target, timeoutMs })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn net_port_check(
    state: State<'_, AppState>,
    rt: State<'_, NetRuntime>,
    target: TargetArg,
    timeout_ms: Option<i64>,
) -> IpcResult<TcpResult> {
    port_check(&state, &rt, &target, timeout_ms).await
}

/// `net_ping({ target, count })`.
#[tauri::command]
pub async fn net_ping(
    state: State<'_, AppState>,
    rt: State<'_, NetRuntime>,
    target: TargetArg,
    count: Option<i64>,
) -> IpcResult<PingRun> {
    ping(&state, &rt, &target, count).await
}

/// `net_traceroute({ target, maxHops })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn net_traceroute(
    state: State<'_, AppState>,
    rt: State<'_, NetRuntime>,
    target: TargetArg,
    max_hops: Option<i64>,
) -> IpcResult<TraceRun> {
    traceroute(&state, &rt, &target, max_hops).await
}

/// `net_wg_show()`.
#[tauri::command]
pub async fn net_wg_show(state: State<'_, AppState>, rt: State<'_, NetRuntime>) -> IpcResult<WgStatus> {
    wg_show(&state, &rt).await
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
