//! `syslog_get` / `syslog_set` / `syslog_test` (ADR-0010 item 5). The configuration is stored
//! as JSON under `app.syslog`; the running mirror lives inside the audit log
//! (`AuditLog::set_mirror`), so every entry written anywhere in the app is mirrored.
//!
//! All three commands require an unlocked vault: the collector host is inventory, and
//! redirecting the mirror must not be possible from a locked screen.

use mooring_audit::syslog::{send_test, SyslogConfig, SyslogMirror, TlsRoots, Transport};
use mooring_audit::AuditEvent;
use serde::Serialize;
use tauri::State;

use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Setting key.
pub const KEY: &str = "app.syslog";

/// `syslog_get` result: the configuration plus mirror counters (telemetry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyslogStatus {
    /// Stored configuration.
    #[serde(flatten)]
    pub config: SyslogConfig,
    /// Whether a mirror is running now.
    pub running: bool,
    /// Messages lost since the mirror started (`syslog_dropped`).
    pub dropped: u64,
    /// Messages delivered since the mirror started.
    pub sent: u64,
}

/// `syslog_test` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestResult {
    /// Delivered (for UDP: sent without a local error).
    pub ok: bool,
    /// Safe error text.
    pub error: Option<String>,
}

fn syslog_error(e: &mooring_audit::syslog::SyslogError) -> IpcError {
    match e {
        mooring_audit::syslog::SyslogError::Invalid { field, reason } => {
            IpcError::invalid(field, reason)
        }
        other => IpcError::new("syslog.failed", other.to_string()),
    }
}

/// This machine's name for the syslog `HOSTNAME` field (`-` when unknown).
pub fn local_hostname() -> String {
    sysinfo::System::host_name().unwrap_or_default()
}

/// Validate IPC input into a config. Numbers arrive as `i64` so out-of-range values get a
/// typed `input.invalid` instead of a deserialisation failure.
pub fn parse(
    host: &str,
    port: i64,
    transport: &str,
    facility: i64,
    enabled: bool,
) -> IpcResult<SyslogConfig> {
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| IpcError::invalid("port", "must be 1..=65535"))?;
    let facility = u8::try_from(facility)
        .ok()
        .filter(|f| *f <= 23)
        .ok_or_else(|| IpcError::invalid("facility", "must be 0..=23"))?;
    let transport = match transport {
        "udp" => Transport::Udp,
        "tcp" => Transport::Tcp,
        "tls" => Transport::Tls,
        _ => return Err(IpcError::invalid("transport", "must be udp, tcp or tls")),
    };
    if host.len() > 1024 {
        return Err(IpcError::invalid("host", "must be 1..=253 characters"));
    }
    SyslogConfig { host: host.to_owned(), port, transport, facility, enabled }
        .validated()
        .map_err(|e| syslog_error(&e))
}

fn stored(state: &AppState) -> IpcResult<Option<SyslogConfig>> {
    let slot = state.store.lock().map_err(|_| IpcError::poisoned())?;
    let Some(store) = slot.store.as_ref() else {
        return Ok(None);
    };
    Ok(store
        .app_setting(KEY)?
        .and_then(|json| serde_json::from_str::<SyslogConfig>(&json).ok())
        .and_then(|c| c.validated().ok()))
}

fn start(config: &SyslogConfig, roots: TlsRoots) -> IpcResult<SyslogMirror> {
    SyslogMirror::start(config.clone(), &local_hostname(), roots).map_err(|e| syslog_error(&e))
}

/// Start the stored mirror at app start (before unlock: lock/unlock events are mirrored too).
/// Failures are logged; startup never fails because of syslog.
pub fn start_stored(state: &AppState) {
    match stored(state) {
        Ok(Some(cfg)) if cfg.enabled => match start(&cfg, TlsRoots::System) {
            Ok(m) => {
                if let Ok(mut log) = state.audit.lock() {
                    log.set_mirror(Some(m));
                    tracing::info!(transport = cfg.transport.as_str(), "syslog mirror started");
                }
            }
            Err(e) => tracing::warn!(code = e.code, "syslog mirror not started"),
        },
        Ok(_) => {}
        Err(e) => tracing::warn!(code = e.code, "syslog config unreadable"),
    }
}

/// Current configuration and counters, `None` when never configured.
pub fn get(state: &AppState) -> IpcResult<Option<SyslogStatus>> {
    state.with_ready(|_, _| Ok(()))?;
    let Some(config) = stored(state)? else {
        return Ok(None);
    };
    let log = state.audit.lock().map_err(|_| IpcError::poisoned())?;
    let (running, dropped, sent) =
        log.mirror().map_or((false, 0, 0), |m| (true, m.dropped(), m.sent()));
    Ok(Some(SyslogStatus { config, running, dropped, sent }))
}

/// Persist, (re)start or stop the mirror, and audit the change. Disabling is recorded before
/// the mirror stops (the old collector sees it); enabling after it starts (the new one does).
pub fn set(state: &AppState, config: SyslogConfig, roots: TlsRoots) -> IpcResult<SyslogStatus> {
    let config = config.validated().map_err(|e| syslog_error(&e))?;
    let json = serde_json::to_string(&config)
        .map_err(|_| IpcError::new("state.internal", "internal error"))?;
    let mirror = if config.enabled { Some(start(&config, roots)?) } else { None };
    state.with_ready(|_, store| Ok(store.set_app_setting(KEY, &json)?))?;
    let event = AuditEvent::AuditSyslogChanged {
        enabled: config.enabled,
        host: config.host.clone(),
        port: config.port,
        transport: config.transport.as_str().to_owned(),
        facility: config.facility,
    };
    if config.enabled {
        state.audit.lock().map_err(|_| IpcError::poisoned())?.set_mirror(mirror);
        state.audit(event);
    } else {
        state.audit(event);
        state.audit.lock().map_err(|_| IpcError::poisoned())?.set_mirror(None);
    }
    get(state)?.ok_or_else(|| IpcError::new("state.internal", "internal error"))
}

/// The stored collector, for `syslog_test`. Requires an unlocked vault.
pub fn test_target(state: &AppState) -> IpcResult<SyslogConfig> {
    state.with_ready(|_, _| Ok(()))?;
    stored(state)?
        .ok_or_else(|| IpcError::new("syslog.not_configured", "no syslog collector configured"))
}

/// Send one test message synchronously (bounded by the 5 s socket timeouts).
pub fn run_test(config: &SyslogConfig, roots: &TlsRoots) -> TestResult {
    match send_test(config, &local_hostname(), roots) {
        Ok(()) => TestResult { ok: true, error: None },
        Err(e) => TestResult { ok: false, error: Some(e.to_string()) },
    }
}

// ------------------------------------------------------------------ Tauri wrappers

/// `syslog_get()`.
#[tauri::command]
pub fn syslog_get(state: State<'_, AppState>) -> IpcResult<Option<SyslogStatus>> {
    get(&state)
}

/// `syslog_set({ host, port, transport, facility, enabled })`.
#[tauri::command(rename_all = "camelCase")]
pub fn syslog_set(
    state: State<'_, AppState>,
    host: String,
    port: i64,
    transport: String,
    facility: i64,
    enabled: bool,
) -> IpcResult<SyslogStatus> {
    let config = parse(&host, port, &transport, facility, enabled)?;
    set(&state, config, TlsRoots::System)
}

/// `syslog_test()`. The network round trip runs on a blocking thread.
#[tauri::command]
pub async fn syslog_test(state: State<'_, AppState>) -> IpcResult<TestResult> {
    let config = test_target(&state)?;
    tauri::async_runtime::spawn_blocking(move || run_test(&config, &TlsRoots::System))
        .await
        .map_err(|_| IpcError::new("state.internal", "internal error"))
}

#[cfg(test)]
#[path = "syslog_tests.rs"]
mod tests;
