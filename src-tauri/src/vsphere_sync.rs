//! vSphere inventory sync (ADR-0015 §1–2, task V2): per-vCenter sessions, the single-flight
//! refresh and its store transaction, status, and logout on vault lock.
//!
//! * [`VsphereHub`] (one per app, in `AppState`) holds one [`Source`] per vCenter connection:
//!   the cached [`Session`] (token in `Zeroizing` memory inside mooring-vsphere), the refresh
//!   flight lock, the status shown by `vsphere_status`, a 10 s power-state cache and the
//!   scheduler task ([`crate::scheduler`]).
//! * [`refresh`] is single-flight per source: a trigger that arrives while a refresh runs
//!   waits for it and returns its result instead of starting another one.
//! * A refresh fetches everything, diffs it against the stored snapshot and writes the
//!   result in one transaction ([`mooring_store::Store::apply_inventory_diff`]); a failure
//!   writes nothing and is recorded in the status and audited `vsphere_sync_failed`.
//! * [`VsphereHub::on_lock`] bumps the epoch, stops every scheduler, drops every session and
//!   logs it out in the background. A locked vault refuses every call with `vault.locked`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::ConnectionId;
use mooring_store::{SyncPlan, SyncedRow};
use mooring_vsphere::{
    diff, Caps, Inventory, InventoryItem, PowerState, Session, DEFAULT_MAX_VMS, MAX_CLUSTERS,
    MAX_DATACENTERS, MAX_HOSTS,
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::commands::vsphere_confirm::Prompt;
use crate::confirm_gate::ConfirmGate;
use crate::commands::vsphere_login::{self, Login};
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::{record_audit, AppState, Ready};

/// How long a power state read live stays fresh (ADR-0015 §3).
pub const POWER_CACHE: Duration = Duration::from_secs(10);

/// `vsphere_refresh` result (ADR-0015 §5 `SyncReport`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    /// New items.
    pub added: u64,
    /// Renamed / moved / details changed.
    pub changed: u64,
    /// Missing for the first time (kept, `syncState: "missing"`).
    pub missing: u64,
    /// Removed after two consecutive misses.
    pub deleted: u64,
    /// RFC 3339.
    pub at: String,
}

/// `vsphere_status` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// RFC 3339 of the last successful refresh.
    pub last_refresh: Option<String>,
    /// IPC error code of the last failed refresh (cleared by a success).
    pub last_error: Option<String>,
    /// A refresh is running.
    pub running: bool,
    /// The last successful report.
    pub last_report: Option<SyncReport>,
    /// The scheduler runs for this vCenter.
    pub scheduled: bool,
}

/// What started a refresh (audit `trigger`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// `vsphere_refresh`.
    Manual,
    /// The scheduler.
    Schedule,
    /// `vsphere_sync_enable`.
    Import,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Schedule => "schedule",
            Self::Import => "import",
        }
    }
}

/// One vCenter connection.
#[derive(Default)]
pub struct Source {
    flight: tokio::sync::Mutex<()>,
    done: AtomicU64,
    status: Mutex<SyncStatus>,
    last: Mutex<Option<Result<SyncReport, IpcError>>>,
    session: Mutex<Option<(u64, Arc<Session>)>>,
    power: Mutex<HashMap<String, (PowerState, Instant)>>,
    pub(crate) timer: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct HubInner {
    sources: Mutex<HashMap<String, Arc<Source>>>,
    epoch: AtomicU64,
    minute: Mutex<Duration>,
    max_vms: Mutex<usize>,
}

/// All vCenter sources of the app. Cheap to clone.
#[derive(Debug, Clone)]
pub struct VsphereHub(Arc<HubInner>);

impl Default for VsphereHub {
    fn default() -> Self {
        Self(Arc::new(HubInner {
            sources: Mutex::new(HashMap::new()),
            epoch: AtomicU64::new(0),
            minute: Mutex::new(Duration::from_secs(60)),
            max_vms: Mutex::new(DEFAULT_MAX_VMS),
        }))
    }
}

impl VsphereHub {
    /// The entry of `source`, created on first use.
    pub fn source(&self, source: &str) -> Arc<Source> {
        let mut map = self.0.sources.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(map.entry(source.to_owned()).or_default())
    }

    fn existing(&self, source: &str) -> Option<Arc<Source>> {
        self.0.sources.lock().ok()?.get(source).cloned()
    }

    /// Current lock epoch (bumped by every [`Self::on_lock`]).
    pub fn epoch(&self) -> u64 {
        self.0.epoch.load(Ordering::SeqCst)
    }

    /// Length of one scheduler "minute" (60 s; tests shorten it).
    pub fn minute(&self) -> Duration {
        *self.0.minute.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Test knob: the length of a scheduler minute.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_minute(&self, d: Duration) {
        *self.0.minute.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = d;
    }

    /// VM cap per vCenter (default 5 000, ceiling 20 000).
    pub fn max_vms(&self) -> usize {
        *self.0.max_vms.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Test knob: the VM cap.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_max_vms(&self, n: usize) {
        *self.0.max_vms.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = n;
    }

    /// `vsphere_status`.
    pub fn status(&self, source: &str) -> SyncStatus {
        let Some(s) = self.existing(source) else { return SyncStatus::default() };
        let mut st = s.status.lock().map(|g| g.clone()).unwrap_or_default();
        st.scheduled = s.timer.lock().is_ok_and(|t| t.is_some());
        st
    }

    /// The cached session of `source` for the current epoch.
    pub fn session(&self, source: &str) -> Option<Arc<Session>> {
        let s = self.existing(source)?;
        let g = s.session.lock().ok()?;
        g.as_ref().filter(|(e, _)| *e == self.epoch()).map(|(_, s)| Arc::clone(s))
    }

    fn keep_session(&self, source: &str, epoch: u64, session: Arc<Session>) {
        if epoch != self.epoch() {
            spawn_logout(session);
            return;
        }
        if let Ok(mut g) = self.source(source).session.lock() {
            if let Some((_, old)) = g.replace((epoch, session)) {
                spawn_logout(old);
            }
        }
    }

    /// Forget (and log out) the session of `source`, e.g. after an auth failure.
    pub fn drop_session(&self, source: &str) {
        if let Some(s) = self.existing(source) {
            if let Some((_, old)) = s.session.lock().ok().and_then(|mut g| g.take()) {
                spawn_logout(old);
            }
        }
    }

    /// Cached power state younger than [`POWER_CACHE`].
    pub fn cached_power(&self, source: &str, vm: &str) -> Option<PowerState> {
        let s = self.existing(source)?;
        let g = s.power.lock().ok()?;
        g.get(vm).filter(|(_, at)| at.elapsed() < POWER_CACHE).map(|(p, _)| *p)
    }

    /// Remember a live power state.
    pub fn cache_power(&self, source: &str, vm: &str, state: PowerState) {
        if let Ok(mut g) = self.source(source).power.lock() {
            g.insert(vm.to_owned(), (state, Instant::now()));
        }
    }

    /// Vault lock: stop every scheduler, drop every session (logged out in the background),
    /// clear the power cache. Later results of a refresh started before the lock are dropped.
    pub fn on_lock(&self) {
        self.0.epoch.fetch_add(1, Ordering::SeqCst);
        let all: Vec<Arc<Source>> =
            self.0.sources.lock().map(|m| m.values().cloned().collect()).unwrap_or_default();
        for s in all {
            if let Some(t) = s.timer.lock().ok().and_then(|mut t| t.take()) {
                t.abort();
            }
            if let Some((_, old)) = s.session.lock().ok().and_then(|mut g| g.take()) {
                spawn_logout(old);
            }
            if let Ok(mut p) = s.power.lock() {
                p.clear();
            }
        }
    }

    /// Forget a vCenter whose sync was disabled or whose connection was deleted.
    pub fn remove(&self, source: &str) {
        let s = self.0.sources.lock().ok().and_then(|mut m| m.remove(source));
        if let Some(s) = s {
            if let Some(t) = s.timer.lock().ok().and_then(|mut t| t.take()) {
                t.abort();
            }
            if let Some((_, old)) = s.session.lock().ok().and_then(|mut g| g.take()) {
                spawn_logout(old);
            }
        }
    }
}

fn spawn_logout(session: Arc<Session>) {
    tauri::async_runtime::spawn(async move {
        if let Err(e) = session.logout_shared().await {
            tracing::debug!(code = e.code(), "vsphere logout failed");
        }
    });
}

/// The `'static` handle a refresh or scheduler task needs.
#[derive(Debug, Clone)]
pub struct VsCtx {
    /// Vault + store.
    pub ready: Ready,
    /// Audit log.
    pub audit: Arc<Mutex<AuditLog>>,
    /// `$APP_DATA` (`known_vsphere_certs`).
    pub data_dir: PathBuf,
    /// The hub.
    pub hub: VsphereHub,
    /// Confirmation gate (M-16).
    pub confirm: Arc<ConfirmGate>,
}

impl VsCtx {
    /// From the app state.
    pub fn of(state: &AppState) -> Self {
        Self {
            ready: state.ready(),
            audit: Arc::clone(&state.audit),
            data_dir: state.data_dir.clone(),
            hub: state.vsphere.clone(),
            confirm: Arc::clone(&state.confirm),
        }
    }

    /// Append an audit event.
    pub fn audit(&self, e: AuditEvent) {
        record_audit(&self.audit, e);
    }
}

/// The session of `source`: the cached one, or a fresh login (trust prompt through
/// `prompt` when given; scheduled refreshes pass `None` and fail on an unknown certificate).
pub async fn session(ctx: &VsCtx, source: ConnectionId, prompt: Option<Prompt<'_>>) -> IpcResult<Arc<Session>> {
    let id = source.to_string();
    if let Some(s) = ctx.hub.session(&id) {
        return Ok(s);
    }
    let epoch = ctx.hub.epoch();
    let Login { session, .. } = vsphere_login::login(ctx, source, prompt).await?;
    let session = Arc::new(session);
    ctx.hub.keep_session(&id, epoch, Arc::clone(&session));
    if epoch != ctx.hub.epoch() {
        return Err(IpcError::locked());
    }
    Ok(session)
}

/// One refresh of `source`, single-flight: a caller arriving while one runs gets its result.
pub async fn refresh(
    ctx: &VsCtx,
    source: ConnectionId,
    trigger: Trigger,
    prompt: Option<Prompt<'_>>,
) -> IpcResult<SyncReport> {
    let id = source.to_string();
    let entry = ctx.hub.source(&id);
    let seen = entry.done.load(Ordering::SeqCst);
    let _flight = entry.flight.lock().await;
    if entry.done.load(Ordering::SeqCst) != seen {
        if let Some(last) = entry.last.lock().ok().and_then(|g| g.clone()) {
            return last;
        }
    }
    set_running(&entry, true);
    let started = Instant::now();
    ctx.audit(AuditEvent::VsphereSyncStarted { connection: id.clone(), trigger: trigger.as_str().to_owned() });
    let result = run_refresh(ctx, source, prompt).await;
    let result = match result {
        Ok(counts) => {
            let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            ctx.audit(AuditEvent::VsphereSyncFinished {
                connection: id.clone(),
                added: counts.added,
                changed: counts.changed,
                missing: counts.missing,
                removed: counts.deleted,
                ms,
            });
            Ok(counts)
        }
        Err(e) => {
            ctx.audit(AuditEvent::VsphereSyncFailed { connection: id.clone(), code: e.code.to_owned() });
            if e.code == "vsphere.auth_failed" {
                ctx.hub.drop_session(&id);
            }
            Err(e)
        }
    };
    if let Ok(mut st) = entry.status.lock() {
        st.running = false;
        match &result {
            Ok(r) => {
                st.last_refresh = Some(r.at.clone());
                st.last_error = None;
                st.last_report = Some(r.clone());
            }
            Err(e) => st.last_error = Some(e.code.to_owned()),
        }
    }
    if let Ok(mut l) = entry.last.lock() {
        *l = Some(result.clone());
    }
    entry.done.fetch_add(1, Ordering::SeqCst);
    result
}

fn set_running(entry: &Source, running: bool) {
    if let Ok(mut st) = entry.status.lock() {
        st.running = running;
    }
}

async fn run_refresh(ctx: &VsCtx, source: ConnectionId, prompt: Option<Prompt<'_>>) -> IpcResult<SyncReport> {
    let epoch = ctx.hub.epoch();
    let rows = ctx.ready.with_ready(|_, store| {
        if store.sync_root(source)?.is_none() {
            return Err(IpcError::new("vsphere.not_found", "sync is not enabled for this vCenter"));
        }
        Ok(store.synced_rows(source)?)
    })?;
    let old = previous(&rows)?;
    let streaks = rows.iter().filter(|r| r.streak > 0).map(|r| (r.node.external_id.clone(), r.streak)).collect();
    let session = session(ctx, source, prompt).await?;
    let caps = Caps { datacenters: MAX_DATACENTERS, clusters: MAX_CLUSTERS, hosts: MAX_HOSTS, vms: ctx.hub.max_vms() };
    let new = session.inventory(&caps).await.map_err(|e| vsphere_login::map_error(&e))?;
    let d = diff(&old, &new, &streaks);
    let mut upsert: Vec<&InventoryItem> = d.added.iter().chain(d.changed.iter().map(|c| &c.new)).collect();
    upsert.sort_by(|a, b| (a.kind.depth(), &a.external_id).cmp(&(b.kind.depth(), &b.external_id)));
    let plan = SyncPlan {
        upsert: upsert.into_iter().map(to_node).collect::<IpcResult<_>>()?,
        remove: d.removed.clone(),
        missing: d.missing_streak.clone(),
    };
    if epoch != ctx.hub.epoch() {
        return Err(IpcError::locked());
    }
    let counts = ctx.ready.with_ready(|_, store| Ok(store.apply_inventory_diff(source, &plan)?))?;
    for i in new.iter().filter(|i| i.power_state.is_some()) {
        if let Some(p) = i.power_state {
            ctx.hub.cache_power(&source.to_string(), &i.external_id, p);
        }
    }
    Ok(SyncReport {
        added: counts.added,
        changed: d.changed.len() as u64,
        missing: counts.missing,
        deleted: counts.removed,
        at: dto::ts(OffsetDateTime::now_utc()),
    })
}

fn kind_name(i: &InventoryItem) -> IpcResult<String> {
    match serde_json::to_value(i.kind) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(IpcError::new("vsphere.failed", "inventory item could not be stored")),
    }
}

fn to_node(i: &InventoryItem) -> IpcResult<mooring_store::SyncNode> {
    let data = serde_json::to_string(i).map_err(|_| IpcError::new("vsphere.failed", "inventory item could not be stored"))?;
    Ok(mooring_store::SyncNode {
        external_id: i.external_id.clone(),
        kind: kind_name(i)?,
        parent: i.parent.clone(),
        name: i.name.clone(),
        data,
    })
}

/// The stored snapshot, rebuilt from `sync_data` with the store's own parent and id.
fn previous(rows: &[SyncedRow]) -> IpcResult<Inventory> {
    let corrupt = || IpcError::new("store.corrupt", "a stored inventory item is damaged");
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        let mut item: InventoryItem = serde_json::from_str(&r.node.data).map_err(|_| corrupt())?;
        item.external_id.clone_from(&r.node.external_id);
        item.parent.clone_from(&r.node.parent);
        items.push(item);
    }
    Inventory::from_items(items).map_err(|_| corrupt())
}

/// Parse and check a vCenter connection id from IPC.
pub fn source_id(raw: &str) -> IpcResult<ConnectionId> {
    dto::connection_id("connectionId", raw)
}

#[cfg(test)]
#[path = "vsphere_sync_tests.rs"]
mod tests;
