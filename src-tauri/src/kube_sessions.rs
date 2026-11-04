//! Kubernetes sessions in the session registry (ADR-0014 K4).
//!
//! A **cluster session** (`kind: "cluster"`) holds the connected [`KubeClient`] (and so the
//! bearer token or client key, in memory only) and owns everything opened through it: log
//! streams, pod forwards and the `exec` shells. An **exec session** (`kind: "exec"`) is an
//! ordinary terminal session ([`run_exec`] drives it like SSH) whose parent is a cluster.
//!
//! Ending a cluster (`session_close`, the API side going away, or a vault lock) aborts its
//! log streams, closes its pod forwards and closes its exec shells. A vault lock ends every
//! Kubernetes session ([`close_all`]): unlike SSH, nothing of it survives a lock.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mooring_audit::AuditLog;
use mooring_core::options::ExecCommand;
use mooring_core::session::{CloseCode, Session};
use mooring_proto_kube::{AuditSink, KubeClient, PodForward};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::commands::kube_wire::{self, AccessDto};
use crate::session_task::{drive, finish, End};
use crate::sessions::{Control, PhaseCell, SessionCommand, TaskContext, WireEvent};
use crate::state::{record_audit, SessionRegistry};

/// What a Kubernetes registry entry is.
#[derive(Debug, Clone)]
pub enum KubeRole {
    /// The cluster handle.
    Cluster(KubeControl),
    /// An exec shell of the cluster session `parent`.
    Exec {
        /// Cluster session id.
        parent: String,
    },
}

/// `session_list` `(kind, parentSessionId)` of a registry entry; `None` for other protocols.
pub fn list_kind(control: &Control) -> Option<(&'static str, Option<String>)> {
    match control {
        Control::Kube(KubeRole::Cluster(_)) => Some(("cluster", None)),
        Control::Kube(KubeRole::Exec { parent }) => Some(("exec", Some(parent.clone()))),
        _ => None,
    }
}

/// One running log stream.
#[derive(Debug)]
pub struct LogEntry {
    /// Stops the pump task.
    pub abort: AbortHandle,
    /// `(namespace, pod, container)` for the close audit.
    pub target: (String, String, Option<String>),
}

/// One pod forward and its open time (RFC 3339).
#[derive(Debug)]
pub struct ForwardEntry {
    /// The listener (dropping it closes it and records `session.forward.close`).
    pub forward: PodForward,
    /// RFC 3339.
    pub opened_at: String,
}

#[derive(Debug)]
struct Inner {
    connection_id: String,
    audit: Arc<Mutex<AuditLog>>,
    registry: SessionRegistry,
    exec_command: ExecCommand,
    client: Mutex<Option<KubeClient>>,
    sink: Mutex<Option<AuditSink>>,
    access: Mutex<HashMap<String, AccessDto>>,
    logs: Mutex<HashMap<String, LogEntry>>,
    forwards: Mutex<BTreeMap<u64, ForwardEntry>>,
    exec: Mutex<HashSet<String>>,
    next: AtomicU64,
    locked: AtomicBool,
    ended: AtomicBool,
}

/// Shared state of one cluster session (cheap to clone).
#[derive(Debug, Clone)]
pub struct KubeControl(Arc<Inner>);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl KubeControl {
    /// A cluster session that is not connected yet.
    pub fn new(
        connection_id: String,
        audit: Arc<Mutex<AuditLog>>,
        registry: SessionRegistry,
        exec_command: ExecCommand,
    ) -> Self {
        Self(Arc::new(Inner {
            connection_id,
            audit,
            registry,
            exec_command,
            client: Mutex::new(None),
            sink: Mutex::new(None),
            access: Mutex::new(HashMap::new()),
            logs: Mutex::new(HashMap::new()),
            forwards: Mutex::new(BTreeMap::new()),
            exec: Mutex::new(HashSet::new()),
            next: AtomicU64::new(1),
            locked: AtomicBool::new(false),
            ended: AtomicBool::new(false),
        }))
    }

    /// Connection id.
    pub fn connection_id(&self) -> &str {
        &self.0.connection_id
    }

    /// The connection's default exec shell.
    pub fn exec_command(&self) -> ExecCommand {
        self.0.exec_command
    }

    /// The connected client; `None` while connecting and after the end.
    pub fn client(&self) -> Option<KubeClient> {
        lock(&self.0.client).clone()
    }

    /// Store the connected client (the end already happened: dropped at once).
    pub(crate) fn set_client(&self, client: KubeClient) {
        *lock(&self.0.sink) = Some(client.audit().clone());
        if !self.ended() {
            *lock(&self.0.client) = Some(client);
        }
    }

    /// Whether the cluster session has ended (or is ending).
    pub fn ended(&self) -> bool {
        self.0.ended.load(Ordering::SeqCst)
    }

    /// Whether a vault lock ended it.
    pub fn locked(&self) -> bool {
        self.0.locked.load(Ordering::SeqCst)
    }

    /// A fresh per-session number (stream and forward ids).
    pub fn next_id(&self) -> u64 {
        self.0.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Cached RBAC pre-flight of `namespace`.
    pub fn access(&self, namespace: &str) -> Option<AccessDto> {
        lock(&self.0.access).get(namespace).copied()
    }

    /// Cache a pre-flight (at most 256 namespaces are kept).
    pub fn cache_access(&self, namespace: &str, access: AccessDto) {
        let mut map = lock(&self.0.access);
        if map.len() >= 256 {
            map.clear();
        }
        map.insert(namespace.to_owned(), access);
    }

    /// The log stream map.
    pub fn logs(&self) -> MutexGuard<'_, HashMap<String, LogEntry>> {
        lock(&self.0.logs)
    }

    /// The pod forward map.
    pub fn forwards(&self) -> MutexGuard<'_, BTreeMap<u64, ForwardEntry>> {
        lock(&self.0.forwards)
    }

    /// Remember an exec child.
    pub fn exec_started(&self, id: &str) {
        lock(&self.0.exec).insert(id.to_owned());
    }

    fn exec_ended(&self, id: &str) {
        lock(&self.0.exec).remove(id);
    }

    /// Write everything the client's audit queue holds to the audit log.
    pub fn drain_audit(&self) {
        let Some(sink) = lock(&self.0.sink).clone() else { return };
        let dropped = sink.dropped();
        if dropped > 0 {
            tracing::warn!(dropped, "kubernetes audit events were dropped before draining");
        }
        for e in sink.take() {
            if let Some(event) = kube_wire::audit_event(&self.0.connection_id, e) {
                record_audit(&self.0.audit, event);
            }
        }
    }

    /// Record one audit event.
    pub fn audit(&self, event: mooring_audit::AuditEvent) {
        record_audit(&self.0.audit, event);
    }

    /// End everything this cluster owns: abort log streams (audited `kube.logs.closed`), close
    /// pod forwards, close exec shells, drop the client (and its token). Idempotent.
    pub fn teardown(&self, reason: &str) {
        self.0.ended.store(true, Ordering::SeqCst);
        let logs: Vec<(String, LogEntry)> = self.logs().drain().collect();
        for (id, entry) in logs {
            entry.abort.abort();
            self.audit(kube_wire::logs_closed(self.connection_id(), &id, entry.target, false, reason));
        }
        let forwards: Vec<ForwardEntry> =
            std::mem::take(&mut *self.forwards()).into_values().collect();
        drop(forwards);
        let children: Vec<String> = lock(&self.0.exec).drain().collect();
        close_sessions(&self.0.registry, &children);
        self.drain_audit();
        lock(&self.0.client).take();
        lock(&self.0.access).clear();
    }
}

/// Ask the sessions `ids` to close (without waiting).
fn close_sessions(registry: &SessionRegistry, ids: &[String]) {
    let senders: Vec<mpsc::Sender<SessionCommand>> = match registry.lock() {
        Ok(map) => ids.iter().filter_map(|id| map.get(id).map(|h| h.commands.clone())).collect(),
        Err(_) => return,
    };
    for tx in senders {
        let (reply, _) = oneshot::channel();
        let _ = tx.try_send(SessionCommand::Close(reply));
    }
}

/// End every Kubernetes session (vault lock): tokens live in memory only and must not outlive
/// the lock. Returns how many cluster sessions were ended.
pub fn close_all(registry: &SessionRegistry) -> usize {
    let clusters: Vec<(KubeControl, mpsc::Sender<SessionCommand>)> = match registry.lock() {
        Ok(map) => map
            .values()
            .filter_map(|h| match &h.control {
                Control::Kube(KubeRole::Cluster(c)) => Some((c.clone(), h.commands.clone())),
                _ => None,
            })
            .collect(),
        Err(_) => return 0,
    };
    let n = clusters.len();
    for (ctrl, tx) in clusters {
        ctrl.0.locked.store(true, Ordering::SeqCst);
        // Synchronous part first: nothing keeps running even if the task is slow to react.
        ctrl.teardown("vault_locked");
        let (reply, _) = oneshot::channel();
        let _ = tx.try_send(SessionCommand::Close(reply));
    }
    if n > 0 {
        tracing::info!(clusters = n, "kubernetes sessions closed on lock");
    }
    n
}

/// The task of one exec shell: [`drive`] as for SSH, then the parent is told and its audit
/// queue (`kube.exec.closed`) drained.
pub(crate) async fn run_exec(
    mut session: Box<dyn Session>,
    mut commands: mpsc::Receiver<SessionCommand>,
    ctx: TaskContext,
    phase: PhaseCell,
    parent: KubeControl,
) {
    let driven = drive(&mut *session, &mut commands, &ctx, &phase, None).await;
    let (mut reason, mut code) = match driven.end {
        End::Closed { reason, code } => (reason, code),
        End::TrustAccepted { .. } => ("session ended".to_owned(), CloseCode::ProtocolError),
    };
    if parent.locked() {
        "vault locked".clone_into(&mut reason);
        code = CloseCode::VaultLocked;
    }
    (ctx.sink)(WireEvent::Closed { reason: reason.clone(), code });
    let _ = session.close().await;
    parent.exec_ended(&ctx.session_id);
    parent.drain_audit();
    finish(commands, ctx, &phase, reason);
}
