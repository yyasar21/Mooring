//! The device side of a sync run over [`AppState`] (ADR-0017, A3 S2).
//!
//! * [`AppLocal`] implements `mooring_sync::LocalSide` by taking the vault and store locks
//!   inside each call (never across the engine's network awaits).
//! * Applying a snapshot rewrites the trust files (`known_hosts`, `known_*_certs`, owner
//!   decision 10): every file's process-wide write lock
//!   ([`mooring_core::known_certs::write_lock`], also taken by the TOFU writers) is held for
//!   the whole apply. No trust store is cached in memory: SSH and every `mooring-http` client
//!   load the file at each connect, so the next connect sees the pulled pins.
//! * [`JoinLocal`] is the same over a vault that is not installed yet (`vault_join`).
//! * [`AppAudit`] maps the engine's events into the hash-chained audit log.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use mooring_audit::{AuditEvent, AuditLog};
use mooring_store::Store;
use mooring_sync::merge::Reseal;
use mooring_sync::snapshot::{self, trust_file_names};
use mooring_sync::{AuditSink, Keep, LocalSide, LocalState, Snapshot, SyncAudit, SyncError};
use mooring_vault::{SubKey, Uuid, Vault, VaultError, VaultState};

use crate::state::{record_audit, AppState, Ready, StoreSlot};

type Result<T> = mooring_sync::Result<T>;

/// Hold every trust file's write lock (fixed order) while `f` runs.
fn with_trust_locks<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    let locks: Vec<Arc<Mutex<()>>> =
        trust_file_names().map(|n| mooring_core::known_certs::write_lock(&dir.join(n))).collect();
    let guards: Vec<MutexGuard<'_, ()>> =
        locks.iter().map(|l| l.lock().unwrap_or_else(PoisonError::into_inner)).collect();
    let out = f();
    drop(guards);
    out
}

/// [`LocalSide`] over the app's vault and store.
#[derive(Debug, Clone)]
pub struct AppLocal {
    ready: Ready,
    trust_dir: PathBuf,
    device_name: String,
}

impl AppLocal {
    /// The device side of `state`.
    pub fn new(state: &AppState, device_name: &str) -> Self {
        Self { ready: state.ready(), trust_dir: state.data_dir.clone(), device_name: device_name.to_owned() }
    }

    fn with<T>(&self, f: impl FnOnce(&Vault, &Store) -> Result<T>) -> Result<T> {
        let mut out = None;
        let r = self.ready.with_ready(|v, s| {
            out = Some(f(v, s));
            Ok(())
        });
        match (r, out) {
            (Ok(()), Some(x)) => x,
            (Err(e), _) if e.code == "vault.locked" || e.code == "vault.missing" => {
                Err(SyncError::Vault(VaultError::Locked))
            }
            _ => Err(SyncError::Invalid("the local store is unavailable")),
        }
    }
}

impl Reseal for AppLocal {
    fn reseal(&self, old_id: &str, new_id: &str, secret: &str, sealed: &str) -> Result<String> {
        self.with(|v, _| mooring_sync::reseal_secret(v, old_id, new_id, secret, sealed))
    }
}

impl LocalSide for AppLocal {
    fn vault_id(&self) -> Uuid {
        self.with(|v, _| Ok(v.vault_id())).unwrap_or(Uuid::nil())
    }
    fn device_name(&self) -> String {
        self.device_name.clone()
    }
    fn header_object(&self) -> Result<Vec<u8>> {
        self.with(|v, _| mooring_sync::header_object(v))
    }
    fn sync_key(&self) -> Result<SubKey> {
        self.with(|v, _| mooring_sync::blob::sync_key(v))
    }
    fn snapshot(&self) -> Result<Snapshot> {
        self.with(|v, s| snapshot::from_store(s, &self.trust_dir, v.vault_id(), &self.device_name))
    }
    fn apply(&self, snap: &Snapshot) -> Result<()> {
        with_trust_locks(&self.trust_dir, || self.with(|_, s| snapshot::apply(s, &self.trust_dir, snap)))
    }
    fn load_state(&self) -> Result<Option<LocalState>> {
        self.with(|_, s| mooring_sync::load_state(s))
    }
    fn load_base(&self) -> Result<Option<Snapshot>> {
        self.with(|v, s| mooring_sync::load_base(s, v))
    }
    fn save_state(&self, state: &LocalState, base: Option<&Snapshot>) -> Result<()> {
        self.with(|v, s| mooring_sync::save_state(s, v, state, base))
    }
}

/// [`LocalSide`] of `vault_join`: the joined vault (unlocked, not installed yet) over the
/// app's store, which is rebound to the joined vault only inside [`LocalSide::apply`] (and
/// bound back when the apply fails).
pub struct JoinLocal {
    /// The joined vault.
    pub vault: Vault,
    /// The app's store slot.
    pub store: Arc<Mutex<StoreSlot>>,
    /// Vault id the store is bound to now (the bootstrap vault).
    pub previous_vault: String,
    /// Directory of the trust files.
    pub trust_dir: PathBuf,
    /// Device name.
    pub device_name: String,
}

impl std::fmt::Debug for JoinLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinLocal").finish_non_exhaustive()
    }
}

impl JoinLocal {
    fn store<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        if self.vault.state() != VaultState::Unlocked {
            return Err(SyncError::Vault(VaultError::Locked));
        }
        let slot = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        let store = slot.store.as_ref().ok_or(SyncError::Invalid("the local store is closed"))?;
        f(store)
    }
}

impl Reseal for JoinLocal {
    fn reseal(&self, old_id: &str, new_id: &str, secret: &str, sealed: &str) -> Result<String> {
        mooring_sync::reseal_secret(&self.vault, old_id, new_id, secret, sealed)
    }
}

impl LocalSide for JoinLocal {
    fn vault_id(&self) -> Uuid {
        self.vault.vault_id()
    }
    fn device_name(&self) -> String {
        self.device_name.clone()
    }
    fn header_object(&self) -> Result<Vec<u8>> {
        mooring_sync::header_object(&self.vault)
    }
    fn sync_key(&self) -> Result<SubKey> {
        mooring_sync::blob::sync_key(&self.vault)
    }
    fn snapshot(&self) -> Result<Snapshot> {
        Ok(Snapshot::empty(self.vault.vault_id(), &self.device_name))
    }
    fn apply(&self, snap: &Snapshot) -> Result<()> {
        with_trust_locks(&self.trust_dir, || {
            self.store(|s| {
                s.rebind_vault_for_join(&self.vault.vault_id().to_string())?;
                let applied = snapshot::apply(s, &self.trust_dir, snap);
                if applied.is_err() {
                    if let Err(e) = s.rebind_vault_for_join(&self.previous_vault) {
                        tracing::error!(error = %e, "join: could not restore the store binding");
                    }
                }
                applied
            })
        })
    }
    fn load_state(&self) -> Result<Option<LocalState>> {
        Ok(None)
    }
    fn load_base(&self) -> Result<Option<Snapshot>> {
        Ok(None)
    }
    fn save_state(&self, state: &LocalState, base: Option<&Snapshot>) -> Result<()> {
        // Before the apply (fresh state) the store still belongs to the bootstrap vault:
        // nothing is persisted until the joined rows are in.
        if state.last_counter == 0 {
            return Ok(());
        }
        self.store(|s| mooring_sync::save_state(s, &self.vault, state, base))
    }
}

/// [`AuditSink`] into the app's audit log (ADR-0017 S2 names).
#[derive(Debug, Clone)]
pub struct AppAudit(pub Arc<Mutex<AuditLog>>);

impl AppAudit {
    /// The audit log of `state`.
    pub fn of(state: &AppState) -> Self {
        Self(Arc::clone(&state.audit))
    }
}

/// The app audit event of an engine event.
pub fn audit_event(e: &SyncAudit) -> AuditEvent {
    match *e {
        SyncAudit::Push { counter, bytes } => AuditEvent::SyncPushed { counter, bytes: bytes as u64 },
        SyncAudit::Pull { counter } => AuditEvent::SyncPulled { counter },
        SyncAudit::Merge { counter, conflicts } => {
            AuditEvent::SyncMerged { counter, conflicts: conflicts as u64 }
        }
        SyncAudit::Fork { remote, last } => AuditEvent::SyncForkDetected { remote, last },
        SyncAudit::RollbackRefused { remote, last } => AuditEvent::SyncRollbackDetected { remote, last },
        SyncAudit::AlarmResolved { keep, counter } => AuditEvent::SyncForkResolved {
            keep: if keep == Keep::Local { "local" } else { "remote" }.to_owned(),
            counter,
        },
    }
}

impl AuditSink for AppAudit {
    fn record(&self, event: &SyncAudit) {
        record_audit(&self.0, audit_event(event));
    }
}
