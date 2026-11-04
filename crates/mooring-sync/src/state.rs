//! Device-local sync state, the local side of an engine run, outcomes and audit events.

use mooring_vault::SubKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;
use crate::merge::{Conflict, Reseal};
use crate::snapshot::Snapshot;

/// A hard stop that needs [`crate::SyncEngine::resolve_fork`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Alarm {
    /// Two histories diverged at or after `last_counter`.
    Fork {
        /// Remote counter when detected.
        remote: u64,
    },
    /// The remote generation went backwards (or the object vanished: `remote = 0`).
    Rollback {
        /// Remote counter when detected.
        remote: u64,
        /// Last counter this device had seen.
        last: u64,
    },
}

/// What this device remembers between runs (stored in `mooring.db`, never synced). The base
/// snapshot is stored separately, sealed under the DEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalState {
    /// Stable id of this device (blob `device_id`).
    pub device_id: Uuid,
    /// Last generation seen or written (0 = never synced).
    pub last_counter: u64,
    /// SHA-256 of that blob, hex.
    pub last_hash: Option<String>,
    /// Its `ETag`.
    pub last_etag: Option<String>,
    /// Pending hard stop.
    pub alarm: Option<Alarm>,
    /// Unix seconds of the last successful pull / push (UI).
    pub last_pull_unix: Option<u64>,
    /// Unix seconds of the last push.
    pub last_push_unix: Option<u64>,
    /// Writer name and time of the remote blob last seen ("last pushed by", R-SYNC-FREEZE).
    pub remote_device: Option<String>,
    /// `created_unix` of that blob.
    pub remote_created_unix: Option<u64>,
}

impl LocalState {
    /// State of a device that never synced.
    pub fn fresh() -> Self {
        Self {
            device_id: Uuid::new_v4(),
            last_counter: 0,
            last_hash: None,
            last_etag: None,
            alarm: None,
            last_pull_unix: None,
            last_push_unix: None,
            remote_device: None,
            remote_created_unix: None,
        }
    }

    /// `last_hash` as bytes.
    pub fn last_hash_bytes(&self) -> Option<[u8; 32]> {
        let h = hex::decode(self.last_hash.as_deref()?).ok()?;
        h.try_into().ok()
    }
}

/// The device side of a run. Each method is synchronous so an implementation can take its
/// locks per call and never hold them across the network awaits of the engine.
pub trait LocalSide: Reseal {
    /// The vault id (non-nil).
    fn vault_id(&self) -> Uuid;
    /// Display name for conflict suffixes and "last pushed by".
    fn device_name(&self) -> String;
    /// The header object to publish: the vault header bytes without the keyring wrap.
    fn header_object(&self) -> Result<Vec<u8>>;
    /// The sync key (vault unlocked).
    fn sync_key(&self) -> Result<SubKey>;
    /// The current local snapshot (tombstones empty).
    fn snapshot(&self) -> Result<Snapshot>;
    /// Make the device match `snapshot`.
    fn apply(&self, snapshot: &Snapshot) -> Result<()>;
    /// Persisted state, `None` before the first run.
    fn load_state(&self) -> Result<Option<LocalState>>;
    /// The last synced snapshot.
    fn load_base(&self) -> Result<Option<Snapshot>>;
    /// Persist state and (when `Some`) the new base.
    fn save_state(&self, state: &LocalState, base: Option<&Snapshot>) -> Result<()>;
}

/// Result of a successful run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Outcome {
    /// Local changes published as generation `counter`.
    Pushed {
        /// New generation.
        counter: u64,
    },
    /// Remote fast-forwarded onto the device.
    Pulled {
        /// Remote generation applied.
        counter: u64,
    },
    /// Both sides changed: merged, applied and published as `counter`.
    Merged {
        /// New generation.
        counter: u64,
        /// What the UI lists after the merge.
        conflicts: Vec<Conflict>,
    },
    /// Nothing to do.
    NoChange {
        /// Current generation.
        counter: u64,
    },
}

/// Which side to keep when resolving an alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Keep {
    /// Publish this device's data over the remote.
    Local,
    /// Replace this device's data with the remote.
    Remote,
}

/// Audit events (ADR-0017 §5). Counters, sizes and ids only; never row content or secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAudit {
    /// `sync.push`.
    Push {
        /// Generation.
        counter: u64,
        /// Blob size.
        bytes: usize,
    },
    /// `sync.pull`.
    Pull {
        /// Generation.
        counter: u64,
    },
    /// `sync.merge`.
    Merge {
        /// Generation published.
        counter: u64,
        /// Number of conflicts.
        conflicts: usize,
    },
    /// `sync.rollback_refused`.
    RollbackRefused {
        /// Remote counter.
        remote: u64,
        /// Last seen.
        last: u64,
    },
    /// `sync.fork`.
    Fork {
        /// Remote counter.
        remote: u64,
        /// Last seen.
        last: u64,
    },
    /// `sync.alarm_resolved`.
    AlarmResolved {
        /// Side kept.
        keep: Keep,
        /// Generation after the resolution.
        counter: u64,
    },
}

impl SyncAudit {
    /// Event name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Push { .. } => "sync.push",
            Self::Pull { .. } => "sync.pull",
            Self::Merge { .. } => "sync.merge",
            Self::RollbackRefused { .. } => "sync.rollback_refused",
            Self::Fork { .. } => "sync.fork",
            Self::AlarmResolved { .. } => "sync.alarm_resolved",
        }
    }
}

/// Receives audit events; the Tauri layer maps them into the hash-chained audit log.
/// `Send + Sync` so an engine run is a `Send` future (Tauri commands, the interval runner).
pub trait AuditSink: Send + Sync {
    /// Record one event.
    fn record(&self, event: &SyncAudit);
}

/// An [`AuditSink`] that collects events (tests).
#[derive(Debug, Default)]
pub struct VecAudit(pub std::sync::Mutex<Vec<SyncAudit>>);

impl AuditSink for VecAudit {
    fn record(&self, event: &SyncAudit) {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(event.clone());
    }
}

impl VecAudit {
    /// Names recorded so far.
    pub fn names(&self) -> Vec<&'static str> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(SyncAudit::name)
            .collect()
    }
}
