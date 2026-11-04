//! `mooring-sync`: client-side encrypted vault sync to S3-compatible storage (ADR-0017, A3 S1).
//!
//! ```text
//! Store + trust files ──snapshot::from_store──► Snapshot (canonical JSON, secrets still sealed)
//!   ──encode_msy1(HKDF(DEK, vault_id, "mooring sync v1"))──► MSY1 blob
//!   ──Remote::put_new / put_cas (If-None-Match: * / If-Match)──► S3 `<prefix>/<vault>/current`
//! ```
//!
//! * [`blob`] — the `MSY1` format (layout table there), pure [`decode_msy1`], vectors in
//!   `test-vectors/`.
//! * [`snapshot`] — what is synced, [`snapshot::from_store`] / [`snapshot::apply`].
//! * [`merge`] — three-way merge, both copies on true conflicts.
//! * [`backend`] — [`ObjectStore`] (S3 via `rusty-s3` + `mooring-http`, or in memory),
//!   [`Remote`] layout and the conditional-write probe.
//! * [`SyncEngine`] — run / resolve, rollback and fork hard stops, audit events.

#![forbid(unsafe_code)]

pub mod backend;
pub mod blob;
mod engine;
mod error;
mod fixup;
pub mod fuzz;
mod local;
pub mod merge;
pub mod snapshot;
mod state;

pub use backend::memory::MemoryStore;
pub use backend::s3::{S3Backend, S3Config, S3Credentials};
pub use backend::{Cond, Object, ObjectStore, PutMeta, PutOutcome, Remote, RemoteHead};
pub use blob::{decode_msy1, BlobHeader, Msy1};
pub use engine::{SyncEngine, SyncPolicy};
pub use error::{Result, SyncError};
pub use local::{
    clear_state, header_object, load_base, load_state, reseal_secret, save_state, StoreLocal,
};
pub use merge::{Conflict, MergePlan, Resolution};
pub use snapshot::{RecordKind, Snapshot};
pub use state::{Alarm, AuditSink, Keep, LocalSide, LocalState, Outcome, SyncAudit, VecAudit};

#[cfg(test)]
mod tests;
