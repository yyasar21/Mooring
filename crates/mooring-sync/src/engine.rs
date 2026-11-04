//! [`SyncEngine`]: one pull → verify → (fast-forward | merge) → conditional push cycle
//! (ADR-0017 §3).
//!
//! * Remote unchanged since our last run (same blob hash): push local changes with
//!   `If-Match`, or report `NoChange`.
//! * Remote counter below our last seen → **rollback** hard stop; equal counter with another
//!   hash → **fork** hard stop; higher counter whose parent chain (via `history/`, at most
//!   `max_chain_walk` hops, each hop hash-checked) does not reach our last blob → **fork**.
//!   Alarms are persisted and audited; every later run refuses until
//!   [`SyncEngine::resolve_fork`] is called with the user's choice.
//! * Otherwise fast-forward when nothing changed locally, else three-way merge against the
//!   base, publish the merge with `If-Match`, and only then apply it locally.
//! * `412` on a conditional write = someone pushed in between: start over (≤ `max_attempts`).

use bytes::Bytes;
use mooring_vault::SubKey;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::backend::{Object, ObjectStore, PutMeta, PutOutcome, Remote};
use crate::blob::{blob_hash, decode_msy1, encode_msy1, open_msy1, BlobHeader};
use crate::error::{Result, SyncError};
use crate::merge::{merge, MergeCtx};
use crate::snapshot::{derive_tombstones, Snapshot};
use crate::state::{Alarm, AuditSink, Keep, LocalSide, LocalState, Outcome, SyncAudit};

/// Knobs of the engine.
#[derive(Debug, Clone, Copy)]
pub struct SyncPolicy {
    /// Attempts per run when conditional writes lose races.
    pub max_attempts: u32,
    /// Blobs kept under `history/`.
    pub history_keep: u64,
    /// Most history hops walked to prove ancestry.
    pub max_chain_walk: u64,
    /// Clock (tests pin it).
    pub clock: fn() -> OffsetDateTime,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            history_keep: 10,
            max_chain_walk: 10,
            clock: OffsetDateTime::now_utc,
        }
    }
}

/// A verified remote blob.
struct Fetched {
    etag: String,
    hash: [u8; 32],
    header: BlobHeader,
    snapshot: Snapshot,
}

/// What `publish` needs besides the snapshot.
struct Publish<'a> {
    key: &'a SubKey,
    header_hash: [u8; 32],
    parent: Option<(u64, [u8; 32])>,
    etag: Option<&'a str>,
    apply: bool,
}

/// The sync engine. Stateless between runs: everything persistent goes through
/// [`LocalSide`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncEngine {
    policy: SyncPolicy,
}

fn alarm_error(a: Alarm) -> SyncError {
    match a {
        Alarm::Fork { remote } => SyncError::Fork { remote },
        Alarm::Rollback { remote, last } => SyncError::Rollback { remote, last },
    }
}

impl SyncEngine {
    /// An engine with `policy`.
    pub fn new(policy: SyncPolicy) -> Self {
        Self { policy }
    }

    fn now(&self) -> (u64, String) {
        let t = (self.policy.clock)();
        let unix = u64::try_from(t.unix_timestamp()).unwrap_or(0);
        (unix, t.format(&Rfc3339).unwrap_or_default())
    }

    fn load<L: LocalSide>(local: &L) -> Result<LocalState> {
        if let Some(s) = local.load_state()? {
            return Ok(s);
        }
        let s = LocalState::fresh();
        local.save_state(&s, None)?;
        Ok(s)
    }

    /// One sync cycle.
    pub async fn run<L: LocalSide, S: ObjectStore>(
        &self,
        local: &L,
        remote: &Remote<S>,
        audit: &dyn AuditSink,
    ) -> Result<Outcome> {
        let mut state = Self::load(local)?;
        if let Some(a) = state.alarm {
            return Err(alarm_error(a));
        }
        for _ in 0..self.policy.max_attempts.max(1) {
            if let Some(o) = self.attempt(local, remote, audit, &mut state).await? {
                return Ok(o);
            }
            tracing::debug!("sync: conditional write lost a race; retrying");
        }
        Err(SyncError::Conflict)
    }

    fn local_view<L: LocalSide>(&self, local: &L) -> Result<(Option<Snapshot>, Snapshot)> {
        let base = local.load_base()?;
        let mut mine = local.snapshot()?;
        derive_tombstones(&mut mine, base.as_ref(), &self.now().1);
        Ok((base, mine))
    }

    async fn attempt<L: LocalSide, S: ObjectStore>(
        &self,
        local: &L,
        remote: &Remote<S>,
        audit: &dyn AuditSink,
        state: &mut LocalState,
    ) -> Result<Option<Outcome>> {
        let header = local.header_object()?;
        let key = local.sync_key()?;
        let (base, mine) = self.local_view(local)?;
        let mut p = Publish {
            key: &key,
            header_hash: blob_hash(&header),
            parent: None,
            etag: None,
            apply: false,
        };
        let Some(obj) = remote.get().await? else {
            if state.last_counter > 0 {
                let a = Alarm::Rollback { remote: 0, last: state.last_counter };
                return Err(raise(local, state, a, audit)?);
            }
            remote.put_header(&header).await?;
            let c = self.publish(local, remote, audit, state, &mine, &p).await?;
            return Ok(c.map(|counter| Outcome::Pushed { counter }));
        };
        let f = open(remote, &obj, local.vault_id(), &key, &header).await?;
        p.parent = Some((f.header.counter, f.hash));
        p.etag = Some(&f.etag);
        let unchanged = base.as_ref().is_some_and(|b| b.same_content(&mine));
        if state.last_hash_bytes() == Some(f.hash) {
            if unchanged {
                return Ok(Some(Outcome::NoChange { counter: f.header.counter }));
            }
            let c = self.publish(local, remote, audit, state, &mine, &p).await?;
            return Ok(c.map(|counter| Outcome::Pushed { counter }));
        }
        let last = state.last_counter;
        if f.header.counter < last {
            let a = Alarm::Rollback { remote: f.header.counter, last };
            return Err(raise(local, state, a, audit)?);
        }
        if f.header.counter == last || (last > 0 && !self.descends(remote, &f, state).await?) {
            return Err(raise(local, state, Alarm::Fork { remote: f.header.counter }, audit)?);
        }
        let plan = if unchanged {
            None
        } else {
            let now = self.now().1;
            let ctx = MergeCtx { remote_device: &f.snapshot.device_name, now: &now };
            Some(merge(base.as_ref(), &mine, &f.snapshot, ctx, local)?)
        };
        match plan {
            Some(plan)
                if !(plan.conflicts.is_empty() && plan.snapshot.same_content(&f.snapshot)) =>
            {
                let mut snap = plan.snapshot;
                snap.device_name = local.device_name();
                p.apply = true;
                let c = self.publish(local, remote, audit, state, &snap, &p).await?;
                if let Some(counter) = c {
                    audit.record(&SyncAudit::Merge { counter, conflicts: plan.conflicts.len() });
                    return Ok(Some(Outcome::Merged { counter, conflicts: plan.conflicts }));
                }
                Ok(None)
            }
            _ => {
                self.fast_forward(local, state, &f, audit)?;
                Ok(Some(Outcome::Pulled { counter: f.header.counter }))
            }
        }
    }

    fn fast_forward<L: LocalSide>(
        &self,
        local: &L,
        state: &mut LocalState,
        f: &Fetched,
        audit: &dyn AuditSink,
    ) -> Result<()> {
        local.apply(&f.snapshot)?;
        state.last_counter = f.header.counter;
        state.last_hash = Some(hex::encode(f.hash));
        state.last_etag = Some(f.etag.clone());
        state.last_pull_unix = Some(self.now().0);
        state.remote_device = Some(f.snapshot.device_name.clone());
        state.remote_created_unix = Some(f.header.created_unix);
        state.alarm = None;
        local.save_state(state, Some(&f.snapshot))?;
        audit.record(&SyncAudit::Pull { counter: f.header.counter });
        Ok(())
    }

    /// Walk `history/` from `f` back to our last blob; `false` = not our descendant.
    async fn descends<S: ObjectStore>(
        &self,
        remote: &Remote<S>,
        f: &Fetched,
        state: &LocalState,
    ) -> Result<bool> {
        let (last, Some(last_hash)) = (state.last_counter, state.last_hash_bytes()) else {
            return Ok(false);
        };
        let mut cur = f.header;
        for _ in 0..=self.policy.max_chain_walk {
            if cur.parent_counter == last {
                return Ok(cur.parent_hash == last_hash);
            }
            if cur.parent_counter < last {
                return Ok(false);
            }
            let Some(bytes) = remote.get_history(cur.parent_counter).await? else {
                return Ok(false);
            };
            if blob_hash(&bytes) != cur.parent_hash {
                return Ok(false);
            }
            let parent = decode_msy1(&bytes)?.header;
            if parent.counter != cur.parent_counter || parent.vault_id != cur.vault_id {
                return Ok(false);
            }
            cur = parent;
        }
        Ok(false)
    }

    /// Encode, conditionally write, then record. `Ok(None)` = precondition failed.
    async fn publish<L: LocalSide, S: ObjectStore>(
        &self,
        local: &L,
        remote: &Remote<S>,
        audit: &dyn AuditSink,
        state: &mut LocalState,
        snapshot: &Snapshot,
        p: &Publish<'_>,
    ) -> Result<Option<u64>> {
        let (now_unix, _) = self.now();
        let parent_counter = p.parent.map_or(0, |x| x.0);
        let counter = parent_counter
            .max(state.last_counter)
            .checked_add(1)
            .ok_or(SyncError::Format("counter overflow"))?;
        let header = BlobHeader {
            vault_id: local.vault_id(),
            device_id: state.device_id,
            counter,
            parent_counter,
            parent_hash: p.parent.map_or([0u8; 32], |x| x.1),
            header_hash: p.header_hash,
            created_unix: now_unix,
        };
        let blob = encode_msy1(&header, p.key, &snapshot.encode()?)?;
        let hash = blob_hash(&blob);
        let meta = PutMeta { counter: Some(counter), parent: p.parent.map(|x| hex::encode(x.1)) };
        let body = Bytes::from(blob);
        let written = match p.etag {
            None => remote.put_new(body.clone(), &meta).await?,
            Some(e) => remote.put_cas(e, body.clone(), &meta).await?,
        };
        let PutOutcome::Written { etag } = written else { return Ok(None) };
        if p.apply {
            local.apply(snapshot)?;
        }
        if let Err(e) = remote.put_history(counter, body.clone()).await {
            tracing::warn!(code = e.code(), "sync: history write failed");
        }
        if let Some(old) = counter.checked_sub(self.policy.history_keep) {
            if old > 0 {
                let _ = remote.delete_history(old).await;
            }
        }
        state.last_counter = counter;
        state.last_hash = Some(hex::encode(hash));
        state.last_etag = Some(etag);
        state.last_push_unix = Some(now_unix);
        state.remote_device = Some(local.device_name());
        state.remote_created_unix = Some(now_unix);
        state.alarm = None;
        local.save_state(state, Some(snapshot))?;
        audit.record(&SyncAudit::Push { counter, bytes: body.len() });
        Ok(Some(counter))
    }

    /// Clear a fork or rollback alarm with the user's choice: `Remote` applies the current
    /// remote blob (verified as usual), `Local` publishes this device's data on top of it.
    pub async fn resolve_fork<L: LocalSide, S: ObjectStore>(
        &self,
        local: &L,
        remote: &Remote<S>,
        keep: Keep,
        audit: &dyn AuditSink,
    ) -> Result<Outcome> {
        let mut state = Self::load(local)?;
        if state.alarm.is_none() {
            return Err(SyncError::Invalid("no fork or rollback to resolve"));
        }
        let header = local.header_object()?;
        let key = local.sync_key()?;
        let obj = remote.get().await?;
        let outcome = match keep {
            Keep::Remote => {
                let obj = obj.ok_or(SyncError::Invalid("the remote has no data to keep"))?;
                let f = open(remote, &obj, local.vault_id(), &key, &header).await?;
                self.fast_forward(local, &mut state, &f, audit)?;
                Outcome::Pulled { counter: f.header.counter }
            }
            Keep::Local => {
                let (_, mine) = self.local_view(local)?;
                let parent = obj.as_ref().map(|o| {
                    let c = decode_msy1(&o.bytes).map_or(0, |m| m.header.counter);
                    (c, blob_hash(&o.bytes))
                });
                let p = Publish {
                    key: &key,
                    header_hash: blob_hash(&header),
                    parent: parent.filter(|x| x.0 > 0),
                    etag: obj.as_ref().map(|o| o.etag.as_str()),
                    apply: false,
                };
                remote.put_header(&header).await?;
                let counter = self
                    .publish(local, remote, audit, &mut state, &mine, &p)
                    .await?
                    .ok_or(SyncError::Conflict)?;
                Outcome::Pushed { counter }
            }
        };
        let counter = match &outcome {
            Outcome::Pulled { counter } | Outcome::Pushed { counter } => *counter,
            _ => 0,
        };
        audit.record(&SyncAudit::AlarmResolved { keep, counter });
        Ok(outcome)
    }
}

fn raise<L: LocalSide>(
    local: &L,
    state: &mut LocalState,
    alarm: Alarm,
    audit: &dyn AuditSink,
) -> Result<SyncError> {
    state.alarm = Some(alarm);
    local.save_state(state, None)?;
    match alarm {
        Alarm::Rollback { remote, last } => {
            audit.record(&SyncAudit::RollbackRefused { remote, last });
        }
        Alarm::Fork { remote } => {
            audit.record(&SyncAudit::Fork { remote, last: state.last_counter });
        }
    }
    tracing::warn!(?alarm, "sync: hard stop");
    Ok(alarm_error(alarm))
}

/// Decode, check pairing with the remote header and this device's header, authenticate and
/// parse a remote `current` object.
async fn open<S: ObjectStore>(
    remote: &Remote<S>,
    obj: &Object,
    vault_id: Uuid,
    key: &SubKey,
    local_header: &[u8],
) -> Result<Fetched> {
    let m = decode_msy1(&obj.bytes)?;
    if m.header.vault_id != vault_id {
        return Err(SyncError::WrongVault);
    }
    let remote_header =
        remote.get_header().await?.ok_or(SyncError::HeaderMismatch("remote header is missing"))?;
    if blob_hash(&remote_header) != m.header.header_hash {
        return Err(SyncError::HeaderMismatch("blob is not paired with the remote header"));
    }
    if remote_header != local_header {
        return Err(SyncError::HeaderMismatch("the vault header changed on another device"));
    }
    let plaintext = open_msy1(&m, key)?;
    let snapshot = Snapshot::decode(&plaintext, vault_id)?;
    Ok(Fetched { etag: obj.etag.clone(), hash: blob_hash(&obj.bytes), header: m.header, snapshot })
}
