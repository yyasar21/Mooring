//! Three-way merge of snapshots (ADR-0017 §3), per record id against the last synced base.
//!
//! | base | local | remote | result |
//! | --- | --- | --- | --- |
//! | b | b | r | r (and the mirror) |
//! | b | l | r, l ≠ r | field-wise: a field changed on one side is taken; if a field changed on both sides to different values it is a **true conflict** |
//! | – | l | r, l ≠ r | add/add: every differing field is a true conflict |
//! | b | – | b / r ≠ b | delete / delete vs edit → keep the edit ([`Resolution::KeptEdit`]) |
//! | – | l | – (remote tombstone) | last writer wins between the edit time and the deletion time |
//!
//! True conflicts: folders take the newer `updated_at` (last writer wins, reported; a folder
//! holds no secret and an empty duplicate helps nobody). Connections and credentials keep
//! **both** copies: the local one keeps its id, the remote one gets a new id and the name
//! suffix ` (conflict from <device>)`; a credential copy has its sealed secrets re-sealed to
//! the new id ([`Reseal`]) because the AAD binds the record id. A secret is never silently
//! overwritten. `updated_at` of a merged record is the later of both sides.
//!
//! [`fixup`] then repairs references the merge can break (missing parents, cycles, several
//! roots, dangling credential references).

use std::collections::{BTreeMap, BTreeSet};

use mooring_store::{ConnectionRow, CredentialRow, FolderRow};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Result, SyncError};
use crate::snapshot::{prune_tombstones, tomb_key, RecordKind, Snapshot, Tombstone};

/// How a conflict was settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Resolution {
    /// Both copies kept; the remote one is `copy_id`.
    KeptBoth {
        /// Id of the remote copy.
        copy_id: String,
    },
    /// One side deleted, the other edited: the edit is kept.
    KeptEdit,
    /// The newer `updated_at` won.
    LastWriterWins,
}

/// One reported conflict (ids and names only, no field values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// Table.
    pub kind: RecordKind,
    /// Record id (the local copy's id for `KeptBoth`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// What happened.
    pub resolution: Resolution,
}

/// Re-seal one sealed secret from `old_id` to `new_id` (same secret name).
pub trait Reseal {
    /// Open under (`old_id`, `secret`) and seal under (`new_id`, `secret`).
    fn reseal(&self, old_id: &str, new_id: &str, secret: &str, sealed: &str) -> Result<String>;
}

/// Inputs that are not snapshots.
#[derive(Debug, Clone, Copy)]
pub struct MergeCtx<'a> {
    /// Remote writer's display name for the conflict suffix.
    pub remote_device: &'a str,
    /// RFC 3339 "now".
    pub now: &'a str,
}

/// Result of a merge: the snapshot to publish and apply, and the conflict list.
#[derive(Debug, Clone)]
pub struct MergePlan {
    /// The merged snapshot.
    pub snapshot: Snapshot,
    /// Every conflict, in table then id order.
    pub conflicts: Vec<Conflict>,
}

trait Row: Clone + PartialEq + Serialize + DeserializeOwned {
    const KIND: RecordKind;
    fn name(&self) -> &str;
    fn updated_at(&self) -> &str;
    fn set_identity(&mut self, id: &str, name: String);
}

macro_rules! row {
    ($t:ty, $k:expr) => {
        impl Row for $t {
            const KIND: RecordKind = $k;
            fn name(&self) -> &str {
                &self.name
            }
            fn updated_at(&self) -> &str {
                &self.updated_at
            }
            fn set_identity(&mut self, id: &str, name: String) {
                id.clone_into(&mut self.id);
                self.name = name;
            }
        }
    };
}
row!(FolderRow, RecordKind::Folder);
row!(ConnectionRow, RecordKind::Connection);
row!(CredentialRow, RecordKind::Credential);

fn obj<R: Serialize>(r: &R) -> Result<Map<String, Value>> {
    match serde_json::to_value(r) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(SyncError::Format("row is not an object")),
    }
}

/// Field-wise three-way merge; `None` = a true conflict.
fn merge_fields<R: Row>(base: Option<&R>, l: &R, r: &R) -> Result<Option<R>> {
    let (lm, rm) = (obj(l)?, obj(r)?);
    let bm = base.map(obj).transpose()?;
    let mut out = Map::new();
    for key in lm.keys().chain(rm.keys()).collect::<BTreeSet<_>>() {
        let (lv, rv) = (lm.get(key), rm.get(key));
        let bv = bm.as_ref().and_then(|b| b.get(key));
        let text = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or_default().to_owned();
        let v = match key.as_str() {
            "updated_at" | "created_at" => {
                let newer = text(lv) >= text(rv);
                if newer == (key == "updated_at") {
                    lv
                } else {
                    rv
                }
            }
            _ if lv == rv => lv,
            _ if bm.is_some() && lv == bv => rv,
            _ if bm.is_some() && rv == bv => lv,
            _ => return Ok(None),
        };
        if let Some(v) = v {
            out.insert(key.clone(), v.clone());
        }
    }
    serde_json::from_value(Value::Object(out))
        .map(Some)
        .map_err(|_| SyncError::Format("merged row"))
}

fn suffixed(name: &str, device: &str) -> String {
    let suffix = format!(" (conflict from {device})");
    let room = mooring_core::model::MAX_NAME.saturating_sub(suffix.chars().count());
    let n: String = name.chars().take(room).collect();
    let mut n = n.trim_end().to_owned();
    if n.is_empty() {
        n.push('?');
    }
    n + &suffix
}

struct Table<'a, R> {
    base: Option<&'a BTreeMap<String, R>>,
    local: &'a BTreeMap<String, R>,
    remote: &'a BTreeMap<String, R>,
    local_tombs: &'a BTreeMap<String, Tombstone>,
    remote_tombs: &'a BTreeMap<String, Tombstone>,
}

#[allow(clippy::many_single_char_names)] // b / l / r = base, local, remote
fn merge_table<R: Row>(
    t: &Table<'_, R>,
    copy: &mut dyn FnMut(&R, &str) -> Result<R>,
    conflicts: &mut Vec<Conflict>,
) -> Result<BTreeMap<String, R>> {
    let mut out = BTreeMap::new();
    let ids: BTreeSet<&String> = t
        .local
        .keys()
        .chain(t.remote.keys())
        .chain(t.base.into_iter().flat_map(BTreeMap::keys))
        .collect();
    let report = |conflicts: &mut Vec<Conflict>, id: &str, name: &str, resolution| {
        conflicts.push(Conflict {
            kind: R::KIND,
            id: id.to_owned(),
            name: name.to_owned(),
            resolution,
        });
    };
    for id in ids {
        let b = t.base.and_then(|m| m.get(id));
        let (l, r) = (t.local.get(id), t.remote.get(id));
        let survives = |row: &R, tombs: &BTreeMap<String, Tombstone>| {
            tombs
                .get(&tomb_key(R::KIND, id))
                .is_none_or(|d| row.updated_at() > d.deleted_at.as_str())
        };
        match (b, l, r) {
            (_, Some(l), Some(r)) if l == r => {
                out.insert(id.clone(), l.clone());
            }
            (b, Some(l), Some(r)) if b == Some(l) => {
                out.insert(id.clone(), r.clone());
            }
            (b, Some(l), Some(r)) if b == Some(r) => {
                out.insert(id.clone(), l.clone());
            }
            (b, Some(l), Some(r)) => {
                if let Some(m) = merge_fields(b, l, r)? {
                    out.insert(id.clone(), m);
                } else if R::KIND == RecordKind::Folder {
                    let win = if r.updated_at() > l.updated_at() { r } else { l };
                    out.insert(id.clone(), win.clone());
                    report(conflicts, id, win.name(), Resolution::LastWriterWins);
                } else {
                    let copy_id = uuid::Uuid::new_v4().to_string();
                    let c = copy(r, &copy_id)?;
                    out.insert(id.clone(), l.clone());
                    out.insert(copy_id.clone(), c);
                    report(conflicts, id, l.name(), Resolution::KeptBoth { copy_id });
                }
            }
            (Some(b), Some(l), None) | (Some(b), None, Some(l)) => {
                if l != b {
                    out.insert(id.clone(), l.clone());
                    report(conflicts, id, l.name(), Resolution::KeptEdit);
                }
            }
            (None, Some(l), None) => {
                if survives(l, t.remote_tombs) {
                    out.insert(id.clone(), l.clone());
                }
            }
            (None, None, Some(r)) => {
                if survives(r, t.local_tombs) {
                    out.insert(id.clone(), r.clone());
                }
            }
            (_, None, None) => {}
        }
    }
    Ok(out)
}

/// Line-set three-way merge of one trust file: a line stays when both sides have it or one
/// side added it; a line one side removed (present in base) goes.
fn merge_lines(
    base: Option<&BTreeSet<String>>,
    l: Option<&BTreeSet<String>>,
    r: Option<&BTreeSet<String>>,
) -> BTreeSet<String> {
    let empty = BTreeSet::new();
    let (b, l, r) = (base.unwrap_or(&empty), l.unwrap_or(&empty), r.unwrap_or(&empty));
    l.union(r).filter(|x| (l.contains(*x) && r.contains(*x)) || !b.contains(*x)).cloned().collect()
}

/// Merge `local` and `remote` against `base` (`None` on a device's first sync).
pub fn merge(
    base: Option<&Snapshot>,
    local: &Snapshot,
    remote: &Snapshot,
    ctx: MergeCtx<'_>,
    reseal: &dyn Reseal,
) -> Result<MergePlan> {
    let mut conflicts = Vec::new();
    let (lt, rt) = (&local.tombstones, &remote.tombstones);
    let device = ctx.remote_device;
    let mut out = Snapshot::empty(local.vault_id, &local.device_name);
    out.folders = merge_table(
        &Table {
            base: base.map(|b| &b.folders),
            local: &local.folders,
            remote: &remote.folders,
            local_tombs: lt,
            remote_tombs: rt,
        },
        &mut |r: &FolderRow, _| Ok(r.clone()),
        &mut conflicts,
    )?;
    out.connections = merge_table(
        &Table {
            base: base.map(|b| &b.connections),
            local: &local.connections,
            remote: &remote.connections,
            local_tombs: lt,
            remote_tombs: rt,
        },
        &mut |r: &ConnectionRow, new_id| {
            let mut c = r.clone();
            c.set_identity(new_id, suffixed(&r.name, device));
            Ok(c)
        },
        &mut conflicts,
    )?;
    out.credentials = merge_table(
        &Table {
            base: base.map(|b| &b.credentials),
            local: &local.credentials,
            remote: &remote.credentials,
            local_tombs: lt,
            remote_tombs: rt,
        },
        &mut |r: &CredentialRow, new_id| {
            let mut c = r.clone();
            c.set_identity(new_id, suffixed(&r.name, device));
            for (secret, sealed) in &mut c.secrets {
                *sealed = reseal.reseal(&r.id, new_id, secret, sealed)?;
            }
            Ok(c)
        },
        &mut conflicts,
    )?;
    let names: BTreeSet<&String> = local.trust.keys().chain(remote.trust.keys()).collect();
    for name in names {
        let lines = merge_lines(
            base.and_then(|b| b.trust.get(name)),
            local.trust.get(name),
            remote.trust.get(name),
        );
        if !lines.is_empty() {
            out.trust.insert(name.clone(), lines);
        }
    }
    out.tombstones = lt.clone();
    for (k, t) in rt {
        let newer = out.tombstones.get(k).is_none_or(|have| t.deleted_at > have.deleted_at);
        if newer {
            out.tombstones.insert(k.clone(), t.clone());
        }
    }
    fixup(&mut out, remote);
    prune_tombstones(&mut out);
    Ok(MergePlan { snapshot: out, conflicts })
}

pub use crate::fixup::fixup;
