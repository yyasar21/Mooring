//! [`Inventory`] snapshots keyed by stable `external_id` and the pure [`diff`] that V2 applies
//! in one SQL transaction (ADR-0015 §2). An item missing from [`DELETE_AFTER_MISSES`]
//! consecutive refreshes is removed; the streak counter lives in the store and is passed in.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::VsphereError;
use crate::model::PowerState;

/// Consecutive missing refreshes after which an item is deleted (ADR-0015 §2, owner decision 3).
pub const DELETE_AFTER_MISSES: u8 = 2;

/// Stable key of an item: the managed-object id (`vm-42`, `host-7`, `domain-c8`,
/// `datacenter-3`), or `standalone-<datacenter id>` for the "Standalone hosts" pseudo-cluster.
pub type ExternalId = String;

/// Tree level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// Root level.
    Datacenter,
    /// A cluster, under a datacenter.
    Cluster,
    /// The pseudo-cluster "Standalone hosts", under a datacenter.
    StandaloneHosts,
    /// An `ESXi` host, under a cluster or the pseudo-cluster.
    Host,
    /// A VM, under a host (a connection in the store; everything else is a folder).
    Vm,
}

impl ItemKind {
    fn depth(self) -> u8 {
        match self {
            Self::Datacenter => 0,
            Self::Cluster | Self::StandaloneHosts => 1,
            Self::Host => 2,
            Self::Vm => 3,
        }
    }

    fn parent_ok(self, parent: Option<Self>) -> bool {
        matches!(
            (self, parent),
            (Self::Datacenter, None)
                | (Self::Cluster | Self::StandaloneHosts, Some(Self::Datacenter))
                | (Self::Host, Some(Self::Cluster | Self::StandaloneHosts))
                | (Self::Vm, Some(Self::Host))
        )
    }
}

/// One node of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryItem {
    /// Stable key.
    pub external_id: ExternalId,
    /// Level.
    pub kind: ItemKind,
    /// Display name as vCenter reports it (bounded; the store sanitises).
    pub name: String,
    /// Parent's `external_id` (`None` for datacenters).
    pub parent: Option<ExternalId>,
    /// VMs: power state from the list call.
    pub power_state: Option<PowerState>,
    /// VMs: vCPUs.
    pub cpu_count: Option<u32>,
    /// VMs: memory in MiB.
    pub memory_mib: Option<u64>,
}

/// A validated snapshot: unique ids, every parent present and of the right kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    items: BTreeMap<ExternalId, InventoryItem>,
}

impl Inventory {
    /// Empty snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from items in any order (V2 rebuilds the previous snapshot from the store).
    pub fn from_items(
        items: impl IntoIterator<Item = InventoryItem>,
    ) -> Result<Self, VsphereError> {
        let mut all: Vec<InventoryItem> = items.into_iter().collect();
        all.sort_by_key(|i| i.kind.depth());
        let mut inv = Self::new();
        for i in all {
            inv.insert(i)?;
        }
        Ok(inv)
    }

    /// Add an item whose parent is already present.
    pub fn insert(&mut self, item: InventoryItem) -> Result<(), VsphereError> {
        if self.items.contains_key(&item.external_id) {
            return Err(VsphereError::BadResponse("duplicate inventory id"));
        }
        let parent_kind = match &item.parent {
            None => None,
            Some(p) => Some(
                self.items
                    .get(p)
                    .map(|p| p.kind)
                    .ok_or(VsphereError::BadResponse("orphan item"))?,
            ),
        };
        if !item.kind.parent_ok(parent_kind) {
            return Err(VsphereError::BadResponse("item under the wrong parent kind"));
        }
        self.items.insert(item.external_id.clone(), item);
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: &str) -> Option<&InventoryItem> {
        self.items.get(id)
    }

    /// All items, ordered by id.
    pub fn iter(&self) -> impl Iterator<Item = &InventoryItem> {
        self.items.values()
    }

    /// Item count.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// No items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of VMs.
    pub fn vm_count(&self) -> usize {
        self.items.values().filter(|i| i.kind == ItemKind::Vm).count()
    }
}

/// One item present in both snapshots with a difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// Previous state.
    pub old: InventoryItem,
    /// New state.
    pub new: InventoryItem,
    /// The name changed.
    pub renamed: bool,
    /// The parent changed (vMotion, host moved to another cluster).
    pub moved: bool,
    /// Only power / CPU / memory changed (no tree write needed).
    pub details_only: bool,
}

/// What a refresh changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryDiff {
    /// New items, parents before children.
    pub added: Vec<InventoryItem>,
    /// Items missing for [`DELETE_AFTER_MISSES`] refreshes: delete now, children first.
    pub removed: Vec<ExternalId>,
    /// Items in both snapshots that differ.
    pub changed: Vec<Change>,
    /// Items missing for the first time(s): mark `sync_state = 'missing'`, keep.
    pub missing: Vec<ExternalId>,
    /// Items that were missing before and are back: mark `present`.
    pub restored: Vec<ExternalId>,
    /// The streak map to persist: every still-missing id with its new count. Ids not in it
    /// have a streak of 0.
    pub missing_streak: BTreeMap<ExternalId, u8>,
}

impl InventoryDiff {
    /// Nothing to write.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && self.missing.is_empty()
            && self.restored.is_empty()
    }
}

/// Compare the stored snapshot `old` (including items already marked missing) with the
/// fetched `new`, given the stored streaks. Pure and deterministic (ordered by id/depth).
pub fn diff(
    old: &Inventory,
    new: &Inventory,
    prev_streak: &BTreeMap<ExternalId, u8>,
) -> InventoryDiff {
    let mut d = InventoryDiff::default();
    for n in new.iter() {
        match old.get(&n.external_id) {
            None => d.added.push(n.clone()),
            Some(o) => {
                if prev_streak.get(&n.external_id).copied().unwrap_or(0) > 0 {
                    d.restored.push(n.external_id.clone());
                }
                if o != n {
                    let renamed = o.name != n.name;
                    let moved = o.parent != n.parent || o.kind != n.kind;
                    d.changed.push(Change {
                        old: o.clone(),
                        new: n.clone(),
                        renamed,
                        moved,
                        details_only: !renamed && !moved,
                    });
                }
            }
        }
    }
    let mut removed: Vec<&InventoryItem> = Vec::new();
    for o in old.iter() {
        if new.get(&o.external_id).is_some() {
            continue;
        }
        let streak = prev_streak.get(&o.external_id).copied().unwrap_or(0).saturating_add(1);
        if streak >= DELETE_AFTER_MISSES {
            removed.push(o);
        } else {
            d.missing.push(o.external_id.clone());
            d.missing_streak.insert(o.external_id.clone(), streak);
        }
    }
    d.added.sort_by(|a, b| (a.kind.depth(), &a.external_id).cmp(&(b.kind.depth(), &b.external_id)));
    removed.sort_by(|a, b| (b.kind.depth(), &a.external_id).cmp(&(a.kind.depth(), &b.external_id)));
    d.removed = removed.into_iter().map(|i| i.external_id.clone()).collect();
    d
}

#[cfg(test)]
#[path = "diff_tests.rs"]
mod tests;
