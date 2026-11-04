//! vSphere-synced subtrees (ADR-0015 §2, migration 0006).
//!
//! A vCenter connection (the *source*) owns one synced root folder and, below it, one folder
//! per datacenter / cluster / "Standalone hosts" / host and one `vsphere-console` connection
//! per VM. The store knows nothing about vSphere types: the caller hands it [`SyncNode`]s
//! (external id, kind, parent external id, name, opaque JSON data) and a [`SyncPlan`] computed
//! from them, and [`Store::apply_inventory_diff`] writes the plan in **one** transaction.
//!
//! Ordinary edits inside a synced subtree fail with [`StoreError::SyncedReadOnly`]; the
//! overlays (credential, tags, username/domain overrides, role credentials, options, a
//! folder's default credential) are ordinary columns the plan never touches.

use std::collections::{BTreeMap, HashMap};

use mooring_core::{ConnectionId, Folder, FolderId, Protocol};
use rusqlite::{params, Connection as Sql, OptionalExtension};

use crate::error::{invalid, not_found, Result, StoreError};
use crate::util::{fmt_ts, now, parse_id};
use crate::{Store, MAX_NAME};

/// Folder levels of a synced tree; `vm` rows are connections.
pub const FOLDER_KINDS: [&str; 4] = ["datacenter", "cluster", "standalone_hosts", "host"];
/// The connection level.
pub const VM_KIND: &str = "vm";
/// Largest `sync_data` JSON text.
pub const MAX_SYNC_DATA: usize = 4096;
/// Longest external id (vSphere managed-object id, `standalone-` prefix included).
pub const MAX_EXTERNAL_ID: usize = 80;

/// One inventory item as the store persists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncNode {
    /// Managed-object id, `[a-z0-9-]`, unique per source.
    pub external_id: String,
    /// One of [`FOLDER_KINDS`] or [`VM_KIND`].
    pub kind: String,
    /// Parent's external id; `None` = directly under the synced root.
    pub parent: Option<String>,
    /// The name as vCenter reports it (≤ 255 bytes). The display name is sanitised from it.
    pub name: String,
    /// Opaque JSON object (≤ [`MAX_SYNC_DATA`]): what the caller needs to rebuild its
    /// previous snapshot (raw name, power state, CPU, memory).
    pub data: String,
}

/// A stored synced row: the node, its streak, and the folder / connection id it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedRow {
    /// The stored node.
    pub node: SyncNode,
    /// Consecutive refreshes it was missing.
    pub streak: u8,
    /// Folder id (folder kinds) or connection id (VMs).
    pub id: String,
}

/// What one refresh writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncPlan {
    /// Added or changed nodes, parents before children.
    pub upsert: Vec<SyncNode>,
    /// External ids to delete (two consecutive misses), children first.
    pub remove: Vec<String>,
    /// Still-missing external ids with their new streak (kept, marked `missing`). Every
    /// other row of the source gets streak 0 and `present`.
    pub missing: BTreeMap<String, u8>,
}

/// Counts of an applied plan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncCounts {
    /// Inserted rows.
    pub added: u64,
    /// Updated rows.
    pub changed: u64,
    /// Rows marked missing.
    pub missing: u64,
    /// Deleted rows.
    pub removed: u64,
}

/// Sync columns of one row, for the tree DTOs and the vSphere commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncFlags {
    /// The vCenter connection id.
    pub source: String,
    /// `None` on the synced root.
    pub external_id: Option<String>,
    /// Connections: `present` | `missing`.
    pub state: Option<String>,
    /// Connections: the stored `sync_data`.
    pub data: Option<String>,
}

/// Display name of a synced item: forbidden characters dropped, whitespace collapsed, at most
/// [`MAX_NAME`] characters; the external id when nothing is left.
pub fn display_name(raw: &str, external_id: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !mooring_core::is_bidi_or_invisible(*c))
        .collect();
    let joined = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let name: String = joined.chars().take(MAX_NAME).collect();
    let name = name.trim().to_owned();
    if name.is_empty() {
        external_id.to_owned()
    } else {
        name
    }
}

fn check_node(n: &SyncNode) -> Result<()> {
    let id_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= MAX_EXTERNAL_ID
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !id_ok(&n.external_id) || n.parent.as_deref().is_some_and(|p| !id_ok(p)) {
        return Err(invalid("externalId", "must be [a-z0-9-], at most 80 bytes"));
    }
    if n.kind != VM_KIND && !FOLDER_KINDS.contains(&n.kind.as_str()) {
        return Err(invalid("kind", "unknown inventory kind"));
    }
    if n.name.len() > 255 {
        return Err(invalid("name", "longer than 255 bytes"));
    }
    let object = serde_json::from_str::<serde_json::Value>(&n.data).is_ok_and(|v| v.is_object());
    if n.data.len() > MAX_SYNC_DATA || !object {
        return Err(invalid("data", "must be a JSON object of at most 4 KiB"));
    }
    Ok(())
}

/// The source of a synced folder, if it is synced.
pub(crate) fn folder_source(conn: &Sql, id: FolderId) -> Result<Option<String>> {
    let row: Option<Option<String>> = conn
        .query_row("SELECT sync_source FROM folder WHERE id = ?1", [id.to_string()], |r| r.get(0))
        .optional()?;
    Ok(row.flatten())
}

/// The source of a synced connection, if it is synced.
pub(crate) fn connection_source(conn: &Sql, id: ConnectionId) -> Result<Option<String>> {
    let row: Option<Option<String>> = conn
        .query_row("SELECT sync_source FROM connection WHERE id = ?1", [id.to_string()], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(row.flatten())
}

/// Refuse an ordinary edit of / into a synced folder.
pub(crate) fn ensure_folder_editable(conn: &Sql, id: FolderId) -> Result<()> {
    match folder_source(conn, id)? {
        Some(_) => Err(StoreError::SyncedReadOnly),
        None => Ok(()),
    }
}

fn root_of(conn: &Sql, source: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT id FROM folder WHERE sync_source = ?1 AND external_id IS NULL",
            [source],
            |r| r.get(0),
        )
        .optional()?)
}

impl Store {
    /// The synced root of a vCenter connection, if it has one.
    pub fn sync_root(&self, source: ConnectionId) -> Result<Option<FolderId>> {
        root_of(&self.conn, &source.to_string())?.map(|s| parse_id(&s)).transpose()
    }

    /// Create the synced root `name` under `parent` for the vCenter connection `source`
    /// (idempotent: an existing root is returned). The source must be a non-synced
    /// `vsphere-console` connection and `parent` a non-synced folder.
    pub fn sync_enable(
        &self,
        source: ConnectionId,
        parent: FolderId,
        name: &str,
    ) -> Result<Folder> {
        if let Some(root) = self.sync_root(source)? {
            return self.get_folder(root);
        }
        let c = self.get_connection(source)?;
        if c.protocol != Protocol::VsphereConsole {
            return Err(invalid("connectionId", "not a vCenter connection"));
        }
        if connection_source(&self.conn, source)?.is_some() {
            return Err(StoreError::SyncedReadOnly);
        }
        let folder = Folder::new(Some(parent), display_name(name, "vCenter"))?;
        let tx = self.conn.unchecked_transaction()?;
        if !crate::folders::folder_exists(&tx, parent)? {
            return Err(not_found("folder", &parent));
        }
        ensure_folder_editable(&tx, parent)?;
        let ts = fmt_ts(now())?;
        tx.execute(
            "INSERT INTO folder (id, parent_id, name, default_credential_id, sort, created_at,
                                 updated_at, sync_source)
             VALUES (?1, ?2, ?3, NULL, 0, ?4, ?4, ?5)",
            params![folder.id.to_string(), parent.to_string(), folder.name, ts, source.to_string()],
        )?;
        tx.commit()?;
        Ok(folder)
    }

    /// Unbind the subtree of `source`. `keep = true` turns every synced row into an ordinary
    /// one (the tree stays, editable); `keep = false` deletes the root and everything below.
    /// Returns whether a subtree existed.
    pub fn sync_disable(&self, source: ConnectionId, keep: bool) -> Result<bool> {
        let src = source.to_string();
        let tx = self.conn.unchecked_transaction()?;
        let Some(root) = root_of(&tx, &src)? else { return Ok(false) };
        if keep {
            tx.execute(
                "UPDATE connection SET sync_source = NULL, external_id = NULL, sync_state = NULL,
                        sync_data = NULL, missing_streak = 0 WHERE sync_source = ?1",
                [&src],
            )?;
            tx.execute(
                "UPDATE folder SET sync_source = NULL, external_id = NULL, sync_kind = NULL,
                        sync_data = NULL, missing_streak = 0 WHERE sync_source = ?1",
                [&src],
            )?;
        } else {
            tx.execute("DELETE FROM folder WHERE id = ?1", [&root])?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Every synced row of `source` (the root excluded), for rebuilding the last snapshot.
    pub fn synced_rows(&self, source: ConnectionId) -> Result<Vec<SyncedRow>> {
        let src = source.to_string();
        let mut out = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT f.id, f.external_id, f.sync_kind, p.external_id, f.sync_data, f.missing_streak
             FROM folder f JOIN folder p ON p.id = f.parent_id
             WHERE f.sync_source = ?1 AND f.external_id IS NOT NULL",
        )?;
        let folders = stmt.query_map([&src], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?;
        for row in folders {
            out.push(decode_row(row?)?);
        }
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.external_id, 'vm', p.external_id, c.sync_data, c.missing_streak
             FROM connection c JOIN folder p ON p.id = c.folder_id
             WHERE c.sync_source = ?1 AND c.external_id IS NOT NULL",
        )?;
        let vms = stmt.query_map([&src], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?;
        for row in vms {
            out.push(decode_row(row?)?);
        }
        Ok(out)
    }

    /// Write one refresh of `source` in a single transaction: upserts (parents first), the
    /// streak reset and `missing` marks, then deletions (children first). Nothing is written
    /// when any step fails.
    pub fn apply_inventory_diff(
        &self,
        source: ConnectionId,
        plan: &SyncPlan,
    ) -> Result<SyncCounts> {
        for n in &plan.upsert {
            check_node(n)?;
        }
        let src = source.to_string();
        let tx = self.conn.unchecked_transaction()?;
        let root =
            root_of(&tx, &src)?.ok_or_else(|| invalid("connectionId", "sync not enabled"))?;
        let (host, port): (String, Option<u16>) =
            tx.query_row("SELECT host, port FROM connection WHERE id = ?1", [&src], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        let ts = fmt_ts(now())?;
        let mut counts = SyncCounts::default();
        let mut folders: HashMap<String, String> = HashMap::new();
        for n in &plan.upsert {
            let parent = match &n.parent {
                None => root.clone(),
                Some(p) => match folders.get(p) {
                    Some(id) => id.clone(),
                    None => folder_by_external(&tx, &src, p)?
                        .ok_or_else(|| invalid("parent", "unknown parent item"))?,
                },
            };
            let name = display_name(&n.name, &n.external_id);
            let inserted = if n.kind == VM_KIND {
                upsert_vm(&tx, &src, n, &parent, &name, (&host, port), &ts)?
            } else {
                let (id, inserted) = upsert_folder(&tx, &src, n, &parent, &name, &ts)?;
                folders.insert(n.external_id.clone(), id);
                inserted
            };
            if inserted {
                counts.added += 1;
            } else {
                counts.changed += 1;
            }
        }
        tx.execute(
            "UPDATE connection SET missing_streak = 0, sync_state = 'present' WHERE sync_source = ?1",
            [&src],
        )?;
        tx.execute("UPDATE folder SET missing_streak = 0 WHERE sync_source = ?1", [&src])?;
        for (ext, streak) in &plan.missing {
            let n = tx.execute(
                "UPDATE connection SET missing_streak = ?3, sync_state = 'missing'
                 WHERE sync_source = ?1 AND external_id = ?2",
                params![src, ext, streak],
            )? + tx.execute(
                "UPDATE folder SET missing_streak = ?3 WHERE sync_source = ?1 AND external_id = ?2",
                params![src, ext, streak],
            )?;
            counts.missing += n as u64;
        }
        for ext in &plan.remove {
            let n = tx.execute(
                "DELETE FROM connection WHERE sync_source = ?1 AND external_id = ?2",
                params![src, ext],
            )? + tx.execute(
                "DELETE FROM folder WHERE sync_source = ?1 AND external_id = ?2",
                params![src, ext],
            )?;
            counts.removed += n as u64;
        }
        tx.commit()?;
        Ok(counts)
    }

    /// Sync columns of a connection (`None` for an ordinary one).
    pub fn connection_sync(&self, id: ConnectionId) -> Result<Option<SyncFlags>> {
        let row: Option<SyncCols> = self
            .conn
            .query_row(
                "SELECT sync_source, external_id, sync_state, sync_data FROM connection
                     WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (source, external_id, state, data) = row.ok_or_else(|| not_found("connection", &id))?;
        Ok(source.map(|source| SyncFlags { source, external_id, state, data }))
    }

    /// Sync columns of every synced folder and connection, by row id (tree DTOs).
    pub fn sync_flags(&self) -> Result<HashMap<String, SyncFlags>> {
        let mut out = HashMap::new();
        for sql in [
            "SELECT id, sync_source, external_id, NULL FROM folder WHERE sync_source IS NOT NULL",
            "SELECT id, sync_source, external_id, sync_state FROM connection
             WHERE sync_source IS NOT NULL",
        ] {
            let mut stmt = self.conn.prepare(sql)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            for row in rows {
                let (id, source, external_id, state) = row?;
                out.insert(id, SyncFlags { source, external_id, state, data: None });
            }
        }
        Ok(out)
    }

    /// vCenter connections that own a synced root (the scheduler's list).
    pub fn sync_sources(&self) -> Result<Vec<ConnectionId>> {
        let mut stmt = self.conn.prepare(
            "SELECT sync_source FROM folder WHERE sync_source IS NOT NULL AND external_id IS NULL
             ORDER BY sync_source",
        )?;
        let ids = stmt.query_map([], |r| r.get::<_, String>(0))?;
        ids.map(|r| parse_id(&r?)).collect()
    }
}

/// `(sync_source, external_id, sync_state, sync_data)` of a connection row.
type SyncCols = (Option<String>, Option<String>, Option<String>, Option<String>);

type RawRow = (String, String, String, Option<String>, Option<String>, i64);

fn decode_row(raw: RawRow) -> Result<SyncedRow> {
    let (id, external_id, kind, parent, data, streak) = raw;
    let data = data.unwrap_or_else(|| "{}".to_owned());
    let name = serde_json::from_str::<serde_json::Value>(&data)
        .ok()
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_owned))
        .unwrap_or_default();
    Ok(SyncedRow {
        node: SyncNode { external_id, kind, parent, name, data },
        streak: u8::try_from(streak).map_err(|_| StoreError::Corrupt { what: "missing_streak" })?,
        id,
    })
}

fn folder_by_external(tx: &Sql, src: &str, ext: &str) -> Result<Option<String>> {
    Ok(tx
        .query_row(
            "SELECT id FROM folder WHERE sync_source = ?1 AND external_id = ?2",
            params![src, ext],
            |r| r.get(0),
        )
        .optional()?)
}

fn upsert_folder(
    tx: &Sql,
    src: &str,
    n: &SyncNode,
    parent: &str,
    name: &str,
    ts: &str,
) -> Result<(String, bool)> {
    if let Some(id) = folder_by_external(tx, src, &n.external_id)? {
        tx.execute(
            "UPDATE folder SET parent_id = ?2, name = ?3, sync_kind = ?4, sync_data = ?5,
                    updated_at = ?6 WHERE id = ?1",
            params![id, parent, name, n.kind, n.data, ts],
        )?;
        return Ok((id, false));
    }
    let id = FolderId::new().to_string();
    tx.execute(
        "INSERT INTO folder (id, parent_id, name, default_credential_id, sort, created_at,
                             updated_at, sync_source, external_id, sync_kind, sync_data)
         VALUES (?1, ?2, ?3, NULL, 0, ?4, ?4, ?5, ?6, ?7, ?8)",
        params![id, parent, name, ts, src, n.external_id, n.kind, n.data],
    )?;
    Ok((id, true))
}

fn upsert_vm(
    tx: &Sql,
    src: &str,
    n: &SyncNode,
    folder: &str,
    name: &str,
    (host, port): (&str, Option<u16>),
    ts: &str,
) -> Result<bool> {
    let updated = tx.execute(
        "UPDATE connection SET folder_id = ?3, name = ?4, sync_data = ?5, updated_at = ?6
         WHERE sync_source = ?1 AND external_id = ?2",
        params![src, n.external_id, folder, name, n.data, ts],
    )?;
    if updated > 0 {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id,
                                 created_at, updated_at, sync_source, external_id, sync_state,
                                 sync_data)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7, ?8, ?9, 'present', ?10)",
        params![
            ConnectionId::new().to_string(),
            folder,
            name,
            Protocol::VsphereConsole.name(),
            host,
            port,
            ts,
            src,
            n.external_id,
            n.data
        ],
    )?;
    Ok(true)
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
