//! Jump-host chains (ADR-0025 §1, migration 0008): `connection_via` rows of a connection.
//!
//! Rules enforced here, on create and update: every hop exists and is `Protocol::Ssh`; the
//! shape rules (depth ≤ 3, no self, no duplicates) come from `mooring_core::validate_via`.
//! A hop's own chain is ignored at connect time, so cycles cannot be followed; they are still
//! refused here as a convenience (`a via b`, `b via a`) because the UI would show a path that
//! never ends. Deleting a connection other chains use is refused with
//! `InUse { kind: "connection" }` (IPC `connection.in_use_as_hop`).

use mooring_core::{Connection, ConnectionId, Protocol};
use rusqlite::{params, OptionalExtension};

use crate::error::{invalid, Result, StoreError};
use crate::util::{parse_id, protocol_from_str};
use crate::Store;

/// Check a chain against the store: existence, protocol and a two-way cycle through the
/// hop's own chain. Shape rules first (no I/O).
pub(crate) fn check_via(conn: &rusqlite::Connection, c: &Connection) -> Result<()> {
    mooring_core::validate_via(c.id, &c.via)?;
    for hop in &c.via {
        let protocol: Option<String> = conn
            .query_row("SELECT protocol FROM connection WHERE id = ?1", [hop.to_string()], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(protocol) = protocol else {
            return Err(invalid("via", "a jump host does not exist"));
        };
        if protocol_from_str(&protocol)? != Protocol::Ssh {
            return Err(invalid("via", "a jump host must be an SSH connection"));
        }
        if via_of(conn, *hop)?.contains(&c.id) {
            return Err(invalid("via", "the jump host already routes through this connection"));
        }
    }
    Ok(())
}

/// The chain of `id`, in position order (empty when none).
pub(crate) fn via_of(conn: &rusqlite::Connection, id: ConnectionId) -> Result<Vec<ConnectionId>> {
    let mut stmt = conn.prepare(
        "SELECT hop_connection_id FROM connection_via WHERE connection_id = ?1 ORDER BY position",
    )?;
    let ids = stmt
        .query_map([id.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ids.iter().map(|s| parse_id(s)).collect()
}

/// Replace the chain of `c.id` inside the caller's transaction.
pub(crate) fn write_via(tx: &rusqlite::Connection, c: &Connection) -> Result<()> {
    let id = c.id.to_string();
    tx.execute("DELETE FROM connection_via WHERE connection_id = ?1", [&id])?;
    let mut stmt = tx.prepare(
        "INSERT INTO connection_via (connection_id, position, hop_connection_id) VALUES (?1, ?2, ?3)",
    )?;
    for (position, hop) in c.via.iter().enumerate() {
        let position = i64::try_from(position).map_err(|_| invalid("via", "too long"))?;
        stmt.execute(params![id, position, hop.to_string()])?;
    }
    Ok(())
}

/// Connections whose chain contains `id`, sorted.
pub(crate) fn used_as_hop_by(
    conn: &rusqlite::Connection,
    id: ConnectionId,
) -> Result<Vec<ConnectionId>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT connection_id FROM connection_via WHERE hop_connection_id = ?1 ORDER BY connection_id",
    )?;
    let ids = stmt
        .query_map([id.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ids.iter().map(|s| parse_id(s)).collect()
}

/// Whether a connection inside the subtree of `folder` is a jump host of a connection
/// outside it (deleting the folder would break that chain; refused before the FK check).
pub(crate) fn subtree_hop_in_use(conn: &rusqlite::Connection, folder: &str) -> Result<bool> {
    Ok(conn.query_row(
        "WITH RECURSIVE sub(id) AS (
             SELECT ?1 UNION SELECT f.id FROM folder f JOIN sub ON f.parent_id = sub.id
         ),
         inside(id) AS (SELECT c.id FROM connection c WHERE c.folder_id IN (SELECT id FROM sub))
         SELECT EXISTS (
             SELECT 1 FROM connection_via v
             WHERE v.hop_connection_id IN (SELECT id FROM inside)
               AND v.connection_id NOT IN (SELECT id FROM inside)
         )",
        [folder],
        |r| r.get(0),
    )?)
}

impl Store {
    /// Ids of the connections that route through `id` (empty when none).
    pub fn connections_via(&self, id: ConnectionId) -> Result<Vec<ConnectionId>> {
        used_as_hop_by(&self.conn, id)
    }

    /// Refuse to delete a connection other chains use.
    pub(crate) fn ensure_not_a_hop(&self, id: ConnectionId) -> Result<()> {
        if used_as_hop_by(&self.conn, id)?.is_empty() {
            Ok(())
        } else {
            Err(StoreError::InUse { kind: "connection", id: id.to_string() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::FolderId;

    fn store() -> (Store, FolderId) {
        let s = Store::open_in_memory().expect("open");
        let root = s.create_folder(None, "root").expect("root");
        (s, root.id)
    }

    fn mk(s: &Store, folder: FolderId, name: &str, p: Protocol) -> Connection {
        let c = Connection::new(folder, name, p, "h.example.test").expect("valid");
        s.create_connection(&c).expect("create")
    }

    #[test]
    fn chains_round_trip_in_order() {
        let (s, f) = store();
        let a = mk(&s, f, "a", Protocol::Ssh);
        let b = mk(&s, f, "b", Protocol::Ssh);
        let mut leaf = mk(&s, f, "leaf", Protocol::Rdp);
        leaf.via = vec![b.id, a.id];
        let stored = s.update_connection(&leaf).expect("update");
        assert_eq!(stored.via, vec![b.id, a.id]);
        assert_eq!(s.get_connection(leaf.id).expect("get").via, vec![b.id, a.id]);
        assert_eq!(s.connections_via(a.id).expect("rev"), vec![leaf.id]);
        leaf.via = vec![a.id];
        assert_eq!(s.update_connection(&leaf).expect("update").via, vec![a.id]);
        assert!(s.connections_via(b.id).expect("rev").is_empty());
        leaf.via.clear();
        assert!(s.update_connection(&leaf).expect("update").via.is_empty());
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn validation_table() {
        let (s, f) = store();
        let a = mk(&s, f, "a", Protocol::Ssh);
        let b = mk(&s, f, "b", Protocol::Ssh);
        let c = mk(&s, f, "c", Protocol::Ssh);
        let d = mk(&s, f, "d", Protocol::Ssh);
        let rdp = mk(&s, f, "rdp", Protocol::Rdp);
        let mut leaf = mk(&s, f, "leaf", Protocol::Ssh);
        let refused = |via: Vec<ConnectionId>, needle: &str| {
            let mut l = leaf.clone();
            l.via = via;
            let e = s.update_connection(&l).expect_err(needle);
            match e {
                StoreError::Invalid { field: "via", reason } => {
                    assert!(reason.contains(needle), "{reason}");
                }
                other => panic!("{needle}: {other:?}"),
            }
        };
        refused(vec![leaf.id], "own jump host");
        refused(vec![a.id, a.id], "twice");
        refused(vec![a.id, b.id, c.id, d.id], "at most 3");
        refused(vec![rdp.id], "SSH connection");
        refused(vec![ConnectionId::new()], "does not exist");
        leaf.via = vec![a.id, b.id, c.id];
        s.update_connection(&leaf).expect("depth 3 is fine");
        // a via leaf would make a two-way cycle: refused.
        let mut a2 = a.clone();
        a2.via = vec![leaf.id];
        assert!(matches!(s.update_connection(&a2), Err(StoreError::Invalid { field: "via", .. })));
        // Create path checks the same rules.
        let mut fresh =
            Connection::new(f, "fresh", Protocol::Vnc, "h.example.test").expect("valid");
        fresh.via = vec![rdp.id];
        assert!(matches!(
            s.create_connection(&fresh),
            Err(StoreError::Invalid { field: "via", .. })
        ));
        fresh.via = vec![a.id];
        assert_eq!(s.create_connection(&fresh).expect("create").via, vec![a.id]);
    }

    #[test]
    fn deleting_a_hop_in_use_is_refused_and_the_leaf_cascades() {
        let (s, f) = store();
        let a = mk(&s, f, "a", Protocol::Ssh);
        let mut leaf = mk(&s, f, "leaf", Protocol::Ssh);
        leaf.via = vec![a.id];
        s.update_connection(&leaf).expect("update");
        let e = s.delete_connection(a.id).expect_err("in use");
        assert!(matches!(e, StoreError::InUse { kind: "connection", .. }), "{e:?}");
        assert!(!e.to_string().contains("secret"));
        s.delete_connection(leaf.id).expect("leaf goes with its chain");
        assert!(s.connections_via(a.id).expect("rev").is_empty());
        s.delete_connection(a.id).expect("free now");
    }

    #[test]
    fn folder_delete_cascade_is_blocked_by_an_outside_leaf() {
        let (s, f) = store();
        let sub = s.create_folder(Some(f), "sub").expect("sub");
        let hop = mk(&s, sub.id, "hop", Protocol::Ssh);
        let mut leaf = mk(&s, f, "leaf", Protocol::Ssh);
        leaf.via = vec![hop.id];
        s.update_connection(&leaf).expect("update");
        // Refused before SQLite's RESTRICT, with the same `InUse` as a single delete; never a
        // half-deleted subtree.
        let e = s.delete_folder(sub.id).expect_err("in use");
        assert!(matches!(e, StoreError::InUse { kind: "connection", .. }), "{e:?}");
        assert!(s.get_connection(hop.id).is_ok());
        // A chain wholly inside the subtree goes with it.
        let mut inner = mk(&s, sub.id, "inner", Protocol::Ssh);
        inner.via = vec![hop.id];
        s.update_connection(&inner).expect("update");
        leaf.via.clear();
        s.update_connection(&leaf).expect("update");
        s.delete_folder(sub.id).expect("self-contained subtree");
    }
}
