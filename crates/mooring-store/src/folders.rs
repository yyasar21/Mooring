//! Folder CRUD and the tree invariants of `mooring_core::tree` enforced in SQL:
//! exactly one root, parents must exist, the root cannot be moved, and a move may not create
//! a cycle. Deleting a folder cascades to sub-folders, connections and their tags. Inside a
//! vSphere-synced subtree create / rename / move / delete fail with `SyncedReadOnly`.

use mooring_core::{CredentialId, Folder, FolderId};
use rusqlite::{params, OptionalExtension, Row};

use crate::error::{not_found, Result, StoreError};
use crate::sync::ensure_folder_editable;
use crate::util::{check_name, fmt_ts, now, parse_id, parse_opt_id};
use crate::Store;

const FOLDER_COLS: &str = "id, parent_id, name, default_credential_id";

fn row_to_folder(
    r: &Row<'_>,
) -> rusqlite::Result<(String, Option<String>, String, Option<String>)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

fn decode(raw: (String, Option<String>, String, Option<String>)) -> Result<Folder> {
    let (id, parent, name, cred) = raw;
    Ok(Folder {
        id: parse_id(&id)?,
        parent: parse_opt_id(parent.as_deref())?,
        name,
        default_credential: parse_opt_id(cred.as_deref())?,
    })
}

impl Store {
    /// Create a folder. `parent == None` creates the root, which is allowed once.
    pub fn create_folder(&self, parent: Option<FolderId>, name: &str) -> Result<Folder> {
        let folder = Folder::new(parent, name)?;
        let tx = self.conn.unchecked_transaction()?;
        if let Some(p) = parent {
            if !folder_exists(&tx, p)? {
                return Err(not_found("folder", &p));
            }
            ensure_folder_editable(&tx, p)?;
        } else {
            let roots: i64 =
                tx.query_row("SELECT count(*) FROM folder WHERE parent_id IS NULL", [], |r| {
                    r.get(0)
                })?;
            if roots > 0 {
                return Err(StoreError::Tree("only one root folder is allowed".into()));
            }
        }
        let ts = fmt_ts(now())?;
        tx.execute(
            "INSERT INTO folder (id, parent_id, name, default_credential_id, sort, created_at,
                                 updated_at)
             VALUES (?1, ?2, ?3, NULL, 0, ?4, ?4)",
            params![folder.id.to_string(), parent.map(|p| p.to_string()), folder.name, ts],
        )?;
        tx.commit()?;
        Ok(folder)
    }

    /// The root folder, if one exists.
    pub fn root_folder(&self) -> Result<Option<Folder>> {
        let sql = format!("SELECT {FOLDER_COLS} FROM folder WHERE parent_id IS NULL");
        self.conn.query_row(&sql, [], row_to_folder).optional()?.map(decode).transpose()
    }

    /// Look up one folder.
    pub fn get_folder(&self, id: FolderId) -> Result<Folder> {
        let sql = format!("SELECT {FOLDER_COLS} FROM folder WHERE id = ?1");
        let raw = self.conn.query_row(&sql, [id.to_string()], row_to_folder).optional()?;
        decode(raw.ok_or_else(|| not_found("folder", &id))?)
    }

    /// Every folder, ordered by `sort` then name.
    pub fn list_folders(&self) -> Result<Vec<Folder>> {
        let sql = format!("SELECT {FOLDER_COLS} FROM folder ORDER BY sort, name, id");
        self.collect(&sql, &[])
    }

    /// Direct children of a folder, ordered by `sort` then name.
    pub fn child_folders(&self, parent: FolderId) -> Result<Vec<Folder>> {
        let sql = format!(
            "SELECT {FOLDER_COLS} FROM folder WHERE parent_id = ?1 ORDER BY sort, name, id"
        );
        self.collect(&sql, &[&parent.to_string()])
    }

    fn collect(&self, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<Folder>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(args, row_to_folder)?;
        rows.map(|r| decode(r?)).collect()
    }

    /// Rename a folder.
    pub fn rename_folder(&self, id: FolderId, name: &str) -> Result<()> {
        let name = check_name("name", name)?;
        ensure_folder_editable(&self.conn, id)?;
        let n = self.conn.execute(
            "UPDATE folder SET name = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), name, fmt_ts(now())?],
        )?;
        if n == 0 {
            return Err(not_found("folder", &id));
        }
        Ok(())
    }

    /// Set the sort key used to order siblings.
    pub fn set_folder_sort(&self, id: FolderId, sort: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE folder SET sort = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), sort, fmt_ts(now())?],
        )?;
        if n == 0 {
            return Err(not_found("folder", &id));
        }
        Ok(())
    }

    /// Set or clear the credential inherited by everything under this folder.
    pub fn set_folder_default_credential(
        &self,
        id: FolderId,
        credential: Option<CredentialId>,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some(c) = credential {
            crate::credentials::ensure_credential(&tx, c)?;
        }
        let n = tx.execute(
            "UPDATE folder SET default_credential_id = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), credential.map(|c| c.to_string()), fmt_ts(now())?],
        )?;
        if n == 0 {
            return Err(not_found("folder", &id));
        }
        tx.commit()?;
        Ok(())
    }

    /// Move a folder under a new parent. Same rules as `ConnectionTree::move_folder`:
    /// the new parent must exist, the root cannot move, and the folder may not be moved into
    /// itself or one of its descendants.
    pub fn move_folder(&self, id: FolderId, new_parent: FolderId) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if !folder_exists(&tx, new_parent)? {
            return Err(not_found("folder", &new_parent));
        }
        ensure_folder_editable(&tx, id)?;
        ensure_folder_editable(&tx, new_parent)?;
        if id == new_parent || is_ancestor_or_cyclic(&tx, id, new_parent)? {
            return Err(StoreError::Tree("move would create a cycle".into()));
        }
        let parent: Option<Option<String>> = tx
            .query_row("SELECT parent_id FROM folder WHERE id = ?1", [id.to_string()], |r| r.get(0))
            .optional()?;
        match parent {
            None => return Err(not_found("folder", &id)),
            Some(None) => return Err(StoreError::Tree("the root folder cannot be moved".into())),
            Some(Some(_)) => {}
        }
        tx.execute(
            "UPDATE folder SET parent_id = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), new_parent.to_string(), fmt_ts(now())?],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Delete a folder and, by cascade, every sub-folder, connection and tag below it.
    /// The root folder cannot be deleted (one-root invariant).
    pub fn delete_folder(&self, id: FolderId) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let parent: Option<Option<String>> = tx
            .query_row("SELECT parent_id FROM folder WHERE id = ?1", [id.to_string()], |r| r.get(0))
            .optional()?;
        match parent {
            None => return Err(not_found("folder", &id)),
            Some(None) => return Err(StoreError::Tree("the root folder cannot be deleted".into())),
            Some(Some(_)) => {}
        }
        ensure_folder_editable(&tx, id)?;
        tx.execute("DELETE FROM folder WHERE id = ?1", [id.to_string()])?;
        tx.commit()?;
        Ok(())
    }
}

pub(crate) fn folder_exists(conn: &rusqlite::Connection, id: FolderId) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM folder WHERE id = ?1)",
        [id.to_string()],
        |r| r.get(0),
    )?)
}

/// True when `ancestor` is on the parent chain of `start`, or the chain is already cyclic or
/// deeper than the folder count (refuse anything that touches a corrupt tree).
fn is_ancestor_or_cyclic(
    conn: &rusqlite::Connection,
    ancestor: FolderId,
    start: FolderId,
) -> Result<bool> {
    let (hit, max_depth, total): (bool, i64, i64) = conn.query_row(
        "WITH RECURSIVE
           bound(n) AS (SELECT count(*) FROM folder),
           chain(id, parent_id, depth) AS (
             SELECT id, parent_id, 0 FROM folder WHERE id = ?1
             UNION ALL
             SELECT f.id, f.parent_id, chain.depth + 1
             FROM folder f JOIN chain ON f.id = chain.parent_id, bound
             WHERE chain.depth <= bound.n
           )
         SELECT coalesce(max(id = ?2), 0), coalesce(max(depth), 0), (SELECT n FROM bound)
         FROM chain",
        params![start.to_string(), ancestor.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(hit || max_depth >= total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_root_and_parent_must_exist() {
        let s = Store::open_in_memory().expect("open");
        let root = s.create_folder(None, "Home lab").expect("root");
        assert!(matches!(s.create_folder(None, "second"), Err(StoreError::Tree(_))));
        assert!(matches!(
            s.create_folder(Some(FolderId::new()), "orphan"),
            Err(StoreError::NotFound { .. })
        ));
        assert_eq!(s.root_folder().expect("root"), Some(root));
    }

    #[test]
    fn moves_refuse_cycles_and_root() {
        let s = Store::open_in_memory().expect("open");
        let root = s.create_folder(None, "root").expect("root");
        let a = s.create_folder(Some(root.id), "a").expect("a");
        let b = s.create_folder(Some(a.id), "b").expect("b");
        assert!(matches!(s.move_folder(a.id, b.id), Err(StoreError::Tree(_))));
        assert!(matches!(s.move_folder(a.id, a.id), Err(StoreError::Tree(_))));
        assert!(matches!(s.move_folder(root.id, a.id), Err(StoreError::Tree(_))));
        s.move_folder(b.id, root.id).expect("legal");
        assert_eq!(s.get_folder(b.id).expect("b").parent, Some(root.id));
        s.move_folder(a.id, b.id).expect("legal now");
    }
}
