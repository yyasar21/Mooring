//! In-memory connection tree with credential inheritance and cycle protection.
//!
//! A1 replaces the storage with `SQLite`; the invariants enforced here (one root, no cycles,
//! no orphans, inherited credentials resolved along the parent chain) stay the contract.

use std::collections::HashMap;

use crate::error::{MooringError, Result};
use crate::model::{Connection, ConnectionId, CredentialId, Folder, FolderId};

/// Folders and connections, indexed by id.
#[derive(Debug, Default, Clone)]
pub struct ConnectionTree {
    folders: HashMap<FolderId, Folder>,
    connections: HashMap<ConnectionId, Connection>,
}

impl ConnectionTree {
    /// An empty tree with one root folder named `root_name`.
    pub fn new(root_name: &str) -> Result<(Self, FolderId)> {
        let root = Folder::new(None, root_name)?;
        let id = root.id;
        let mut t = Self::default();
        t.folders.insert(id, root);
        Ok((t, id))
    }

    /// Add a folder. Its parent must exist.
    pub fn add_folder(&mut self, folder: Folder) -> Result<FolderId> {
        let Some(parent) = folder.parent else {
            return Err(MooringError::Tree("only one root folder is allowed".into()));
        };
        self.folder(parent)?;
        let id = folder.id;
        self.folders.insert(id, folder);
        Ok(id)
    }

    /// Add a connection. Its folder must exist.
    pub fn add_connection(&mut self, conn: Connection) -> Result<ConnectionId> {
        self.folder(conn.folder)?;
        let id = conn.id;
        self.connections.insert(id, conn);
        Ok(id)
    }

    /// Move a folder under a new parent, refusing cycles.
    pub fn move_folder(&mut self, id: FolderId, new_parent: FolderId) -> Result<()> {
        self.folder(new_parent)?;
        if id == new_parent || self.is_descendant(new_parent, id) {
            return Err(MooringError::Tree("move would create a cycle".into()));
        }
        let f = self.folders.get_mut(&id).ok_or_else(|| not_found("folder", &id))?;
        if f.parent.is_none() {
            return Err(MooringError::Tree("the root folder cannot be moved".into()));
        }
        f.parent = Some(new_parent);
        Ok(())
    }

    /// Credential a connection will use: its own, else the nearest ancestor folder's default.
    pub fn effective_credential(&self, id: ConnectionId) -> Result<Option<CredentialId>> {
        let c = self.connection(id)?;
        if c.credential.is_some() {
            return Ok(c.credential);
        }
        let mut cursor = Some(c.folder);
        let mut hops = 0usize;
        while let Some(fid) = cursor {
            let f = self.folder(fid)?;
            if f.default_credential.is_some() {
                return Ok(f.default_credential);
            }
            cursor = f.parent;
            hops += 1;
            if hops > self.folders.len() {
                return Err(MooringError::Tree("cycle detected while resolving credential".into()));
            }
        }
        Ok(None)
    }

    /// Look up a folder.
    pub fn folder(&self, id: FolderId) -> Result<&Folder> {
        self.folders.get(&id).ok_or_else(|| not_found("folder", &id))
    }

    /// Look up a connection.
    pub fn connection(&self, id: ConnectionId) -> Result<&Connection> {
        self.connections.get(&id).ok_or_else(|| not_found("connection", &id))
    }

    /// Connections directly inside a folder, sorted by name.
    #[must_use]
    pub fn connections_in(&self, folder: FolderId) -> Vec<&Connection> {
        let mut v: Vec<_> = self.connections.values().filter(|c| c.folder == folder).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Child folders, sorted by name.
    #[must_use]
    pub fn children(&self, folder: FolderId) -> Vec<&Folder> {
        let mut v: Vec<_> = self.folders.values().filter(|f| f.parent == Some(folder)).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Case-insensitive search over connection name, host and tags.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&Connection> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let mut v: Vec<_> = self
            .connections
            .values()
            .filter(|c| {
                c.name.to_lowercase().contains(&q)
                    || c.host.to_lowercase().contains(&q)
                    || c.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    fn is_descendant(&self, candidate: FolderId, ancestor: FolderId) -> bool {
        let mut cursor = self.folders.get(&candidate).and_then(|f| f.parent);
        let mut hops = 0usize;
        while let Some(p) = cursor {
            if p == ancestor {
                return true;
            }
            cursor = self.folders.get(&p).and_then(|f| f.parent);
            hops += 1;
            if hops > self.folders.len() {
                return true; // already cyclic: refuse anything that touches it
            }
        }
        false
    }
}

fn not_found(kind: &'static str, id: &dyn std::fmt::Display) -> MooringError {
    MooringError::NotFound { kind, id: id.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    fn lab() -> (ConnectionTree, FolderId, FolderId, ConnectionId) {
        let (mut t, root) = ConnectionTree::new("Home lab").expect("root");
        let mut servers = Folder::new(Some(root), "servers").expect("folder");
        let cred = CredentialId::new();
        servers.default_credential = Some(cred);
        let servers_id = t.add_folder(servers).expect("add");
        let c = Connection::new(servers_id, "xinfra01", Protocol::Ssh, "10.10.20.5").expect("conn");
        let cid = t.add_connection(c).expect("add");
        (t, root, servers_id, cid)
    }

    #[test]
    fn credential_is_inherited_from_folder() {
        let (t, _, servers, cid) = lab();
        let folder_cred = t.folder(servers).expect("f").default_credential;
        assert_eq!(t.effective_credential(cid).expect("ok"), folder_cred);
    }

    #[test]
    fn refuses_cycles_and_second_root() {
        let (mut t, root, servers, _) = lab();
        let sub = t.add_folder(Folder::new(Some(servers), "okd").expect("f")).expect("add");
        assert!(t.move_folder(servers, sub).is_err());
        assert!(t.move_folder(root, servers).is_err());
        assert!(t.add_folder(Folder::new(None, "another root").expect("f")).is_err());
        t.move_folder(sub, root).expect("legal move");
    }

    #[test]
    fn search_matches_name_host_and_tags() {
        let (mut t, _, servers, _) = lab();
        let mut c = Connection::new(servers, "xmon01", Protocol::Ssh, "10.10.20.30").expect("c");
        c.tags.push("observability".into());
        t.add_connection(c).expect("add");
        assert_eq!(t.search("OBSERV").len(), 1);
        assert_eq!(t.search("10.10.20").len(), 2);
        assert!(t.search("  ").is_empty());
    }
}
