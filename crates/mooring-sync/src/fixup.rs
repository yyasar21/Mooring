//! Referential repairs after a merge, so the store accepts the result:
//! one root (the remote's when both sides had one), parents that exist and form no cycle,
//! connections in existing folders, credential references that exist.

use std::collections::BTreeSet;

use crate::snapshot::Snapshot;

fn pick_root(s: &Snapshot, remote: &Snapshot) -> Option<String> {
    let roots: Vec<&String> =
        s.folders.values().filter(|f| f.parent_id.is_none()).map(|f| &f.id).collect();
    roots
        .iter()
        .find(|id| remote.folders.get(id.as_str()).is_some_and(|f| f.parent_id.is_none()))
        .or_else(|| roots.first())
        .map(|id| (*id).clone())
        .or_else(|| s.folders.keys().next().cloned())
}

fn has_cycle(s: &Snapshot, start: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut cur = Some(start.to_owned());
    while let Some(id) = cur {
        if !seen.insert(id.clone()) {
            return true;
        }
        cur = s.folders.get(&id).and_then(|f| f.parent_id.clone());
    }
    false
}

/// Repair `s` in place; `remote` breaks the tie between two roots.
pub fn fixup(s: &mut Snapshot, remote: &Snapshot) {
    let root = pick_root(s, remote);
    if let Some(root) = &root {
        let ids: Vec<String> = s.folders.keys().cloned().collect();
        for id in &ids {
            if id == root {
                if let Some(f) = s.folders.get_mut(id) {
                    f.parent_id = None;
                }
                continue;
            }
            let parent = s.folders.get(id).and_then(|f| f.parent_id.clone());
            let bad_parent = parent.as_ref().is_none_or(|p| !s.folders.contains_key(p));
            if bad_parent {
                if let Some(f) = s.folders.get_mut(id) {
                    f.parent_id = Some(root.clone());
                }
            }
        }
        for id in &ids {
            if id != root && has_cycle(s, id) {
                if let Some(f) = s.folders.get_mut(id) {
                    f.parent_id = Some(root.clone());
                }
            }
        }
    }
    let creds: BTreeSet<String> = s.credentials.keys().cloned().collect();
    for f in s.folders.values_mut() {
        if f.default_credential_id.as_ref().is_some_and(|c| !creds.contains(c)) {
            f.default_credential_id = None;
        }
    }
    let folders: BTreeSet<String> = s.folders.keys().cloned().collect();
    s.connections.retain(|_, c| root.is_some() || folders.contains(&c.folder_id));
    for c in s.connections.values_mut() {
        if !folders.contains(&c.folder_id) {
            if let Some(root) = &root {
                c.folder_id.clone_from(root);
            }
        }
        if c.credential_id.as_ref().is_some_and(|id| !creds.contains(id)) {
            c.credential_id = None;
        }
        c.roles.retain(|_, id| creds.contains(id));
    }
}
