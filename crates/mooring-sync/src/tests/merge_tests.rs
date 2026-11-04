//! Merge matrix on hand-built snapshots: add/add, modify/modify (disjoint and overlapping),
//! delete/modify, delete/delete, tombstones without base, folder LWW, trust lines, fixups.

use std::collections::BTreeMap;

use mooring_store::{ConnectionRow, CredentialRow, FolderRow};
use mooring_vault::Vault;
use uuid::Uuid;

use super::vaults;
use crate::merge::{merge, MergeCtx, Reseal, Resolution};
use crate::snapshot::{tomb_key, RecordKind, Snapshot, Tombstone};
use crate::{reseal_secret, Result};

const ROOT: &str = "00000000-0000-4000-8000-000000000001";
const T0: &str = "2026-11-01T00:00:00Z";
const T1: &str = "2026-11-02T00:00:00Z";
const T2: &str = "2026-11-03T00:00:00Z";

struct NoReseal;
impl Reseal for NoReseal {
    fn reseal(&self, _: &str, new_id: &str, _: &str, sealed: &str) -> Result<String> {
        Ok(format!("{sealed}@{new_id}"))
    }
}

struct VaultReseal<'a>(&'a Vault);
impl Reseal for VaultReseal<'_> {
    fn reseal(&self, old: &str, new: &str, secret: &str, sealed: &str) -> Result<String> {
        reseal_secret(self.0, old, new, secret, sealed)
    }
}

fn folder(id: &str, parent: Option<&str>, name: &str) -> FolderRow {
    FolderRow {
        created_at: T0.into(),
        default_credential_id: None,
        id: id.into(),
        name: name.into(),
        parent_id: parent.map(Into::into),
        sort: 0,
        updated_at: T0.into(),
    }
}

fn conn(id: &str, name: &str, host: &str) -> ConnectionRow {
    ConnectionRow {
        created_at: T0.into(),
        credential_id: None,
        domain_override: None,
        folder_id: ROOT.into(),
        host: host.into(),
        id: id.into(),
        name: name.into(),
        options_json: "{}".into(),
        port: None,
        protocol: "ssh".into(),
        roles: BTreeMap::new(),
        tags: vec![],
        updated_at: T0.into(),
        username_override: None,
    }
}

fn base() -> Snapshot {
    let mut s = Snapshot::empty(Uuid::from_u128(5), "dev");
    s.folders.insert(ROOT.into(), folder(ROOT, None, "All connections"));
    s.connections.insert("c1".into(), conn("c1", "web", "web.example.test"));
    s.connections.insert("c2".into(), conn("c2", "db", "db.example.test"));
    s
}

fn ctx() -> MergeCtx<'static> {
    MergeCtx { remote_device: "laptop", now: T2 }
}

fn edit(s: &mut Snapshot, id: &str, f: impl FnOnce(&mut ConnectionRow)) {
    let c = s.connections.get_mut(id).expect("row");
    f(c);
    c.updated_at = T1.into();
}

#[test]
fn one_sided_and_disjoint_edits_merge_cleanly() {
    let b = base();
    let (mut l, mut r) = (b.clone(), b.clone());
    edit(&mut l, "c1", |c| c.name = "web (renamed)".into());
    edit(&mut r, "c1", |c| c.port = Some(2222));
    edit(&mut r, "c2", |c| c.host = "db2.example.test".into());
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    assert!(p.conflicts.is_empty());
    let c1 = &p.snapshot.connections["c1"];
    assert_eq!((c1.name.as_str(), c1.port), ("web (renamed)", Some(2222)));
    assert_eq!(c1.updated_at, T1);
    assert_eq!(p.snapshot.connections["c2"].host, "db2.example.test");
}

#[test]
fn true_conflict_keeps_both_copies_with_a_suffix() {
    let b = base();
    let (mut l, mut r) = (b.clone(), b.clone());
    edit(&mut l, "c1", |c| c.host = "a.example.test".into());
    edit(&mut r, "c1", |c| c.host = "b.example.test".into());
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    assert_eq!(p.conflicts.len(), 1);
    let Resolution::KeptBoth { copy_id } = &p.conflicts[0].resolution else { panic!("both") };
    assert_eq!(p.snapshot.connections["c1"].host, "a.example.test", "local keeps its id");
    let copy = &p.snapshot.connections[copy_id];
    assert_eq!(copy.host, "b.example.test");
    assert_eq!(copy.name, "web (conflict from laptop)");
    assert_eq!(p.snapshot.connections.len(), 3);
}

#[test]
fn add_add_same_content_is_one_row_and_different_content_is_two() {
    let b = base();
    let (mut l, mut r) = (b.clone(), b.clone());
    l.connections.insert("n1".into(), conn("n1", "new", "n.example.test"));
    r.connections.insert("n1".into(), conn("n1", "new", "n.example.test"));
    l.connections.insert("n2".into(), conn("n2", "x", "x.example.test"));
    r.connections.insert("n2".into(), conn("n2", "x", "y.example.test"));
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    assert_eq!(p.conflicts.len(), 1, "only n2 conflicts");
    assert_eq!(p.snapshot.connections.len(), 5);
}

#[test]
fn delete_vs_modify_keeps_the_edit_and_delete_vs_unchanged_deletes() {
    let b = base();
    let (mut l, mut r) = (b.clone(), b.clone());
    l.connections.remove("c1");
    l.connections.remove("c2");
    edit(&mut r, "c1", |c| c.name = "edited remotely".into());
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    assert_eq!(p.snapshot.connections.keys().collect::<Vec<_>>(), ["c1"]);
    assert_eq!(p.conflicts[0].resolution, Resolution::KeptEdit);
    // delete / delete
    let mut r2 = b.clone();
    r2.connections.remove("c2");
    let p = merge(Some(&b), &l, &r2, ctx(), &NoReseal).expect("merge");
    assert!(p.snapshot.connections.is_empty(), "c1 deleted locally, c2 deleted on both");
    assert!(p.conflicts.is_empty());
}

#[test]
fn tombstones_decide_without_a_base() {
    let mut l = base();
    let mut r = base();
    r.connections.remove("c2");
    r.tombstones.insert(
        tomb_key(RecordKind::Connection, "c2"),
        Tombstone { deleted_at: T1.into(), id: "c2".into(), kind: RecordKind::Connection },
    );
    r.connections.remove("c1");
    r.tombstones.insert(
        tomb_key(RecordKind::Connection, "c1"),
        Tombstone { deleted_at: T1.into(), id: "c1".into(), kind: RecordKind::Connection },
    );
    l.connections.get_mut("c1").expect("c1").updated_at = T2.into(); // edited after the delete
    let p = merge(None, &l, &r, ctx(), &NoReseal).expect("merge");
    assert!(p.snapshot.connections.contains_key("c1"), "newer edit survives");
    assert!(!p.snapshot.connections.contains_key("c2"), "older row is deleted");
    assert!(p.snapshot.tombstones.contains_key(&tomb_key(RecordKind::Connection, "c2")));
    assert!(!p.snapshot.tombstones.contains_key(&tomb_key(RecordKind::Connection, "c1")));
}

#[test]
fn folders_use_last_writer_wins() {
    let b = base();
    let (mut l, mut r) = (b.clone(), b.clone());
    let f = l.folders.get_mut(ROOT).expect("root");
    f.name = "Mine".into();
    f.updated_at = T1.into();
    let f = r.folders.get_mut(ROOT).expect("root");
    f.name = "Theirs".into();
    f.updated_at = T2.into();
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    assert_eq!(p.snapshot.folders[ROOT].name, "Theirs");
    assert_eq!(p.conflicts[0].resolution, Resolution::LastWriterWins);
}

#[test]
fn credential_copies_are_resealed_to_their_new_id() {
    let v = vaults(1).remove(0);
    let seal = |id: &str, pw: &[u8]| {
        serde_json::to_string(&v.seal(id, "password", pw).expect("seal")).expect("json")
    };
    let id = Uuid::new_v4().to_string();
    let row = |pw: &[u8], at: &str| CredentialRow {
        created_at: T0.into(),
        fields_json: "{}".into(),
        id: id.clone(),
        kind: "user_password".into(),
        name: "ops".into(),
        secrets: [("password".to_owned(), seal(&id, pw))].into_iter().collect(),
        updated_at: at.into(),
    };
    let mut b = base();
    b.credentials.insert(id.clone(), row(b"pw-0", T0));
    let (mut l, mut r) = (b.clone(), b.clone());
    l.credentials.insert(id.clone(), row(b"pw-local", T1));
    r.credentials.insert(id.clone(), row(b"pw-remote", T1));
    let p = merge(Some(&b), &l, &r, ctx(), &VaultReseal(&v)).expect("merge");
    let Resolution::KeptBoth { copy_id } = &p.conflicts[0].resolution else { panic!("both") };
    let open = |rid: &str| {
        let s = &p.snapshot.credentials[rid].secrets["password"];
        v.open(rid, "password", &serde_json::from_str(s).expect("sealed")).expect("opens").to_vec()
    };
    assert_eq!(open(&id), b"pw-local");
    assert_eq!(open(copy_id), b"pw-remote", "copy re-sealed under its own id");
}

#[test]
fn trust_lines_merge_as_sets() {
    let set = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect();
    let mut b = base();
    b.trust.insert("known_hosts".into(), set(&["a", "b"]));
    let (mut l, mut r) = (b.clone(), b.clone());
    l.trust.insert("known_hosts".into(), set(&["a", "b", "c"]));
    r.trust.insert("known_hosts".into(), set(&["b", "d"]));
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    assert_eq!(p.snapshot.trust["known_hosts"], set(&["b", "c", "d"]), "a removed remotely");
}

#[test]
fn fixups_repair_roots_cycles_and_dangling_references() {
    let b = base();
    let mut l = b.clone();
    let mut r = b.clone();
    let other_root = "00000000-0000-4000-8000-000000000002";
    l.folders.insert(other_root.into(), folder(other_root, None, "Local root"));
    l.folders.insert("fa".into(), folder("fa", Some("fb"), "A"));
    l.folders.insert("fb".into(), folder("fb", Some("fa"), "B"));
    edit(&mut l, "c1", |c| {
        c.folder_id = "gone".into();
        c.credential_id = Some("missing".into());
        c.roles.insert("gateway".into(), "missing".into());
    });
    r.folders.get_mut(ROOT).expect("root").updated_at = T1.into();
    let p = merge(Some(&b), &l, &r, ctx(), &NoReseal).expect("merge");
    let s = &p.snapshot;
    let roots: Vec<_> = s.folders.values().filter(|f| f.parent_id.is_none()).collect();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].id, ROOT, "the remote root wins");
    assert_eq!(s.folders[other_root].parent_id.as_deref(), Some(ROOT));
    let cyc = [&s.folders["fa"], &s.folders["fb"]];
    assert!(cyc.iter().any(|f| f.parent_id.as_deref() == Some(ROOT)), "cycle broken");
    let c1 = &s.connections["c1"];
    assert_eq!((c1.folder_id.as_str(), c1.credential_id.as_ref()), (ROOT, None));
    assert!(c1.roles.is_empty());
}
