use std::collections::BTreeMap;

use mooring_core::{Connection, Protocol, ProtocolOptions};

use super::*;

fn node(ext: &str, kind: &str, parent: Option<&str>, name: &str) -> SyncNode {
    SyncNode {
        external_id: ext.to_owned(),
        kind: kind.to_owned(),
        parent: parent.map(str::to_owned),
        name: name.to_owned(),
        data: serde_json::json!({ "name": name }).to_string(),
    }
}

struct Fx {
    s: Store,
    root: Folder,
    vc: Connection,
    synced: Folder,
}

fn fx() -> Fx {
    let s = Store::open_in_memory().expect("open");
    let root = s.create_folder(None, "All").expect("root");
    let vc = s
        .create_connection(
            &Connection::new(root.id, "vc", Protocol::VsphereConsole, "vc.example.test")
                .expect("c"),
        )
        .expect("vc");
    let synced = s.sync_enable(vc.id, root.id, "vc").expect("enable");
    Fx { s, root, vc, synced }
}

fn tree() -> SyncPlan {
    SyncPlan {
        upsert: vec![
            node("datacenter-1", "datacenter", None, "dc-1"),
            node("domain-c1", "cluster", Some("datacenter-1"), "cluster-1"),
            node("host-1", "host", Some("domain-c1"), "esx-1.example.test"),
            node("vm-1", "vm", Some("host-1"), "web\u{202e}01\n"),
            node("vm-2", "vm", Some("host-1"), "db-01"),
        ],
        ..SyncPlan::default()
    }
}

fn vm(f: &Fx, ext: &str) -> Option<Connection> {
    let rows = f.s.synced_rows(f.vc.id).expect("rows");
    let row = rows.into_iter().find(|r| r.node.external_id == ext)?;
    Some(f.s.get_connection(row.id.parse().expect("id")).expect("conn"))
}

#[test]
fn enable_is_idempotent_and_options_report_the_root() {
    let f = fx();
    assert_eq!(f.s.sync_enable(f.vc.id, f.root.id, "again").expect("same").id, f.synced.id);
    assert_eq!(f.s.sync_root(f.vc.id).expect("root"), Some(f.synced.id));
    assert_eq!(f.s.sync_sources().expect("sources"), vec![f.vc.id]);
    let ProtocolOptions::Vsphere(o) = f.s.connection_options(f.vc.id).expect("opts") else {
        panic!("variant")
    };
    assert_eq!(o.sync_folder_id, Some(f.synced.id.to_string()));
    // Writing a different syncFolderId is ignored (store-owned).
    let mut w = o.clone();
    w.sync_folder_id = Some(f.root.id.to_string());
    f.s.set_connection_options(f.vc.id, &ProtocolOptions::Vsphere(w)).expect("set");
    let ProtocolOptions::Vsphere(o2) = f.s.connection_options(f.vc.id).expect("o") else {
        panic!("variant")
    };
    assert_eq!(o2.sync_folder_id, Some(f.synced.id.to_string()));
    let ssh =
        f.s.create_connection(
            &Connection::new(f.root.id, "ssh", Protocol::Ssh, "192.0.2.1").expect("c"),
        )
        .expect("ssh");
    assert!(f.s.sync_enable(ssh.id, f.root.id, "x").is_err(), "only vCenter connections");
}

#[test]
fn apply_creates_tree_and_sanitises_names() {
    let f = fx();
    let c = f.s.apply_inventory_diff(f.vc.id, &tree()).expect("apply");
    assert_eq!(c, SyncCounts { added: 5, ..SyncCounts::default() });
    let vm1 = vm(&f, "vm-1").expect("vm-1");
    assert_eq!(vm1.name, "web01");
    assert_eq!(vm1.protocol, Protocol::VsphereConsole);
    assert_eq!(vm1.host, "vc.example.test");
    let host = f.s.get_folder(vm1.folder).expect("host folder");
    assert_eq!(host.name, "esx-1.example.test");
    let flags = f.s.connection_sync(vm1.id).expect("flags").expect("synced");
    assert_eq!(flags.source, f.vc.id.to_string());
    assert_eq!(flags.external_id.as_deref(), Some("vm-1"));
    assert_eq!(flags.state.as_deref(), Some("present"));
    assert!(f.s.connection_sync(f.vc.id).expect("vc").is_none());
    assert_eq!(f.s.synced_rows(f.vc.id).expect("rows").len(), 5);
    assert!(f.s.sync_flags().expect("flags").contains_key(&f.synced.id.to_string()));
    assert_eq!(f.s.search("web01", 10).expect("fts").len(), 1, "search index follows");
}

#[test]
fn diff_moves_renames_marks_missing_and_removes() {
    let f = fx();
    f.s.apply_inventory_diff(f.vc.id, &tree()).expect("first");
    let second = SyncPlan {
        upsert: vec![
            node("host-2", "host", Some("domain-c1"), "esx-2.example.test"),
            node("vm-2", "vm", Some("host-2"), "db-02"),
        ],
        missing: BTreeMap::from([("vm-1".to_owned(), 1)]),
        remove: vec![],
    };
    let c = f.s.apply_inventory_diff(f.vc.id, &second).expect("second");
    assert_eq!((c.added, c.changed, c.missing, c.removed), (1, 1, 1, 0));
    let vm2 = vm(&f, "vm-2").expect("vm-2");
    assert_eq!(vm2.name, "db-02");
    assert_eq!(f.s.get_folder(vm2.folder).expect("f").name, "esx-2.example.test");
    let vm1 = vm(&f, "vm-1").expect("still there");
    let flags = f.s.connection_sync(vm1.id).expect("f").expect("synced");
    assert_eq!(flags.state.as_deref(), Some("missing"));
    let rows = f.s.synced_rows(f.vc.id).expect("rows");
    assert_eq!(rows.iter().find(|r| r.node.external_id == "vm-1").expect("r").streak, 1);
    let third = SyncPlan { remove: vec!["vm-1".to_owned()], ..SyncPlan::default() };
    assert_eq!(f.s.apply_inventory_diff(f.vc.id, &third).expect("third").removed, 1);
    assert!(vm(&f, "vm-1").is_none());
    let rows = f.s.synced_rows(f.vc.id).expect("rows");
    assert!(rows.iter().all(|r| r.streak == 0), "streaks reset for present items");
}

#[test]
fn bad_plan_writes_nothing() {
    let f = fx();
    let mut plan = tree();
    plan.upsert.push(node("vm-9", "vm", Some("host-404"), "orphan"));
    assert!(f.s.apply_inventory_diff(f.vc.id, &plan).is_err());
    assert!(f.s.synced_rows(f.vc.id).expect("rows").is_empty(), "rolled back");
    let mut bad = tree();
    bad.upsert[0].external_id = "DC 1".into();
    assert!(f.s.apply_inventory_diff(f.vc.id, &bad).is_err());
    bad = tree();
    bad.upsert[0].data = "[1]".into();
    assert!(f.s.apply_inventory_diff(f.vc.id, &bad).is_err());
}

#[test]
fn synced_subtree_is_read_only_except_overlays() {
    let f = fx();
    f.s.apply_inventory_diff(f.vc.id, &tree()).expect("apply");
    let vm1 = vm(&f, "vm-1").expect("vm");
    let host = vm1.folder;
    let ro = |r: Result<_>| matches!(r, Err(StoreError::SyncedReadOnly));
    assert!(ro(f.s.create_folder(Some(host), "mine").map(|_| ())));
    assert!(ro(f.s.create_folder(Some(f.synced.id), "mine").map(|_| ())));
    assert!(ro(f.s.rename_folder(host, "x")));
    assert!(ro(f.s.rename_folder(f.synced.id, "x")));
    assert!(ro(f.s.move_folder(host, f.root.id)));
    let normal = f.s.create_folder(Some(f.root.id), "normal").expect("normal");
    assert!(ro(f.s.move_folder(normal.id, host)), "nothing moves in");
    assert!(ro(f.s.delete_folder(host)));
    assert!(ro(f.s.delete_connection(vm1.id)));
    let mut renamed = vm1.clone();
    renamed.name = "other".into();
    assert!(ro(f.s.update_connection(&renamed).map(|_| ())));
    let mut moved = vm1.clone();
    moved.folder = normal.id;
    assert!(ro(f.s.update_connection(&moved).map(|_| ())));
    let mut new = Connection::new(host, "n", Protocol::Ssh, "192.0.2.2").expect("c");
    assert!(ro(f.s.create_connection(&new).map(|_| ())));
    new.folder = normal.id;
    let created = f.s.create_connection(&new).expect("normal ok");
    let mut into = created.clone();
    into.folder = host;
    assert!(ro(f.s.update_connection(&into).map(|_| ())));
    // Overlays: tags, default credential, options are allowed; and they survive a refresh.
    f.s.set_tags(vm1.id, &["prod".to_owned()]).expect("tags");
    let mut tagged = f.s.get_connection(vm1.id).expect("c");
    tagged.tags.push("db".into());
    f.s.update_connection(&tagged).expect("overlay update");
    f.s.set_folder_default_credential(host, None).expect("default credential overlay");
    let mut again = tree();
    again.upsert.retain(|n| n.external_id == "vm-1");
    again.upsert[0].name = "web-01-renamed".into();
    f.s.apply_inventory_diff(f.vc.id, &again).expect("refresh");
    let after = f.s.get_connection(vm1.id).expect("c");
    assert_eq!(after.name, "web-01-renamed");
    assert_eq!(after.tags, vec!["db".to_owned(), "prod".to_owned()], "overlay survives");
}

#[test]
fn disable_keep_detaches_and_drop_deletes() {
    let f = fx();
    f.s.apply_inventory_diff(f.vc.id, &tree()).expect("apply");
    let vm1 = vm(&f, "vm-1").expect("vm");
    assert!(f.s.sync_disable(f.vc.id, true).expect("keep"));
    assert!(f.s.connection_sync(vm1.id).expect("c").is_none());
    f.s.rename_folder(f.synced.id, "editable now").expect("editable");
    assert!(!f.s.sync_disable(f.vc.id, false).expect("nothing left"));
    let f = fx();
    f.s.apply_inventory_diff(f.vc.id, &tree()).expect("apply");
    let vm1 = vm(&f, "vm-1").expect("vm");
    assert!(f.s.sync_disable(f.vc.id, false).expect("drop"));
    assert!(f.s.get_connection(vm1.id).is_err());
    assert!(f.s.get_folder(f.synced.id).is_err());
}

#[test]
fn deleting_the_vcenter_deletes_its_subtree() {
    let f = fx();
    f.s.apply_inventory_diff(f.vc.id, &tree()).expect("apply");
    let vm1 = vm(&f, "vm-1").expect("vm");
    f.s.delete_connection(f.vc.id).expect("delete vc");
    assert!(f.s.get_connection(vm1.id).is_err());
    assert!(f.s.get_folder(f.synced.id).is_err());
}

#[test]
fn display_names() {
    assert_eq!(display_name("  a \t b ", "vm-1"), "a b");
    assert_eq!(display_name("\u{200b}\u{7}", "vm-1"), "vm-1");
    assert_eq!(display_name(&"x".repeat(300), "vm-1").chars().count(), MAX_NAME);
}
