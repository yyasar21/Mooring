//! Folder / connection / tag round trips, validation and folder-delete cascade.

mod common;

use common::{conn, lab};
use mooring_core::{Connection, ConnectionId, Protocol};
use mooring_store::{StoreError, MAX_TAGS};

#[test]
fn folder_round_trip_rename_sort_and_children() {
    let l = lab();
    let s = &l.store;
    assert_eq!(s.get_folder(l.servers.id).expect("get"), l.servers);
    s.rename_folder(l.servers.id, "  Servers ").expect("rename");
    assert_eq!(s.get_folder(l.servers.id).expect("get").name, "Servers");
    assert!(matches!(s.rename_folder(l.servers.id, ""), Err(StoreError::Invalid { .. })));

    let net = s.create_folder(Some(l.root.id), "network").expect("net");
    s.set_folder_sort(net.id, -1).expect("sort");
    let kids: Vec<_> =
        s.child_folders(l.root.id).expect("kids").into_iter().map(|f| f.id).collect();
    assert_eq!(kids, vec![net.id, l.servers.id]);
    assert_eq!(s.list_folders().expect("all").len(), 4);
    assert!(matches!(s.delete_folder(l.root.id), Err(StoreError::Tree(_))));
}

#[test]
fn connection_round_trip_update_and_delete() {
    let l = lab();
    let s = &l.store;
    let mut c =
        Connection::new(l.okd.id, " okd-master ", Protocol::Ssh, " 10.10.30.10 ").expect("valid");
    c.port = Some(2222);
    c.tags = vec!["okd".into(), "k8s".into(), "okd".into()];
    let stored = s.create_connection(&c).expect("create");
    assert_eq!(stored.name, "okd-master");
    assert_eq!(stored.host, "10.10.30.10");
    assert_eq!(stored.tags, vec!["k8s".to_owned(), "okd".to_owned()]);
    assert_eq!(stored.port, Some(2222));
    assert_eq!(s.get_connection(c.id).expect("get"), stored);

    let mut upd = stored.clone();
    upd.name = "okd-cp-1".into();
    upd.protocol = Protocol::Rdp;
    upd.port = None;
    upd.folder = l.servers.id;
    upd.tags = vec!["control-plane".into()];
    let after = s.update_connection(&upd).expect("update");
    assert_eq!(after, upd);
    assert!(s.list_connections(l.okd.id).expect("okd").is_empty());
    assert_eq!(s.list_connections(l.servers.id).expect("servers"), vec![after]);

    s.delete_connection(c.id).expect("delete");
    assert!(matches!(s.get_connection(c.id), Err(StoreError::NotFound { .. })));
    assert!(matches!(s.delete_connection(c.id), Err(StoreError::NotFound { .. })));
}

#[test]
fn connection_validation_happens_before_sql() {
    let l = lab();
    let s = &l.store;
    let good = Connection::new(l.root.id, "x", Protocol::Ssh, "h").expect("valid");

    let mut bad = good.clone();
    bad.name = "y".repeat(121);
    assert!(matches!(s.create_connection(&bad), Err(StoreError::Invalid { field: "name", .. })));

    let mut bad = good.clone();
    bad.host = "h".repeat(2049);
    assert!(matches!(s.create_connection(&bad), Err(StoreError::Invalid { field: "host", .. })));

    let mut bad = good.clone();
    bad.tags = vec!["t".repeat(65)];
    assert!(matches!(s.create_connection(&bad), Err(StoreError::Invalid { field: "tag", .. })));

    let mut bad = good.clone();
    bad.tags = (0..=MAX_TAGS).map(|i| format!("t{i}")).collect();
    assert!(matches!(s.create_connection(&bad), Err(StoreError::Invalid { field: "tags", .. })));

    let mut bad = good.clone();
    bad.port = Some(0);
    assert!(matches!(s.create_connection(&bad), Err(StoreError::Invalid { field: "port", .. })));

    let mut bad = good.clone();
    bad.folder = mooring_core::FolderId::new();
    assert!(matches!(s.create_connection(&bad), Err(StoreError::NotFound { .. })));

    let mut bad = good;
    bad.credential = Some(mooring_core::CredentialId::new());
    assert!(matches!(s.create_connection(&bad), Err(StoreError::NotFound { .. })));
}

#[test]
fn set_tags_replaces() {
    let l = lab();
    let s = &l.store;
    let c = conn(s, &l.servers, "xmon01", "10.10.20.30", &["a", "b"]);
    let t = s.set_tags(c.id, &["observability".into(), " c ".into()]).expect("set");
    assert_eq!(t, vec!["c".to_owned(), "observability".to_owned()]);
    assert_eq!(s.get_connection(c.id).expect("get").tags, t);
    s.set_tags(c.id, &[]).expect("clear");
    assert!(s.get_connection(c.id).expect("get").tags.is_empty());
    assert!(matches!(s.set_tags(ConnectionId::new(), &[]), Err(StoreError::NotFound { .. })));
}

#[test]
fn deleting_a_folder_cascades_to_subfolders_connections_and_tags() {
    let l = lab();
    let s = &l.store;
    let a = conn(s, &l.servers, "xinfra01", "10.10.20.5", &["infra"]);
    let b = conn(s, &l.okd, "okd-master", "10.10.30.10", &["okd"]);
    let keep = conn(s, &l.root, "router", "10.10.0.1", &["net"]);

    s.delete_folder(l.servers.id).expect("delete");

    assert!(matches!(s.get_folder(l.okd.id), Err(StoreError::NotFound { .. })));
    assert!(matches!(s.get_connection(a.id), Err(StoreError::NotFound { .. })));
    assert!(matches!(s.get_connection(b.id), Err(StoreError::NotFound { .. })));
    assert_eq!(s.get_connection(keep.id).expect("kept").tags, vec!["net".to_owned()]);
    // search index follows the cascade
    assert!(s.search("okd", 10).expect("search").is_empty());
    assert!(s.search("infra", 10).expect("search").is_empty());
    assert_eq!(s.search("net", 10).expect("search").len(), 1);
}

#[test]
fn move_folder_keeps_contents() {
    let l = lab();
    let s = &l.store;
    let c = conn(s, &l.okd, "okd-master", "10.10.30.10", &[]);
    s.move_folder(l.okd.id, l.root.id).expect("move");
    assert_eq!(s.get_folder(l.okd.id).expect("okd").parent, Some(l.root.id));
    assert_eq!(s.list_connections(l.okd.id).expect("list")[0].id, c.id);
    assert!(matches!(s.move_folder(l.servers.id, l.servers.id), Err(StoreError::Tree(_))));
}

#[test]
fn corrupt_cyclic_tree_is_detected_not_looped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let (a, b, c) = {
        let s = mooring_store::Store::open(&path).expect("open");
        let root = s.create_folder(None, "root").expect("root");
        let a = s.create_folder(Some(root.id), "a").expect("a");
        let b = s.create_folder(Some(a.id), "b").expect("b");
        let c = conn(&s, &b, "x", "h", &[]);
        (a, b, c)
    };
    // Bypass the store: make a <-> b a cycle detached from the root.
    let raw = rusqlite::Connection::open(&path).expect("raw");
    raw.execute(
        "UPDATE folder SET parent_id = ?1 WHERE id = ?2",
        [b.id.to_string(), a.id.to_string()],
    )
    .expect("corrupt");
    drop(raw);

    let s = mooring_store::Store::open(&path).expect("reopen");
    assert!(matches!(s.effective_credential(c.id), Err(StoreError::Tree(_))));
    assert!(matches!(s.move_folder(b.id, a.id), Err(StoreError::Tree(_))));
}
