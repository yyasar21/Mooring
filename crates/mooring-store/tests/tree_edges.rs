//! Inheritance, cascade and search edge cases not covered by `crud.rs` / `credentials.rs`
//! (ADR-0005 test plan).

mod common;

use common::{conn, lab, password, vault};
use mooring_core::{Connection, FolderId, Protocol};
use mooring_store::{SecretField, Store, StoreError};

#[test]
fn moving_a_folder_changes_what_it_inherits() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let root_c = password(s, &v, "root");
    let servers_c = password(s, &v, "servers");
    s.set_folder_default_credential(l.root.id, Some(root_c.id)).expect("root");
    s.set_folder_default_credential(l.servers.id, Some(servers_c.id)).expect("servers");
    let c = conn(s, &l.kube, "kube-cp", "198.51.100.10", &[]);
    assert_eq!(s.effective_credential(c.id).expect("eff"), Some(servers_c.id));

    s.move_folder(l.kube.id, l.root.id).expect("move kube under root");
    assert_eq!(s.effective_credential(c.id).expect("eff after move"), Some(root_c.id));
}

#[test]
fn moving_a_connection_changes_what_it_inherits() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let kube_c = password(s, &v, "kube");
    s.set_folder_default_credential(l.kube.id, Some(kube_c.id)).expect("kube default");
    let c = conn(s, &l.kube, "kube-cp", "198.51.100.10", &[]);
    assert_eq!(s.effective_credential(c.id).expect("eff"), Some(kube_c.id));

    let mut moved = s.get_connection(c.id).expect("get");
    moved.folder = l.servers.id;
    s.update_connection(&moved).expect("move connection");
    assert_eq!(s.effective_credential(c.id).expect("eff after move"), None);

    moved.folder = FolderId::new();
    assert!(matches!(s.update_connection(&moved), Err(StoreError::NotFound { .. })));
}

#[test]
fn deleting_a_shared_default_credential_nulls_every_reference() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let shared = password(s, &v, "shared");
    let root_c = password(s, &v, "root");
    s.set_folder_default_credential(l.root.id, Some(root_c.id)).expect("root");
    for f in [l.servers.id, l.kube.id] {
        s.set_folder_default_credential(f, Some(shared.id)).expect("set");
    }
    let mut c = Connection::new(l.kube.id, "x", Protocol::Ssh, "h").expect("valid");
    c.credential = Some(shared.id);
    let c = s.create_connection(&c).expect("create");

    s.delete_credential(shared.id).expect("delete");
    assert_eq!(s.get_folder(l.servers.id).expect("servers").default_credential, None);
    assert_eq!(s.get_folder(l.kube.id).expect("kube").default_credential, None);
    assert_eq!(s.get_connection(c.id).expect("conn").credential, None);
    assert_eq!(s.effective_credential(c.id).expect("eff"), Some(root_c.id), "falls back to root");
    assert!(matches!(
        s.open_credential_secret(&v, shared.id, SecretField::Secret),
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(s.delete_credential(shared.id), Err(StoreError::NotFound { .. })));
}

#[test]
fn folder_delete_cascade_keeps_credentials() {
    let l = lab();
    let s = &l.store;
    let v = vault();
    let folder_c = password(s, &v, "folder default");
    let own_c = password(s, &v, "override");
    s.set_folder_default_credential(l.kube.id, Some(folder_c.id)).expect("set");
    let mut c = Connection::new(l.kube.id, "x", Protocol::Ssh, "h").expect("valid");
    c.credential = Some(own_c.id);
    s.create_connection(&c).expect("create");

    s.delete_folder(l.servers.id).expect("delete subtree");
    // Credentials are vault records, not tree nodes: they survive and still open.
    assert_eq!(s.list_credentials().expect("list").len(), 2);
    for id in [folder_c.id, own_c.id] {
        assert_eq!(
            s.open_credential_secret(&v, id, SecretField::Secret).expect("open").as_slice(),
            b"test-secret"
        );
    }
    assert!(s.list_connections(l.kube.id).expect("gone").is_empty());
    assert!(matches!(s.delete_folder(l.kube.id), Err(StoreError::NotFound { .. })));
}

#[test]
fn deep_tree_resolves_nearest_and_root_fallback() {
    let s = Store::open_in_memory().expect("open");
    let v = vault();
    let root = s.create_folder(None, "root").expect("root");
    let mut chain = vec![root.clone()];
    for i in 0..64 {
        let parent = chain.last().expect("parent").id;
        chain.push(s.create_folder(Some(parent), &format!("level {i}")).expect("folder"));
    }
    let leaf = chain.last().expect("leaf");
    let c = conn(&s, leaf, "deep", "deep.example.test", &[]);
    assert_eq!(s.effective_credential(c.id).expect("none"), None);

    let root_c = password(&s, &v, "root");
    s.set_folder_default_credential(root.id, Some(root_c.id)).expect("root");
    assert_eq!(s.effective_credential(c.id).expect("root fallback"), Some(root_c.id));

    let mid_c = password(&s, &v, "mid");
    s.set_folder_default_credential(chain[32].id, Some(mid_c.id)).expect("mid");
    assert_eq!(s.effective_credential(c.id).expect("nearest"), Some(mid_c.id));

    // Unrelated sibling branch does not leak into the chain.
    let sib = s.create_folder(Some(chain[40].id), "sibling").expect("sib");
    let sib_c = password(&s, &v, "sibling");
    s.set_folder_default_credential(sib.id, Some(sib_c.id)).expect("sib");
    assert_eq!(s.effective_credential(c.id).expect("still mid"), Some(mid_c.id));

    // Deleting a middle folder removes the whole lower chain including the connection.
    s.delete_folder(chain[10].id).expect("delete mid-chain");
    assert!(matches!(s.get_connection(c.id), Err(StoreError::NotFound { .. })));
    assert_eq!(s.list_folders().expect("left").len(), 10, "root + levels 0..=8");
}

#[test]
fn search_survives_vacuum_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let keep = {
        let l = {
            let store = Store::open(&path).expect("open");
            let root = store.create_folder(None, "root").expect("root");
            (store, root)
        };
        let (s, root) = l;
        let mut ids = Vec::new();
        for i in 0..20 {
            ids.push(conn(&s, &root, &format!("node{i:02}"), &format!("192.0.2.{i}"), &["fleet"]));
        }
        // Delete the low rowids so VACUUM has something to renumber.
        for c in &ids[..15] {
            s.delete_connection(c.id).expect("delete");
        }
        ids[15..].to_vec()
    };
    let raw = rusqlite::Connection::open(&path).expect("raw");
    raw.execute_batch("VACUUM").expect("vacuum");
    drop(raw);

    let s = Store::open(&path).expect("reopen");
    let mut hits: Vec<_> =
        s.search("fleet", 50).expect("search").into_iter().map(|h| h.id).collect();
    hits.sort_by_key(ToString::to_string);
    let mut want: Vec<_> = keep.iter().map(|c| c.id).collect();
    want.sort_by_key(ToString::to_string);
    assert_eq!(hits, want);
    let one = s.search("node17", 5).expect("by name");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].host, "192.0.2.17");
}

#[test]
fn search_folds_diacritics_and_case() {
    let l = lab();
    let s = &l.store;
    let c = conn(s, &l.root, "Çankaya Sunucu", "cankaya.example.test", &["Ankara"]);
    for q in ["cankaya sunucu", "ÇANKAYA", "ankara", "ANK"] {
        let hits = s.search(q, 10).expect("search");
        assert_eq!(hits.iter().map(|h| h.id).collect::<Vec<_>>(), vec![c.id], "query {q:?}");
    }
}

#[test]
fn data_survives_file_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let v = vault();
    let (cid, credid) = {
        let s = Store::open(&path).expect("open");
        let root = s.create_folder(None, "root").expect("root");
        let cred = password(&s, &v, "persist");
        s.set_folder_default_credential(root.id, Some(cred.id)).expect("default");
        (conn(&s, &root, "persist", "p.example.test", &["t"]).id, cred.id)
    };
    let s = Store::open(&path).expect("reopen");
    assert_eq!(s.schema_version().expect("v"), mooring_store::schema::LATEST);
    assert_eq!(s.get_connection(cid).expect("conn").tags, vec!["t".to_owned()]);
    assert_eq!(s.effective_credential(cid).expect("eff"), Some(credid));
    assert_eq!(
        s.open_credential_secret(&v, credid, SecretField::Secret).expect("open").as_slice(),
        b"test-secret"
    );
}
