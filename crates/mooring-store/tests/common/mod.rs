//! Shared fixtures for the store integration tests. No real secrets: every value is a
//! synthetic test string.

#![allow(dead_code)]

use mooring_core::{Connection, Folder, Protocol};
use mooring_store::{CredentialKind, CredentialMeta, Store};
use mooring_vault::{KdfParams, Vault};
use secrecy::SecretString;

pub fn vault() -> Vault {
    Vault::create(&SecretString::from("test-only master pw".to_owned()), KdfParams::TEST)
        .expect("create vault")
}

pub struct Lab {
    pub store: Store,
    pub root: Folder,
    pub servers: Folder,
    pub okd: Folder,
}

/// root ─ servers ─ okd
pub fn lab() -> Lab {
    let store = Store::open_in_memory().expect("open");
    let root = store.create_folder(None, "Home lab").expect("root");
    let servers = store.create_folder(Some(root.id), "servers").expect("servers");
    let okd = store.create_folder(Some(servers.id), "okd").expect("okd");
    Lab { store, root, servers, okd }
}

pub fn conn(store: &Store, folder: &Folder, name: &str, host: &str, tags: &[&str]) -> Connection {
    let mut c = Connection::new(folder.id, name, Protocol::Ssh, host).expect("valid connection");
    c.tags = tags.iter().map(|t| (*t).to_owned()).collect();
    store.create_connection(&c).expect("insert connection")
}

pub fn password(store: &Store, vault: &Vault, name: &str) -> CredentialMeta {
    let meta = CredentialMeta::new(name, CredentialKind::Password, Some("ops")).expect("meta");
    store.create_credential(vault, &meta, b"test-secret", None).expect("insert credential")
}
