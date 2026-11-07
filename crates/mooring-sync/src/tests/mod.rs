//! Unit and scenario tests of the crate. Synthetic values only (`example.test`, test
//! passwords that are documented as public in `test-vectors/README.md`).

#![allow(clippy::many_single_char_names)] // a / b devices, s = store, v = vault

mod blob_tests;
mod engine_tests;
mod export_tests;
mod merge_tests;
mod s3_mock;
mod s3_tests;

use std::path::PathBuf;

use mooring_core::{Connection, Folder, Protocol, SecretName};
use mooring_store::{CredentialKind, CredentialMeta, Secrets, Store};
use mooring_vault::{KdfParams, Vault};
use secrecy::SecretString;
use tempfile::TempDir;

use crate::{MemoryStore, Remote, StoreLocal};

pub(crate) const PASSWORD: &str = "test-only sync master pw";
pub(crate) const VECTOR_PASSWORD: &str = "nexus-test-vector-password";

pub(crate) fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

/// One vault, opened on `n` devices (same header, same DEK).
pub(crate) fn vaults(n: usize) -> Vec<Vault> {
    let pw = SecretString::from(PASSWORD.to_owned());
    let first = Vault::create(&pw, KdfParams::TEST).expect("vault");
    let mut out = Vec::new();
    for _ in 1..n {
        let mut v = Vault::from_header(first.header().clone());
        v.unlock(&pw).expect("unlock");
        out.push(v);
    }
    out.insert(0, first);
    out
}

/// A device: its own store, trust directory and name.
pub(crate) struct Device {
    pub store: Store,
    pub vault: Vault,
    pub dir: TempDir,
    pub name: String,
}

impl Device {
    pub fn new(vault: Vault, name: &str) -> Self {
        Self {
            store: Store::open_in_memory().expect("store"),
            vault,
            dir: tempfile::tempdir().expect("dir"),
            name: name.to_owned(),
        }
    }

    pub fn local(&self) -> StoreLocal<'_> {
        StoreLocal {
            store: &self.store,
            vault: &self.vault,
            trust_dir: self.dir.path(),
            device_name: self.name.clone(),
        }
    }

    pub fn root(&self) -> Folder {
        match self.store.root_folder().expect("root") {
            Some(r) => r,
            None => self.store.create_folder(None, "All connections").expect("create root"),
        }
    }

    pub fn conn(&self, name: &str, host: &str) -> Connection {
        let c = Connection::new(self.root().id, name, Protocol::Ssh, host).expect("conn");
        self.store.create_connection(&c).expect("insert")
    }

    pub fn password(&self, name: &str, pw: &[u8]) -> CredentialMeta {
        let secrets: Secrets<'_> = [(SecretName::Password, pw)].into_iter().collect();
        self.store
            .create_credential(
                &self.vault,
                name,
                CredentialKind::UserPassword,
                &serde_json::json!({ "username": "ops" }),
                &secrets,
            )
            .expect("credential")
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .store
            .list_folders()
            .expect("folders")
            .iter()
            .flat_map(|f| self.store.list_connections(f.id).expect("conns"))
            .map(|c| c.name)
            .collect();
        v.sort();
        v
    }

    pub fn trust(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
    }
}

/// A shared in-memory bucket and a `Remote` for `vault`'s id.
pub(crate) fn remote(store: &MemoryStore, vault: &Vault) -> Remote<MemoryStore> {
    Remote::new(store.clone(), "team/sync", vault.vault_id()).expect("remote")
}
