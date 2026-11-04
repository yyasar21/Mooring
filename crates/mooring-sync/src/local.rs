//! [`StoreLocal`]: the [`LocalSide`] over a borrowed [`Store`], an unlocked [`Vault`] and the
//! trust-store directory. Device state lives under `sync.state` (JSON) and the base snapshot
//! under `sync.base`, sealed under the DEK as record `mooring-sync` / field `base`.
//!
//! The Tauri layer, which keeps store and vault behind mutexes, implements [`LocalSide`]
//! itself by locking inside each method and delegating to the free functions used here.

use std::path::Path;

use mooring_store::Store;
use mooring_vault::{Sealed, SubKey, Vault};
use uuid::Uuid;

use crate::blob::sync_key;
use crate::error::{Result, SyncError};
use crate::merge::Reseal;
use crate::snapshot::{self, Snapshot};
use crate::state::{LocalSide, LocalState};

const KEY_STATE: &str = "sync.state";
const KEY_BASE: &str = "sync.base";
const BASE_RECORD: &str = "mooring-sync";
const BASE_FIELD: &str = "base";

/// The header object of `vault`: its header bytes; refused while the keyring wrap is on
/// (it is bound into the password wrap's AAD and must not reach the bucket, ADR-0017 §2).
pub fn header_object(vault: &Vault) -> Result<Vec<u8>> {
    if vault.header().keyring_wrap.is_some() {
        return Err(SyncError::KeyringHeader);
    }
    Ok(vault.header().to_bytes()?)
}

/// Re-seal one sealed secret JSON from `old_id` to `new_id`.
pub fn reseal_secret(
    vault: &Vault,
    old_id: &str,
    new_id: &str,
    secret: &str,
    sealed: &str,
) -> Result<String> {
    let s: Sealed =
        serde_json::from_str(sealed).map_err(|_| SyncError::Format("sealed secret JSON"))?;
    let plain = vault.open(old_id, secret, &s)?;
    let out = vault.seal(new_id, secret, &plain)?;
    serde_json::to_string(&out).map_err(|_| SyncError::Format("sealed secret JSON"))
}

/// Load `sync.state`.
pub fn load_state(store: &Store) -> Result<Option<LocalState>> {
    store
        .sync_setting(KEY_STATE)?
        .map(|s| serde_json::from_str(&s).map_err(|_| SyncError::Format("sync.state")))
        .transpose()
}

/// Load and open `sync.base`.
pub fn load_base(store: &Store, vault: &Vault) -> Result<Option<Snapshot>> {
    let Some(text) = store.sync_setting(KEY_BASE)? else { return Ok(None) };
    let sealed: Sealed = serde_json::from_str(&text).map_err(|_| SyncError::Format("sync.base"))?;
    let plain = vault.open(BASE_RECORD, BASE_FIELD, &sealed)?;
    Snapshot::decode(&plain, vault.vault_id()).map(Some)
}

/// Persist `state` and, when given, the sealed base.
pub fn save_state(
    store: &Store,
    vault: &Vault,
    state: &LocalState,
    base: Option<&Snapshot>,
) -> Result<()> {
    if let Some(b) = base {
        let sealed = vault.seal(BASE_RECORD, BASE_FIELD, &b.encode()?)?;
        let text = serde_json::to_string(&sealed).map_err(|_| SyncError::Format("sync.base"))?;
        store.set_sync_setting(KEY_BASE, Some(&text))?;
    }
    let text = serde_json::to_string(state).map_err(|_| SyncError::Format("sync.state"))?;
    store.set_sync_setting(KEY_STATE, Some(&text))?;
    Ok(())
}

/// Forget all device sync state (`sync_disable`).
pub fn clear_state(store: &Store) -> Result<()> {
    store.set_sync_setting(KEY_BASE, None)?;
    store.set_sync_setting(KEY_STATE, None)?;
    Ok(())
}

/// [`LocalSide`] over borrowed parts (single-threaded callers and tests).
#[derive(Debug)]
pub struct StoreLocal<'a> {
    /// The store.
    pub store: &'a Store,
    /// The unlocked vault.
    pub vault: &'a Vault,
    /// Directory holding `known_hosts` and `known_*_certs`.
    pub trust_dir: &'a Path,
    /// Device display name.
    pub device_name: String,
}

impl Reseal for StoreLocal<'_> {
    fn reseal(&self, old_id: &str, new_id: &str, secret: &str, sealed: &str) -> Result<String> {
        reseal_secret(self.vault, old_id, new_id, secret, sealed)
    }
}

impl LocalSide for StoreLocal<'_> {
    fn vault_id(&self) -> Uuid {
        self.vault.vault_id()
    }

    fn device_name(&self) -> String {
        self.device_name.clone()
    }

    fn header_object(&self) -> Result<Vec<u8>> {
        header_object(self.vault)
    }

    fn sync_key(&self) -> Result<SubKey> {
        sync_key(self.vault)
    }

    fn snapshot(&self) -> Result<Snapshot> {
        snapshot::from_store(self.store, self.trust_dir, self.vault.vault_id(), &self.device_name)
    }

    fn apply(&self, s: &Snapshot) -> Result<()> {
        snapshot::apply(self.store, self.trust_dir, s)
    }

    fn load_state(&self) -> Result<Option<LocalState>> {
        load_state(self.store)
    }

    fn load_base(&self) -> Result<Option<Snapshot>> {
        load_base(self.store, self.vault)
    }

    fn save_state(&self, state: &LocalState, base: Option<&Snapshot>) -> Result<()> {
        save_state(self.store, self.vault, state, base)
    }
}
