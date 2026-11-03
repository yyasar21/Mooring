//! Optional OS-keyring unlock (ADR-0006).
//!
//! ```text
//! WrapKey (32 B, random, lives in the OS keyring under account = vault_id)
//!   ──XChaCha20-Poly1305, AAD = header.aad() without keyring_wrap ‖ 0x1F ‖ "keyring"──► DEK
//! ```
//!
//! The master password stays mandatory to enable or disable the wrap. The OS adapter
//! (`keyring` crate) lives in `nexus-app`; this crate only defines [`WrapKeyStore`].

use std::collections::HashMap;
use std::sync::Mutex;

use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{open_key, random, seal_with};
use crate::error::VaultError;
use crate::format::Header;
use crate::kdf::KEY_LEN;
use crate::vault::{rewrap_password, Vault, VaultState};

/// Where the `WrapKey` lives. Implementations must never log or print the key.
pub trait WrapKeyStore {
    /// Store (or replace) the wrap key for `vault_id`.
    fn put(&self, vault_id: Uuid, key: &Zeroizing<[u8; KEY_LEN]>) -> Result<(), VaultError>;
    /// Fetch the wrap key; `Ok(None)` when there is no item.
    fn get(&self, vault_id: Uuid) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, VaultError>;
    /// Delete the wrap key. Deleting a missing item is not an error.
    fn delete(&self, vault_id: Uuid) -> Result<(), VaultError>;
}

/// In-memory store for tests and for platforms without a keyring.
#[derive(Default)]
pub struct MemoryWrapKeyStore {
    keys: Mutex<HashMap<Uuid, Zeroizing<[u8; KEY_LEN]>>>,
}

impl MemoryWrapKeyStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored items (no key material is exposed).
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.lock().map_or(0, |k| k.len())
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for MemoryWrapKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryWrapKeyStore").field("items", &self.len()).finish()
    }
}

fn poisoned() -> VaultError {
    VaultError::Keyring("in-memory store poisoned".into())
}

impl WrapKeyStore for MemoryWrapKeyStore {
    fn put(&self, vault_id: Uuid, key: &Zeroizing<[u8; KEY_LEN]>) -> Result<(), VaultError> {
        self.keys.lock().map_err(|_| poisoned())?.insert(vault_id, key.clone());
        Ok(())
    }

    fn get(&self, vault_id: Uuid) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, VaultError> {
        Ok(self.keys.lock().map_err(|_| poisoned())?.get(&vault_id).cloned())
    }

    fn delete(&self, vault_id: Uuid) -> Result<(), VaultError> {
        self.keys.lock().map_err(|_| poisoned())?.remove(&vault_id);
        Ok(())
    }
}

/// AAD of the keyring wrap: the header AAD with `keyring_wrap = None` (the wrap cannot cover
/// itself) ‖ 0x1F ‖ `b"keyring"`.
pub(crate) fn keyring_aad(header: &Header) -> Vec<u8> {
    let without = Header { keyring_wrap: None, ..header.clone() };
    let mut v = without.aad();
    v.push(0x1f);
    v.extend_from_slice(b"keyring");
    v
}

impl Vault {
    /// Enable OS-keyring unlock. Requires the master password; the vault keeps its current
    /// locked/unlocked state. Persist [`Vault::header`] afterwards.
    pub fn enable_keyring_unlock(
        &mut self,
        store: &dyn WrapKeyStore,
        password: &SecretString,
    ) -> Result<(), VaultError> {
        let was = self.state();
        let kek = self.unlock_with_kek(password)?;
        let dek = self.dek.clone().ok_or(VaultError::Locked)?;
        let wrap_key = Zeroizing::new(random::<KEY_LEN>());
        let mut header = self.header.clone();
        header.keyring_wrap = Some(seal_with(&wrap_key, &keyring_aad(&header), dek.as_ref()));
        rewrap_password(&mut header, &kek, &dek);
        // Store first: if the OS keyring refuses, the header is left untouched.
        store.put(header.vault_id, &wrap_key)?;
        self.header = header;
        if was == VaultState::Locked {
            self.dek = None;
        }
        tracing::info!("keyring unlock enabled");
        Ok(())
    }

    /// Unlock with the wrap key from the OS keyring (the OS may prompt for biometrics).
    pub fn unlock_with_keyring(&mut self, store: &dyn WrapKeyStore) -> Result<(), VaultError> {
        let sealed = self.header.keyring_wrap.as_ref().ok_or(VaultError::KeyringUnavailable)?;
        if self.header.vault_id.is_nil() {
            return Err(VaultError::KeyringUnavailable);
        }
        let wrap_key = store.get(self.header.vault_id)?.ok_or(VaultError::KeyringUnavailable)?;
        let dek = open_key(&wrap_key, &keyring_aad(&self.header), sealed)
            .map_err(|_| VaultError::Unlock)?;
        self.dek = Some(dek);
        tracing::info!("vault unlocked via keyring");
        Ok(())
    }

    /// Disable OS-keyring unlock: requires the master password, deletes the keyring item and
    /// clears `keyring_wrap`. The vault keeps its current state. Persist the header afterwards.
    pub fn disable_keyring_unlock(
        &mut self,
        store: &dyn WrapKeyStore,
        password: &SecretString,
    ) -> Result<(), VaultError> {
        let was = self.state();
        let kek = self.unlock_with_kek(password)?;
        let dek = self.dek.clone().ok_or(VaultError::Locked)?;
        // Delete first: a failed delete leaves everything as it was, so the user can retry.
        store.delete(self.header.vault_id)?;
        let mut header = self.header.clone();
        header.keyring_wrap = None;
        rewrap_password(&mut header, &kek, &dek);
        self.header = header;
        if was == VaultState::Locked {
            self.dek = None;
        }
        tracing::info!("keyring unlock disabled");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;

    const PW: &str = "correct horse battery";

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    /// Store whose every call fails, to check that failures leave the header untouched.
    struct Broken;
    impl WrapKeyStore for Broken {
        fn put(&self, _: Uuid, _: &Zeroizing<[u8; KEY_LEN]>) -> Result<(), VaultError> {
            Err(VaultError::Keyring("denied".into()))
        }
        fn get(&self, _: Uuid) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, VaultError> {
            Err(VaultError::Keyring("denied".into()))
        }
        fn delete(&self, _: Uuid) -> Result<(), VaultError> {
            Err(VaultError::Keyring("denied".into()))
        }
    }

    #[test]
    fn keyring_round_trip_survives_reload() {
        let store = MemoryWrapKeyStore::new();
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let s = v.seal("r", "f", b"via keyring").expect("seal");
        v.lock();
        v.enable_keyring_unlock(&store, &pw(PW)).expect("enable");
        assert_eq!(v.state(), VaultState::Locked, "enable keeps the vault locked");
        assert!(v.header().keyring_enabled());
        assert_eq!(store.len(), 1);

        let bytes = v.header().to_bytes().expect("bytes");
        let mut again = Vault::from_header_bytes(&bytes).expect("parse");
        again.unlock_with_keyring(&store).expect("keyring unlock");
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"via keyring");

        // password unlock still works with the wrap present
        let mut again = Vault::from_header_bytes(&bytes).expect("parse");
        again.unlock(&pw(PW)).expect("password unlock");
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"via keyring");
    }

    #[test]
    fn enable_requires_password_and_failed_store_changes_nothing() {
        let store = MemoryWrapKeyStore::new();
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let before = v.header().clone();
        assert_eq!(
            v.enable_keyring_unlock(&store, &pw("wrong password!!")),
            Err(VaultError::Unlock)
        );
        assert_eq!(v.header(), &before);
        assert!(store.is_empty());
        assert!(matches!(v.enable_keyring_unlock(&Broken, &pw(PW)), Err(VaultError::Keyring(_))));
        assert_eq!(v.header(), &before);
    }

    #[test]
    fn unlock_with_keyring_failure_modes() {
        let store = MemoryWrapKeyStore::new();
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        v.lock();
        // not enabled
        assert_eq!(v.unlock_with_keyring(&store), Err(VaultError::KeyringUnavailable));
        v.enable_keyring_unlock(&store, &pw(PW)).expect("enable");
        // item missing
        let empty = MemoryWrapKeyStore::new();
        assert_eq!(v.unlock_with_keyring(&empty), Err(VaultError::KeyringUnavailable));
        // OS error passes through
        assert!(matches!(v.unlock_with_keyring(&Broken), Err(VaultError::Keyring(_))));
        // wrong key in the keyring
        let wrong = MemoryWrapKeyStore::new();
        wrong.put(v.vault_id(), &Zeroizing::new([9u8; KEY_LEN])).expect("put");
        assert_eq!(v.unlock_with_keyring(&wrong), Err(VaultError::Unlock));
        assert_eq!(v.state(), VaultState::Locked);
    }

    #[test]
    fn keyring_wrap_is_bound_to_header() {
        let store = MemoryWrapKeyStore::new();
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        v.enable_keyring_unlock(&store, &pw(PW)).expect("enable");
        let tamper: [fn(&mut Header); 3] = [
            |h| h.kdf_params.t += 1,
            |h| h.salt[0] ^= 1,
            |h| {
                if let Some(k) = h.keyring_wrap.as_mut() {
                    k.ciphertext[0] ^= 1;
                }
            },
        ];
        for (i, f) in tamper.iter().enumerate() {
            let mut h = v.header().clone();
            f(&mut h);
            let mut again = Vault::from_header(h);
            assert_eq!(again.unlock_with_keyring(&store), Err(VaultError::Unlock), "tamper {i}");
        }
        // moving the wrap to another vault id misses the keyring item and fails AEAD
        let mut h = v.header().clone();
        let other = Uuid::new_v4();
        store.put(other, &store.get(v.vault_id()).expect("get").expect("some")).expect("put");
        h.vault_id = other;
        assert_eq!(Vault::from_header(h).unlock_with_keyring(&store), Err(VaultError::Unlock));
        assert!(keyring_aad(v.header()).ends_with(b"\x1fkeyring"));
    }

    #[test]
    fn disable_deletes_item_and_clears_wrap() {
        let store = MemoryWrapKeyStore::new();
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        v.enable_keyring_unlock(&store, &pw(PW)).expect("enable");
        let enabled = v.header().clone();
        assert!(matches!(v.disable_keyring_unlock(&Broken, &pw(PW)), Err(VaultError::Keyring(_))));
        assert_eq!(v.header(), &enabled, "failed delete leaves the wrap in place");
        assert_eq!(
            v.disable_keyring_unlock(&store, &pw("wrong password!!")),
            Err(VaultError::Unlock)
        );
        v.disable_keyring_unlock(&store, &pw(PW)).expect("disable");
        assert!(!v.header().keyring_enabled());
        assert!(store.is_empty());
        assert_eq!(v.unlock_with_keyring(&store), Err(VaultError::KeyringUnavailable));
        let mut again = Vault::from_header_bytes(&v.header().to_bytes().expect("b")).expect("p");
        again.unlock(&pw(PW)).expect("password unlock after disable");
    }

    #[test]
    fn change_password_drops_keyring_wrap() {
        let store = MemoryWrapKeyStore::new();
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        v.enable_keyring_unlock(&store, &pw(PW)).expect("enable");
        v.change_password(&pw(PW), &pw("another long password"), KdfParams::TEST).expect("chg");
        assert!(!v.header().keyring_enabled());
        assert_eq!(v.unlock_with_keyring(&store), Err(VaultError::KeyringUnavailable));
    }

    #[test]
    fn debug_hides_keys() {
        let store = MemoryWrapKeyStore::new();
        store.put(Uuid::nil(), &Zeroizing::new([0xAB; KEY_LEN])).expect("put");
        let shown = format!("{store:?}");
        assert!(shown.contains("items: 1"));
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("ab, "));
    }
}
