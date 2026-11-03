//! OS keyring adapter for the vault's keyring wrap (ADR-0006).
//!
//! Service `xyz.homelab.mooring`, account = vault id. macOS Keychain, Windows Credential
//! Manager, Secret Service on Linux — chosen by the `keyring` crate. The wrap key is never
//! logged; keyring errors are mapped to fixed strings so no platform detail that might echo
//! the secret reaches the `WebView`.

use mooring_vault::{Uuid, VaultError, WrapKeyStore};
use zeroize::Zeroizing;

/// Keyring service name for every Mooring item.
pub const SERVICE: &str = "xyz.homelab.mooring";

const KEY_LEN: usize = 32;

/// [`WrapKeyStore`] backed by the platform credential store.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsWrapKeyStore;

fn entry(vault_id: Uuid) -> Result<keyring::Entry, VaultError> {
    keyring::Entry::new(SERVICE, &vault_id.to_string()).map_err(|e| map_err(&e))
}

fn map_err(e: &keyring::Error) -> VaultError {
    let msg = match e {
        keyring::Error::NoStorageAccess(_) => "access to the OS keyring was denied",
        keyring::Error::NoDefaultStore => "no OS keyring is available",
        keyring::Error::PlatformFailure(_) => "the OS keyring failed",
        _ => "unexpected OS keyring error",
    };
    tracing::warn!(kind = msg, "keyring operation failed");
    VaultError::Keyring(msg.to_owned())
}

impl WrapKeyStore for OsWrapKeyStore {
    fn put(&self, vault_id: Uuid, key: &Zeroizing<[u8; KEY_LEN]>) -> Result<(), VaultError> {
        entry(vault_id)?.set_secret(key.as_ref()).map_err(|e| map_err(&e))
    }

    fn get(&self, vault_id: Uuid) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, VaultError> {
        match entry(vault_id)?.get_secret() {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let key: [u8; KEY_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| VaultError::Keyring("keyring item has the wrong size".into()))?;
                Ok(Some(Zeroizing::new(key)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_err(&e)),
        }
    }

    fn delete(&self, vault_id: Uuid) -> Result<(), VaultError> {
        match entry(vault_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_err(&e)),
        }
    }
}
