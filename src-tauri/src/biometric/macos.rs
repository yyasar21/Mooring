//! macOS: the wrap key as a data-protection keychain item (ADR-0022 §1) with
//! `kSecAccessControlBiometryCurrentSet` + `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
//! through `security-framework`'s safe API (the FFI stays inside that crate; no `unsafe`
//! here). Any read prompts Touch ID; re-enrolling a finger invalidates the item
//! (`errSecItemNotFound` / `errSecAuthFailed` → `biometry_changed`).
//!
//! Gate (owner decision 23): the data-protection keychain needs an application identifier,
//! which only a Developer-ID-signed build carries. The release pipeline builds those with
//! `--cfg mooring_signed_build` ([`super::SIGNED_BUILD`]); any other build answers
//! `unsigned_build` and never calls the keychain. A signed build still probes once per status
//! (a query for an account that never exists: `errSecMissingEntitlement` means the signature
//! lacks the entitlement, `errSecItemNotFound` means it is there). The probe never prompts
//! because no item matches it.

use mooring_vault::Uuid;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error as SecError;
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options,
};
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
use zeroize::Zeroizing;

use super::{BioError, BiometricStore, Unavailable, KEY_LEN, SERVICE, SIGNED_BUILD};

/// Account of the entitlement probe; never created.
const PROBE_ACCOUNT: &str = "entitlement-probe";

const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// The Touch ID store.
#[derive(Debug, Default, Clone, Copy)]
pub struct TouchIdStore;

fn account(vault_id: Uuid) -> String {
    vault_id.to_string()
}

/// Query of our item in the data-protection keychain.
fn options(vault_id: Uuid) -> PasswordOptions {
    let mut o = PasswordOptions::new_generic_password(SERVICE, &account(vault_id));
    o.use_protected_keychain();
    o
}

/// The access control of a new item: biometry of the currently enrolled set, this device
/// only, only while unlocked.
fn access_control() -> Result<SecAccessControl, BioError> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
    )
    .map_err(|e| map(&e, "access control"))
}

/// Map a Security.framework status to a fixed [`BioError`]; the code is logged, never shown.
fn map(e: &SecError, op: &'static str) -> BioError {
    let code = e.code();
    tracing::warn!(op, code, "keychain call failed");
    match code {
        ERR_SEC_USER_CANCELED => BioError::Cancelled,
        ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_AUTH_FAILED => BioError::NotFound,
        ERR_SEC_MISSING_ENTITLEMENT => BioError::Unavailable(Unavailable::UnsignedBuild),
        ERR_SEC_INTERACTION_NOT_ALLOWED => BioError::Unavailable(Unavailable::KeychainUnavailable),
        _ => BioError::Failed,
    }
}

/// One keychain query for an account that is never created (see the module docs).
fn probe() -> Result<(), Unavailable> {
    let mut o = PasswordOptions::new_generic_password(SERVICE, PROBE_ACCOUNT);
    o.use_protected_keychain();
    match generic_password(o) {
        // An item under the probe account would be a foreign write; treat it as usable.
        Ok(_) => Ok(()),
        Err(e) => match e.code() {
            ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            ERR_SEC_MISSING_ENTITLEMENT => Err(Unavailable::UnsignedBuild),
            code => {
                tracing::warn!(code, "keychain probe failed");
                Err(Unavailable::KeychainUnavailable)
            }
        },
    }
}

impl BiometricStore for TouchIdStore {
    fn platform(&self) -> &'static str {
        "macos"
    }

    fn label(&self) -> Option<&'static str> {
        Some("Touch ID")
    }

    fn available(&self) -> Result<(), Unavailable> {
        if !SIGNED_BUILD {
            return Err(Unavailable::UnsignedBuild);
        }
        probe()
    }

    fn create(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
        self.available().map_err(BioError::Unavailable)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, key.as_mut_slice());
        // Replace, never update: `SecItemUpdate` of an ACL item would prompt for the old one.
        self.delete(vault_id)?;
        let mut o = options(vault_id);
        o.set_access_control(access_control()?);
        o.set_label("Mooring vault unlock (Touch ID)");
        match set_generic_password_options(key.as_slice(), o) {
            Ok(()) => Ok(key),
            Err(e) if e.code() == ERR_SEC_DUPLICATE_ITEM => Err(BioError::Failed),
            Err(e) => Err(map(&e, "add")),
        }
    }

    fn get(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
        if !SIGNED_BUILD {
            return Err(BioError::Unavailable(Unavailable::UnsignedBuild));
        }
        let bytes = Zeroizing::new(generic_password(options(vault_id)).map_err(|e| map(&e, "read"))?);
        let key: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            tracing::warn!("keychain item has the wrong size");
            BioError::Failed
        })?;
        Ok(Zeroizing::new(key))
    }

    fn delete(&self, vault_id: Uuid) -> Result<(), BioError> {
        if !SIGNED_BUILD {
            // An unsigned build never created an item.
            return Ok(());
        }
        match delete_generic_password_options(options(vault_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => match map(&e, "delete") {
                // A missing entitlement means there was never an item to delete.
                BioError::Unavailable(Unavailable::UnsignedBuild) => Ok(()),
                other => Err(other),
            },
        }
    }
}
