//! Biometric unlock (ADR-0022): the vault's `WrapKey` (ADR-0006) behind an OS gesture.
//!
//! * macOS ([`macos`]): a data-protection keychain item with `BiometryCurrentSet` +
//!   `WhenUnlockedThisDeviceOnly`; needs a Developer-ID-signed build (owner decision 23), so
//!   an unsigned build reports `unsigned_build`.
//! * Windows ([`windows`]): a `KeyCredentialManager` (Windows Hello) key signs a fixed
//!   per-vault challenge; `WrapKey = HKDF-SHA256(signature, salt = vault id, info)`. Nothing
//!   readable is stored.
//! * Linux ([`linux`]): not offered (`no_acl`): Secret Service has no biometric ACL.
//!
//! The master password never reaches this module. Every store error is a fixed text; the
//! platform modules log a status code at most. [`BiometricRuntime`] holds the platform store
//! and the failure window of the auto-disable rule (3 failures within 10 minutes).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use mooring_vault::{Uuid, VaultError, WrapKeyStore};
use sha2::Sha256;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
#[cfg(not(any(target_os = "macos", windows)))]
pub mod linux;

/// Keychain service / Hello key-name prefix of every Mooring item.
pub const SERVICE: &str = "io.github.yyasar21.mooring";
/// Wrap key length.
pub const KEY_LEN: usize = 32;
/// Consecutive failures that suspend biometric unlock (owner decision 24).
pub const MAX_FAILURES: usize = 3;
/// Window of [`MAX_FAILURES`].
pub const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// HKDF info of the Windows Hello derivation (ADR-0022 §1).
pub const HELLO_INFO: &[u8] = b"mooring hello v1";
/// Prefix of the fixed challenge Hello signs (`"mooring-hello-v1" ‖ vault_id`).
pub const HELLO_CHALLENGE_PREFIX: &[u8] = b"mooring-hello-v1";

/// Why the store is not usable right now (`biometric_status.reason`, ADR-0022 §2 plus the
/// task's `no_acl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// The OS has no biometric ACL (Linux).
    NoAcl,
    /// macOS build without the application-identifier entitlement.
    UnsignedBuild,
    /// The OS store or biometry is not set up (no Hello, no Touch ID sensor, keychain
    /// refused, item of another machine in portable mode).
    KeychainUnavailable,
}

impl Unavailable {
    /// Wire reason.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoAcl => "no_acl",
            Self::UnsignedBuild => "unsigned_build",
            Self::KeychainUnavailable => "keychain_unavailable",
        }
    }
}

/// What went wrong in one store call. Fixed texts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioError {
    /// The store cannot be used at all.
    Unavailable(Unavailable),
    /// The user cancelled the OS prompt.
    Cancelled,
    /// The OS item or key is gone: biometry re-enrolled (macOS `BiometryCurrentSet`), Hello
    /// container reset (`KeyCredentialStatus::NotFound`), or never enrolled on this machine.
    NotFound,
    /// The gesture failed or the OS refused.
    Failed,
}

impl BioError {
    /// Wire reason of a failed unlock (`vault.biometric_failed.reason`).
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unavailable(u) => u.reason(),
            Self::Cancelled => "cancelled",
            Self::NotFound => "biometry_changed",
            Self::Failed => "failed",
        }
    }

    /// The `VaultError` the vault layer sees (never key material).
    pub fn vault_error(self) -> VaultError {
        match self {
            Self::Unavailable(_) | Self::NotFound => VaultError::KeyringUnavailable,
            Self::Cancelled => VaultError::Keyring("the biometric prompt was cancelled".into()),
            Self::Failed => VaultError::Keyring("the biometric check failed".into()),
        }
    }
}

/// Owner decision 23: Touch ID ships in every macOS build but is enabled only in
/// Developer-ID-signed ones. The release pipeline compiles those with
/// `RUSTFLAGS="--cfg mooring_signed_build"`; every other build answers `unsigned_build`
/// without touching the keychain. (`unexpected_cfgs` is allowed here until the manifest
/// declares the cfg with `check-cfg`.)
#[allow(unexpected_cfgs)]
pub const SIGNED_BUILD: bool = cfg!(mooring_signed_build);

/// A gesture-gated store of the wrap key. Implementations never log the key.
pub trait BiometricStore: Send + Sync + std::fmt::Debug {
    /// `macos` | `windows` | `linux`.
    fn platform(&self) -> &'static str;
    /// Human label of the gesture (`Touch ID`, `Windows Hello`), `None` when not offered.
    fn label(&self) -> Option<&'static str>;
    /// Passive check: can the store be used on this machine and build? Never prompts.
    fn available(&self) -> Result<(), Unavailable>;
    /// Enrol: make (or derive) the wrap key for `vault_id` behind the gesture. Prompts.
    fn create(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError>;
    /// Fetch (or re-derive) the wrap key. Prompts.
    fn get(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError>;
    /// Delete the item or key; a missing one is not an error. Never prompts.
    fn delete(&self, vault_id: Uuid) -> Result<(), BioError>;
}

/// `WrapKey` of a Windows Hello signature: `HKDF-SHA256(ikm = signature, salt = vault_id,
/// info = "mooring hello v1")`. Pure; the vector test pins it.
pub fn wrap_key_from_signature(signature: &[u8], vault_id: Uuid) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), signature);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    // 32 bytes is always within HKDF-SHA256's 8160-byte limit.
    if hk.expand(HELLO_INFO, out.as_mut_slice()).is_err() {
        tracing::error!("hkdf expand failed for a 32-byte key");
    }
    out
}

/// The bytes Windows Hello signs for `vault_id`.
pub fn hello_challenge(vault_id: Uuid) -> Vec<u8> {
    let mut c = HELLO_CHALLENGE_PREFIX.to_vec();
    c.extend_from_slice(vault_id.as_bytes());
    c
}

/// Adapter from [`BiometricStore`] to the vault's [`WrapKeyStore`]; the last store error is
/// kept so the command layer can tell a cancel from a reset after `unlock_with_keyring`.
#[derive(Debug)]
pub struct Adapter<'a> {
    store: &'a dyn BiometricStore,
    last: Mutex<Option<BioError>>,
}

impl<'a> Adapter<'a> {
    /// Wrap `store`.
    pub fn new(store: &'a dyn BiometricStore) -> Self {
        Self { store, last: Mutex::new(None) }
    }

    /// The error of the last failed call, if any.
    pub fn last_error(&self) -> Option<BioError> {
        self.last.lock().ok().and_then(|l| *l)
    }

    fn note<T>(&self, r: Result<T, BioError>) -> Result<T, VaultError> {
        match r {
            Ok(v) => Ok(v),
            Err(e) => {
                if let Ok(mut l) = self.last.lock() {
                    *l = Some(e);
                }
                Err(e.vault_error())
            }
        }
    }
}

impl WrapKeyStore for Adapter<'_> {
    fn put(&self, _: Uuid, _: &Zeroizing<[u8; KEY_LEN]>) -> Result<(), VaultError> {
        // The vault calls `create`; a store never receives a key chosen elsewhere.
        Err(VaultError::Keyring("biometric stores do not accept keys".into()))
    }

    fn create(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        self.note(self.store.create(vault_id))
    }

    fn get(&self, vault_id: Uuid) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, VaultError> {
        match self.store.get(vault_id) {
            Err(BioError::NotFound) => {
                if let Ok(mut l) = self.last.lock() {
                    *l = Some(BioError::NotFound);
                }
                Ok(None)
            }
            other => self.note(other).map(Some),
        }
    }

    fn delete(&self, vault_id: Uuid) -> Result<(), VaultError> {
        self.note(self.store.delete(vault_id))
    }
}

/// A wrap key fetched before the vault lock is taken (the OS prompt must not hold the vault
/// mutex: every other command would wait for the user's gesture). Hands the key to
/// `unlock_with_keyring` once.
pub struct Prefetched(pub Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for Prefetched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prefetched(..)")
    }
}

impl WrapKeyStore for Prefetched {
    fn put(&self, _: Uuid, _: &Zeroizing<[u8; KEY_LEN]>) -> Result<(), VaultError> {
        Err(VaultError::Keyring("read-only wrap key".into()))
    }
    fn get(&self, _: Uuid) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, VaultError> {
        Ok(Some(self.0.clone()))
    }
    fn delete(&self, _: Uuid) -> Result<(), VaultError> {
        Ok(())
    }
}

/// The platform store plus the failure window (held in `AppState`).
pub struct BiometricRuntime {
    store: Arc<dyn BiometricStore>,
    failures: Mutex<Vec<Instant>>,
}

impl std::fmt::Debug for BiometricRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BiometricRuntime")
            .field("platform", &self.store.platform())
            .finish_non_exhaustive()
    }
}

impl BiometricRuntime {
    /// Over `store`.
    pub fn new(store: Arc<dyn BiometricStore>) -> Self {
        Self { store, failures: Mutex::new(Vec::new()) }
    }

    /// The platform store of this build.
    pub fn production_store() -> Arc<dyn BiometricStore> {
        #[cfg(target_os = "macos")]
        let store: Arc<dyn BiometricStore> = Arc::new(self::macos::TouchIdStore);
        #[cfg(windows)]
        let store: Arc<dyn BiometricStore> = Arc::new(self::windows::HelloStore);
        #[cfg(not(any(target_os = "macos", windows)))]
        let store: Arc<dyn BiometricStore> = Arc::new(self::linux::NoStore);
        store
    }

    /// The store.
    pub fn store(&self) -> &dyn BiometricStore {
        self.store.as_ref()
    }

    /// Record one failed attempt at `now`; `true` when it is the [`MAX_FAILURES`]th within
    /// [`FAILURE_WINDOW`] (the caller suspends and the window is cleared).
    pub fn record_failure(&self, now: Instant) -> bool {
        let mut f = self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f.retain(|t| now.saturating_duration_since(*t) < FAILURE_WINDOW);
        f.push(now);
        if f.len() >= MAX_FAILURES {
            f.clear();
            return true;
        }
        false
    }

    /// A success resets the window.
    pub fn reset_failures(&self) {
        self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    }

    /// Failures inside the window (tests).
    pub fn failures(&self, now: Instant) -> usize {
        let f = self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f.iter().filter(|t| now.saturating_duration_since(**t) < FAILURE_WINDOW).count()
    }
}

/// A scriptable in-memory store for tests and the `test-util` build: enrols hold a random
/// key per vault id; `fail_next` makes the next prompting call answer with that error.
#[cfg(any(test, feature = "test-util"))]
pub mod memory {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{BioError, BiometricStore, Unavailable, KEY_LEN};
    use mooring_vault::Uuid;
    use zeroize::Zeroizing;

    /// See the module docs.
    #[derive(Default)]
    pub struct MemoryBiometricStore {
        keys: Mutex<HashMap<Uuid, Zeroizing<[u8; KEY_LEN]>>>,
        /// `Some(reason)` makes the store unavailable.
        pub unavailable: Mutex<Option<Unavailable>>,
        /// Errors to answer the next prompting calls with, in order.
        pub fail_next: Mutex<Vec<BioError>>,
        /// Platform name reported.
        pub platform: &'static str,
        /// Prompting calls made so far.
        pub prompts: Mutex<usize>,
    }

    impl MemoryBiometricStore {
        /// An available store that reports `platform`.
        pub fn new(platform: &'static str) -> Self {
            Self { platform, ..Self::default() }
        }

        /// Queue `e` for the next prompting call.
        pub fn fail_next(&self, e: BioError) {
            self.fail_next.lock().expect("lock").push(e);
        }

        /// Make the store report `reason`.
        pub fn set_unavailable(&self, reason: Option<Unavailable>) {
            *self.unavailable.lock().expect("lock") = reason;
        }

        /// Items held.
        pub fn len(&self) -> usize {
            self.keys.lock().expect("lock").len()
        }

        /// Whether no item is held.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Drop the item without telling anyone (simulates a biometry re-enrolment).
        pub fn forget(&self, vault_id: Uuid) {
            self.keys.lock().expect("lock").remove(&vault_id);
        }

        fn prompt(&self) -> Result<(), BioError> {
            *self.prompts.lock().expect("lock") += 1;
            if let Some(u) = *self.unavailable.lock().expect("lock") {
                return Err(BioError::Unavailable(u));
            }
            let mut q = self.fail_next.lock().expect("lock");
            if q.is_empty() {
                Ok(())
            } else {
                Err(q.remove(0))
            }
        }
    }

    impl std::fmt::Debug for MemoryBiometricStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemoryBiometricStore").field("items", &self.len()).finish()
        }
    }

    impl BiometricStore for MemoryBiometricStore {
        fn platform(&self) -> &'static str {
            self.platform
        }
        fn label(&self) -> Option<&'static str> {
            match self.platform {
                "macos" => Some("Touch ID"),
                "windows" => Some("Windows Hello"),
                _ => None,
            }
        }
        fn available(&self) -> Result<(), Unavailable> {
            self.unavailable.lock().expect("lock").map_or(Ok(()), Err)
        }
        fn create(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
            self.prompt()?;
            let mut k = [0u8; KEY_LEN];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut k);
            let k = Zeroizing::new(k);
            self.keys.lock().expect("lock").insert(vault_id, k.clone());
            Ok(k)
        }
        fn get(&self, vault_id: Uuid) -> Result<Zeroizing<[u8; KEY_LEN]>, BioError> {
            self.prompt()?;
            self.keys.lock().expect("lock").get(&vault_id).cloned().ok_or(BioError::NotFound)
        }
        fn delete(&self, vault_id: Uuid) -> Result<(), BioError> {
            if let Some(u) = *self.unavailable.lock().expect("lock") {
                return Err(BioError::Unavailable(u));
            }
            self.keys.lock().expect("lock").remove(&vault_id);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-0022 test plan: fixed signature bytes → fixed key (RFC 5869 over SHA-256; the
    /// expected value was computed independently with Python's `hmac`).
    #[test]
    fn hello_derivation_vector() {
        let id = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        let sig = [0xA5u8; 256];
        let k = wrap_key_from_signature(&sig, id);
        assert_eq!(
            hex::encode(k.as_slice()),
            "bdd0c075a59a06d5be160d32e6d622772384788b27cb315d248db1a9cac52f03"
        );
        assert_ne!(k, wrap_key_from_signature(&[0xA6u8; 256], id), "signature-bound");
        assert_ne!(k, wrap_key_from_signature(&sig, Uuid::from_u128(2)), "vault-bound");
        let c = hello_challenge(id);
        assert!(c.starts_with(HELLO_CHALLENGE_PREFIX) && c.ends_with(id.as_bytes()));
        assert_eq!(c.len(), HELLO_CHALLENGE_PREFIX.len() + 16);
    }

    #[test]
    fn failure_window_suspends_on_the_third_within_ten_minutes() {
        let rt = BiometricRuntime::new(Arc::new(memory::MemoryBiometricStore::new("macos")));
        let t0 = Instant::now();
        assert!(!rt.record_failure(t0));
        assert!(!rt.record_failure(t0 + Duration::from_secs(60)));
        assert_eq!(rt.failures(t0 + Duration::from_secs(60)), 2);
        assert!(rt.record_failure(t0 + Duration::from_secs(120)), "third within the window");
        assert_eq!(rt.failures(t0 + Duration::from_secs(120)), 0, "window cleared");
        // spread beyond ten minutes: never three inside one window
        assert!(!rt.record_failure(t0));
        assert!(!rt.record_failure(t0 + FAILURE_WINDOW));
        assert!(!rt.record_failure(t0 + 2 * FAILURE_WINDOW));
        rt.reset_failures();
        assert_eq!(rt.failures(t0 + 2 * FAILURE_WINDOW), 0);
        assert!(format!("{rt:?}").contains("macos"));
    }

    #[test]
    fn adapter_maps_errors_and_remembers_the_last_one() {
        let store = memory::MemoryBiometricStore::new("windows");
        let id = Uuid::from_u128(7);
        let a = Adapter::new(&store);
        assert!(a.put(id, &Zeroizing::new([0; KEY_LEN])).is_err(), "no foreign keys");
        let k = WrapKeyStore::create(&a, id).expect("enrol");
        assert_eq!(a.get(id).expect("get").expect("some"), k);
        store.fail_next(BioError::Cancelled);
        assert!(matches!(a.get(id), Err(VaultError::Keyring(_))));
        assert_eq!(a.last_error(), Some(BioError::Cancelled));
        store.forget(id);
        assert_eq!(a.get(id).expect("missing is None"), None);
        assert_eq!(a.last_error(), Some(BioError::NotFound));
        store.set_unavailable(Some(Unavailable::NoAcl));
        assert_eq!(a.get(id), Err(VaultError::KeyringUnavailable));
        assert_eq!(BioError::Unavailable(Unavailable::NoAcl).reason(), "no_acl");
        assert_eq!(BioError::NotFound.reason(), "biometry_changed");
        assert_eq!(Unavailable::UnsignedBuild.reason(), "unsigned_build");
        let shown = format!("{:?}", BioError::Failed.vault_error());
        assert!(!shown.contains(&hex::encode(k.as_slice())));
    }
}
