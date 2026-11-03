//! The vault: create, unlock, seal/open fields, change password, lock.

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::autolock::LockReason;
use crate::crypto::{field_aad, open_key, open_with, random, seal_with};
use crate::error::VaultError;
use crate::format::{Header, Sealed, FORMAT_VERSION, MAGIC};
use crate::kdf::{derive_kek, KdfParams, KEY_LEN, SALT_LEN};

/// Minimum master-password length (characters). Length is the only rule.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// Whether the DEK is in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// DEK wiped; only the header is known.
    Locked,
    /// DEK in memory; fields can be sealed and opened.
    Unlocked,
}

/// An encrypted vault. See the crate docs for the key hierarchy.
pub struct Vault {
    pub(crate) header: Header,
    pub(crate) dek: Option<Zeroizing<[u8; KEY_LEN]>>,
}

// Hand-written so the DEK can never be printed.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("version", &self.header.version)
            .field("vault_id", &self.header.vault_id)
            .field("kdf_params", &self.header.kdf_params)
            .field("keyring", &self.header.keyring_enabled())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

pub(crate) fn check_password(password: &SecretString) -> Result<(), VaultError> {
    if password.expose_secret().chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword { min: MIN_PASSWORD_CHARS });
    }
    Ok(())
}

/// Re-seal the DEK under the KEK with the header's current AAD (fresh nonce).
pub(crate) fn rewrap_password(header: &mut Header, kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) {
    header.wrapped_dek = seal_with(kek, &header.aad(), dek);
}

impl Vault {
    /// Create a new vault with a fresh DEK and a fresh `vault_id`. Returns it unlocked.
    pub fn create(password: &SecretString, params: KdfParams) -> Result<Self, VaultError> {
        check_password(password)?;
        params.validate()?;
        let salt = random::<SALT_LEN>();
        let dek = Zeroizing::new(random::<KEY_LEN>());
        let mut header = Header {
            magic: MAGIC.to_owned(),
            version: FORMAT_VERSION,
            vault_id: Uuid::new_v4(),
            kdf: "argon2id".to_owned(),
            kdf_params: params,
            salt: salt.to_vec(),
            wrapped_dek: Sealed { nonce: Vec::new(), ciphertext: Vec::new() },
            keyring_wrap: None,
        };
        let kek = derive_kek(password.expose_secret().as_bytes(), &salt, params)?;
        rewrap_password(&mut header, &kek, &dek);
        tracing::info!(m_kib = params.m_kib, t = params.t, p = params.p, "vault created");
        Ok(Self { header, dek: Some(dek) })
    }

    /// Load a header; the vault starts locked.
    pub fn from_header(header: Header) -> Self {
        Self { header, dek: None }
    }

    /// Parse header bytes; the vault starts locked.
    pub fn from_header_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        Ok(Self::from_header(Header::from_bytes(bytes)?))
    }

    /// The header to persist. Contains no secret material.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Stable vault identity (nil only for a v1 header that has not been unlocked yet).
    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> VaultState {
        if self.dek.is_some() {
            VaultState::Unlocked
        } else {
            VaultState::Locked
        }
    }

    /// Derive the KEK and unwrap the DEK. Wrong password and tampering are indistinguishable.
    ///
    /// A v1 header is upgraded to v2 in memory on success (new `vault_id`, DEK re-wrapped with
    /// the v2 AAD). Check [`Header::needs_upgrade`] before calling and persist
    /// [`Vault::header`] afterwards when it was true.
    pub fn unlock(&mut self, password: &SecretString) -> Result<(), VaultError> {
        self.unlock_with_kek(password).map(drop)
    }

    /// [`Vault::unlock`] for callers that persist the header: when the unlock upgraded a v1
    /// header, `persist` is called with the new header. If `persist` fails, the vault is locked
    /// again and the previous (v1) header restored, so no unpersisted `vault_id` stays in
    /// memory and the next attempt starts clean (A1 review L1). Unlock errors come back
    /// through `E: From<VaultError>`.
    pub fn unlock_persisting<E: From<VaultError>>(
        &mut self,
        password: &SecretString,
        persist: impl FnOnce(&Header) -> Result<(), E>,
    ) -> Result<(), E> {
        let before = self.header.needs_upgrade().then(|| self.header.clone());
        self.unlock(password)?;
        if let Some(before) = before {
            if let Err(e) = persist(&self.header) {
                self.header = before;
                self.lock();
                tracing::warn!("upgraded vault header could not be persisted; vault locked");
                return Err(e);
            }
        }
        Ok(())
    }

    /// [`Vault::unlock`] that also hands back the KEK for callers that must re-wrap.
    pub(crate) fn unlock_with_kek(
        &mut self,
        password: &SecretString,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let salt: [u8; SALT_LEN] =
            self.header.salt.as_slice().try_into().map_err(|_| VaultError::Unlock)?;
        let kek = derive_kek(password.expose_secret().as_bytes(), &salt, self.header.kdf_params)
            .map_err(|_| VaultError::Unlock)?;
        let dek = open_key(&kek, &self.header.aad(), &self.header.wrapped_dek)
            .map_err(|_| VaultError::Unlock)?;
        if self.header.needs_upgrade() {
            let mut header = self.header.clone();
            header.version = FORMAT_VERSION;
            header.vault_id = Uuid::new_v4();
            header.keyring_wrap = None;
            rewrap_password(&mut header, &kek, &dek);
            self.header = header;
            tracing::info!(version = FORMAT_VERSION, "vault header upgraded");
        }
        self.dek = Some(dek);
        tracing::info!("vault unlocked");
        Ok(kek)
    }

    /// Wipe the DEK from memory.
    pub fn lock(&mut self) {
        self.dek = None; // Zeroizing drop wipes the buffer
        tracing::info!("vault locked");
    }

    /// Lock and hand the reason back so the caller can write the `vault.lock` audit entry
    /// (this crate deliberately does not depend on `nexus-audit`).
    pub fn lock_with_reason(&mut self, reason: LockReason) -> LockReason {
        self.dek = None;
        tracing::info!(reason = reason.as_str(), "vault locked");
        reason
    }

    /// Re-wrap the DEK under a new password (new salt, new nonce). Records are untouched.
    ///
    /// The keyring wrap is bound to the old salt and KDF parameters, so it is cleared here:
    /// keyring unlock must be re-enabled afterwards (and the stale keyring item deleted).
    pub fn change_password(
        &mut self,
        current: &SecretString,
        new: &SecretString,
        params: KdfParams,
    ) -> Result<(), VaultError> {
        self.unlock(current)?;
        check_password(new)?;
        params.validate()?;
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        let salt = random::<SALT_LEN>();
        let mut header = self.header.clone();
        header.kdf_params = params;
        header.salt = salt.to_vec();
        if header.keyring_wrap.take().is_some() {
            tracing::info!("keyring unlock disabled by password change");
        }
        let kek = derive_kek(new.expose_secret().as_bytes(), &salt, params)?;
        rewrap_password(&mut header, &kek, dek);
        self.header = header;
        tracing::info!("vault password changed");
        Ok(())
    }

    /// Encrypt one field of one record. The record id and field name are bound as AAD, so a
    /// sealed value cannot be moved to another record or field.
    pub fn seal(
        &self,
        record_id: &str,
        field: &str,
        plaintext: &[u8],
    ) -> Result<Sealed, VaultError> {
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        Ok(seal_with(dek, &field_aad(record_id, field), plaintext))
    }

    /// Decrypt one field. The returned buffer is zeroized on drop.
    pub fn open(
        &self,
        record_id: &str,
        field: &str,
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        open_with(dek, &field_aad(record_id, field), sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    const PW: &str = "correct horse battery";

    #[test]
    fn create_seal_open_round_trip_and_lock() {
        let v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        assert_eq!(v.header().version, 2);
        assert!(!v.vault_id().is_nil());
        let s = v.seal("conn-1", "password", b"hunter2").expect("seal");
        assert_eq!(v.open("conn-1", "password", &s).expect("open").as_slice(), b"hunter2");

        // bound to record and field
        assert_eq!(v.open("conn-2", "password", &s), Err(VaultError::Tampered));
        assert_eq!(v.open("conn-1", "key", &s), Err(VaultError::Tampered));

        // tampering with ciphertext or nonce is detected
        let mut t = s.clone();
        t.ciphertext[0] ^= 1;
        assert_eq!(v.open("conn-1", "password", &t), Err(VaultError::Tampered));
        let mut t = s.clone();
        t.nonce[0] ^= 1;
        assert_eq!(v.open("conn-1", "password", &t), Err(VaultError::Tampered));

        let mut v = v;
        v.lock();
        assert_eq!(v.state(), VaultState::Locked);
        assert_eq!(v.seal("conn-1", "password", b"x"), Err(VaultError::Locked));
    }

    #[test]
    fn lock_with_reason_returns_reason_and_wipes() {
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        assert_eq!(v.lock_with_reason(LockReason::Idle), LockReason::Idle);
        assert_eq!(v.state(), VaultState::Locked);
    }

    #[test]
    fn header_round_trip_unlock_and_wrong_password() {
        let v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let s = v.seal("r", "f", b"secret").expect("seal");
        let bytes = v.header().to_bytes().expect("bytes");

        let mut again = Vault::from_header_bytes(&bytes).expect("parse");
        assert_eq!(again.unlock(&pw("wrong password!!")), Err(VaultError::Unlock));
        again.unlock(&pw(PW)).expect("unlock");
        assert_eq!(again.header(), v.header(), "v2 unlock must not rewrite the header");
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"secret");
    }

    #[test]
    fn header_tampering_breaks_unlock_not_just_parsing() {
        let v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let tamper: [fn(&mut Header); 4] = [
            |h| h.kdf_params.t += 1,
            |h| h.wrapped_dek.ciphertext[3] ^= 0x80,
            |h| h.vault_id = Uuid::new_v4(),
            |h| {
                h.keyring_wrap = Some(Sealed { nonce: vec![0; 24], ciphertext: vec![0; 48] });
            },
        ];
        for (i, f) in tamper.iter().enumerate() {
            let mut h = v.header().clone();
            f(&mut h);
            let mut again = Vault::from_header(h);
            assert_eq!(again.unlock(&pw(PW)), Err(VaultError::Unlock), "tamper {i}");
        }
    }

    #[test]
    fn downgraded_kdf_floor_is_refused_before_deriving() {
        let v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let mut h = v.header().clone();
        h.kdf_params.m_kib = 64;
        let bytes = h.to_bytes().expect("bytes");
        assert!(matches!(Vault::from_header_bytes(&bytes), Err(VaultError::KdfParams(_))));
    }

    /// Build a v1 header exactly as the A0 code did (legacy AAD, no v2 fields).
    fn v1_vault(password: &str) -> (Header, Zeroizing<[u8; KEY_LEN]>) {
        let salt = random::<SALT_LEN>();
        let dek = Zeroizing::new(random::<KEY_LEN>());
        let mut header = Header {
            magic: MAGIC.to_owned(),
            version: 1,
            vault_id: Uuid::nil(),
            kdf: "argon2id".to_owned(),
            kdf_params: KdfParams::TEST,
            salt: salt.to_vec(),
            wrapped_dek: Sealed { nonce: Vec::new(), ciphertext: Vec::new() },
            keyring_wrap: None,
        };
        let kek = derive_kek(password.as_bytes(), &salt, KdfParams::TEST).expect("kdf");
        rewrap_password(&mut header, &kek, &dek);
        (header, dek)
    }

    #[test]
    fn v1_header_unlocks_and_upgrades_to_v2() {
        let (h1, dek) = v1_vault(PW);
        let bytes = h1.to_bytes().expect("bytes");
        assert!(!String::from_utf8_lossy(&bytes).contains("vault_id"), "v1 shape on disk");
        let mut v = Vault::from_header_bytes(&bytes).expect("v1 parses");
        assert!(v.header().needs_upgrade());
        let s = crate::crypto::seal_with(&dek, &field_aad("r", "f"), b"legacy");

        v.unlock(&pw(PW)).expect("unlock v1");
        assert!(!v.header().needs_upgrade());
        assert_eq!(v.header().version, FORMAT_VERSION);
        assert!(!v.vault_id().is_nil());
        assert_eq!(v.open("r", "f", &s).expect("open").as_slice(), b"legacy");

        // the upgraded header round-trips and unlocks on its own
        let mut again = Vault::from_header_bytes(&v.header().to_bytes().expect("b")).expect("p");
        again.unlock(&pw(PW)).expect("unlock v2");
        assert_eq!(again.header(), v.header());
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"legacy");

        // a v1 header relabelled as v2 (version bump only) is rejected
        let mut forged = h1.clone();
        forged.version = 2;
        forged.vault_id = Uuid::new_v4();
        assert_eq!(Vault::from_header(forged).unlock(&pw(PW)), Err(VaultError::Unlock));
    }

    #[test]
    fn unlock_persisting_locks_and_restores_when_persist_fails() {
        let (h1, _) = v1_vault(PW);
        let mut v = Vault::from_header(h1.clone());
        let r: Result<(), VaultError> =
            v.unlock_persisting(&pw(PW), |_| Err(VaultError::Format("disk full".into())));
        assert_eq!(r, Err(VaultError::Format("disk full".into())));
        assert_eq!(v.state(), VaultState::Locked, "must not stay unlocked");
        assert_eq!(v.header(), &h1, "unpersisted upgrade must not stay in memory");

        // retry with a working sink: upgrades, persists exactly that header, stays unlocked
        let mut saved = None;
        v.unlock_persisting(&pw(PW), |h| {
            saved = Some(h.clone());
            Ok::<(), VaultError>(())
        })
        .expect("unlock");
        assert_eq!(v.state(), VaultState::Unlocked);
        assert_eq!(saved.as_ref(), Some(v.header()));
        assert!(!v.header().needs_upgrade());

        // v2 header: persist is not called; wrong password is passed through
        let mut v2 = Vault::from_header(v.header().clone());
        let r = v2.unlock_persisting(&pw("wrong password!!"), |_| -> Result<(), VaultError> {
            panic!("no persist on failed unlock")
        });
        assert_eq!(r, Err(VaultError::Unlock));
        v2.unlock_persisting(&pw(PW), |_| -> Result<(), VaultError> {
            panic!("no persist for a v2 header")
        })
        .expect("unlock v2");
    }

    #[test]
    fn change_password_keeps_records() {
        let mut v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let id = v.vault_id();
        let s = v.seal("r", "f", b"keep me").expect("seal");
        v.change_password(&pw(PW), &pw("new longer password"), KdfParams::TEST).expect("change");
        assert_eq!(v.vault_id(), id);
        let bytes = v.header().to_bytes().expect("bytes");
        let mut again = Vault::from_header_bytes(&bytes).expect("parse");
        assert_eq!(again.unlock(&pw(PW)), Err(VaultError::Unlock));
        again.unlock(&pw("new longer password")).expect("unlock");
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"keep me");
    }

    #[test]
    fn weak_password_and_debug_redaction() {
        assert_eq!(
            Vault::create(&pw("short"), KdfParams::TEST).err(),
            Some(VaultError::WeakPassword { min: MIN_PASSWORD_CHARS })
        );
        let v = Vault::create(&pw(PW), KdfParams::TEST).expect("create");
        let shown = format!("{v:?}");
        assert!(shown.contains("Unlocked"));
        assert!(!shown.contains("dek"));
    }
}
