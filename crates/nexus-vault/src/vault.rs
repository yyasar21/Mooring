//! The vault: create, unlock, seal/open fields, change password, lock.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::format::{Header, Sealed, FORMAT_VERSION, MAGIC, NONCE_LEN};
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
    header: Header,
    dek: Option<Zeroizing<[u8; KEY_LEN]>>,
}

// Hand-written so the DEK can never be printed.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("version", &self.header.version)
            .field("kdf_params", &self.header.kdf_params)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn seal_with(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Sealed {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = random::<NONCE_LEN>();
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .unwrap_or_default(); // only fails on absurd lengths (> 2^64); treated as empty, which fails to open
    Sealed { nonce: nonce.to_vec(), ciphertext }
}

fn open_with(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if sealed.nonce.len() != NONCE_LEN {
        return Err(VaultError::Tampered);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Tampered)
}

fn field_aad(record_id: &str, field: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(record_id.len() + field.len() + 1);
    v.extend_from_slice(record_id.as_bytes());
    v.push(0x1f);
    v.extend_from_slice(field.as_bytes());
    v
}

fn check_password(password: &SecretString) -> Result<(), VaultError> {
    if password.expose_secret().chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword { min: MIN_PASSWORD_CHARS });
    }
    Ok(())
}

impl Vault {
    /// Create a new vault with a fresh DEK. Returns it unlocked.
    pub fn create(password: &SecretString, params: KdfParams) -> Result<Self, VaultError> {
        check_password(password)?;
        params.validate()?;
        let salt = random::<SALT_LEN>();
        let dek = Zeroizing::new(random::<KEY_LEN>());
        let mut header = Header {
            magic: MAGIC.to_owned(),
            version: FORMAT_VERSION,
            kdf: "argon2id".to_owned(),
            kdf_params: params,
            salt: salt.to_vec(),
            wrapped_dek: Sealed { nonce: Vec::new(), ciphertext: Vec::new() },
        };
        let kek = derive_kek(password.expose_secret().as_bytes(), &salt, params)?;
        header.wrapped_dek = seal_with(&kek, &header.aad(), dek.as_ref());
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
    pub fn unlock(&mut self, password: &SecretString) -> Result<(), VaultError> {
        let salt: [u8; SALT_LEN] =
            self.header.salt.as_slice().try_into().map_err(|_| VaultError::Unlock)?;
        let kek = derive_kek(password.expose_secret().as_bytes(), &salt, self.header.kdf_params)
            .map_err(|_| VaultError::Unlock)?;
        let dek_bytes = open_with(&kek, &self.header.aad(), &self.header.wrapped_dek)
            .map_err(|_| VaultError::Unlock)?;
        let dek: [u8; KEY_LEN] = dek_bytes.as_slice().try_into().map_err(|_| VaultError::Unlock)?;
        self.dek = Some(Zeroizing::new(dek));
        tracing::info!("vault unlocked");
        Ok(())
    }

    /// Wipe the DEK from memory.
    pub fn lock(&mut self) {
        self.dek = None; // Zeroizing drop wipes the buffer
        tracing::info!("vault locked");
    }

    /// Re-wrap the DEK under a new password (new salt, new nonce). Records are untouched.
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
        let kek = derive_kek(new.expose_secret().as_bytes(), &salt, params)?;
        header.wrapped_dek = seal_with(&kek, &header.aad(), dek.as_ref());
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

    #[test]
    fn create_seal_open_round_trip_and_lock() {
        let v = Vault::create(&pw("correct horse battery"), KdfParams::TEST).expect("create");
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
    fn header_round_trip_unlock_and_wrong_password() {
        let v = Vault::create(&pw("correct horse battery"), KdfParams::TEST).expect("create");
        let s = v.seal("r", "f", b"secret").expect("seal");
        let bytes = v.header().to_bytes().expect("bytes");

        let mut again = Vault::from_header_bytes(&bytes).expect("parse");
        assert_eq!(again.unlock(&pw("wrong password!!")), Err(VaultError::Unlock));
        again.unlock(&pw("correct horse battery")).expect("unlock");
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"secret");
    }

    #[test]
    fn header_tampering_breaks_unlock_not_just_parsing() {
        let v = Vault::create(&pw("correct horse battery"), KdfParams::TEST).expect("create");
        let mut h = v.header().clone();
        h.kdf_params.t += 1; // attacker edits a cost parameter
        let mut again = Vault::from_header(h);
        assert_eq!(again.unlock(&pw("correct horse battery")), Err(VaultError::Unlock));

        let mut h = v.header().clone();
        h.wrapped_dek.ciphertext[3] ^= 0x80;
        let mut again = Vault::from_header(h);
        assert_eq!(again.unlock(&pw("correct horse battery")), Err(VaultError::Unlock));
    }

    #[test]
    fn downgraded_kdf_floor_is_refused_before_deriving() {
        let v = Vault::create(&pw("correct horse battery"), KdfParams::TEST).expect("create");
        let mut h = v.header().clone();
        h.kdf_params.m_kib = 64;
        let bytes = h.to_bytes().expect("bytes");
        assert!(matches!(Vault::from_header_bytes(&bytes), Err(VaultError::KdfParams(_))));
    }

    #[test]
    fn change_password_keeps_records() {
        let mut v = Vault::create(&pw("correct horse battery"), KdfParams::TEST).expect("create");
        let s = v.seal("r", "f", b"keep me").expect("seal");
        v.change_password(
            &pw("correct horse battery"),
            &pw("new longer password"),
            KdfParams::TEST,
        )
        .expect("change");
        let bytes = v.header().to_bytes().expect("bytes");
        let mut again = Vault::from_header_bytes(&bytes).expect("parse");
        assert_eq!(again.unlock(&pw("correct horse battery")), Err(VaultError::Unlock));
        again.unlock(&pw("new longer password")).expect("unlock");
        assert_eq!(again.open("r", "f", &s).expect("open").as_slice(), b"keep me");
    }

    #[test]
    fn weak_password_and_debug_redaction() {
        assert_eq!(
            Vault::create(&pw("short"), KdfParams::TEST).err(),
            Some(VaultError::WeakPassword { min: MIN_PASSWORD_CHARS })
        );
        let v = Vault::create(&pw("correct horse battery"), KdfParams::TEST).expect("create");
        let shown = format!("{v:?}");
        assert!(shown.contains("Unlocked"));
        assert!(!shown.contains("dek"));
    }
}
