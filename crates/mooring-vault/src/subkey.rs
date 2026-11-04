//! Purpose-bound keys derived from the DEK (ADR-0017 §2: the sync key).
//!
//! `SubKey = HKDF-SHA256(ikm = DEK, salt, info)` (RFC 5869). The DEK never leaves the vault;
//! callers get an opaque [`SubKey`] that can only seal and open with XChaCha20-Poly1305, is
//! zeroized on drop and prints nothing in `Debug`. Different `info` or `salt` values give
//! independent keys (domain separation), so a sync blob can never be opened as a vault field
//! and vice versa.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{open_with, seal_with, seal_with_nonce};
use crate::error::VaultError;
use crate::format::{Sealed, NONCE_LEN};
use crate::kdf::KEY_LEN;
use crate::vault::Vault;

/// A 32-byte key derived from the DEK for one purpose.
pub struct SubKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubKey(..)")
    }
}

impl SubKey {
    /// Seal with a fresh random 24-byte nonce.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, VaultError> {
        seal_with(&self.0, aad, plaintext)
    }

    /// Seal with a caller-chosen nonce: only for reproducible test vectors. Reusing a nonce
    /// under one key breaks confidentiality.
    pub fn seal_with_nonce(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, VaultError> {
        seal_with_nonce(&self.0, nonce, aad, plaintext)
    }

    /// Authenticate and decrypt. Any mismatch is [`VaultError::Tampered`].
    pub fn open(&self, aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        open_with(&self.0, aad, sealed)
    }
}

impl Vault {
    /// Derive a purpose-bound key from the DEK. Fails with [`VaultError::Locked`] while
    /// locked and refuses an empty `info` (every purpose must name itself).
    pub fn derive_subkey(&self, salt: &[u8], info: &[u8]) -> Result<SubKey, VaultError> {
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        if info.is_empty() {
            return Err(VaultError::Seal);
        }
        let hk = Hkdf::<Sha256>::new(Some(salt), dek.as_slice());
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(info, out.as_mut_slice()).map_err(|_| VaultError::Seal)?;
        Ok(SubKey(out))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use crate::{KdfParams, Vault, VaultError};

    fn vault() -> Vault {
        Vault::create(&SecretString::from("test-only master pw".to_owned()), KdfParams::TEST)
            .expect("vault")
    }

    #[test]
    fn domain_separated_and_deterministic() {
        let v = vault();
        let a = v.derive_subkey(b"salt-a", b"mooring sync v1").expect("a");
        let again = v.derive_subkey(b"salt-a", b"mooring sync v1").expect("a again");
        let other_info = v.derive_subkey(b"salt-a", b"mooring sync v2").expect("info");
        let other_salt = v.derive_subkey(b"salt-b", b"mooring sync v1").expect("salt");
        let s = a.seal(b"aad", b"payload").expect("seal");
        assert_eq!(again.open(b"aad", &s).expect("open").as_slice(), b"payload");
        assert_eq!(other_info.open(b"aad", &s), Err(VaultError::Tampered));
        assert_eq!(other_salt.open(b"aad", &s), Err(VaultError::Tampered));
        assert_eq!(a.open(b"other aad", &s), Err(VaultError::Tampered));
        // The subkey is not the DEK: a field sealed by the vault does not open with it.
        let field = v.seal("r", "f", b"x").expect("field");
        assert_eq!(a.open(&crate::crypto::field_aad("r", "f"), &field), Err(VaultError::Tampered));
        assert_eq!(format!("{a:?}"), "SubKey(..)");
    }

    #[test]
    fn locked_and_empty_info_are_refused() {
        let mut v = vault();
        assert!(v.derive_subkey(b"s", b"").is_err());
        v.lock();
        assert_eq!(v.derive_subkey(b"s", b"i").map(|_| ()), Err(VaultError::Locked));
    }
}
