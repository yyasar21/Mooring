//! XChaCha20-Poly1305 helpers shared by the vault, keyring wrap and test vectors.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::format::{Sealed, NONCE_LEN};
use crate::kdf::KEY_LEN;

/// Fill an array from the OS CSPRNG.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Encrypt under `key` with a fresh random nonce.
pub(crate) fn seal_with(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, VaultError> {
    seal_with_nonce(key, random::<NONCE_LEN>(), aad, plaintext)
}

/// Encrypt with a caller-chosen nonce. Only for reproducible test vectors and `seal_with`.
///
/// The AEAD only fails for inputs beyond its length limit (about 256 GiB); that is reported as
/// [`VaultError::Seal`] instead of silently producing an empty ciphertext (review N1).
pub(crate) fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Seal)?;
    Ok(Sealed { nonce: nonce.to_vec(), ciphertext })
}

/// Decrypt and authenticate. The plaintext is zeroized on drop.
pub(crate) fn open_with(
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

/// Open a sealed 32-byte key (DEK) and return it as a fixed array.
pub(crate) fn open_key(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    sealed: &Sealed,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let bytes = open_with(key, aad, sealed)?;
    let arr: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| VaultError::Tampered)?;
    Ok(Zeroizing::new(arr))
}

/// AAD of a sealed field: `record_id ‖ 0x1F ‖ field`.
pub(crate) fn field_aad(record_id: &str, field: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(record_id.len() + field.len() + 1);
    v.extend_from_slice(record_id.as_bytes());
    v.push(0x1f);
    v.extend_from_slice(field.as_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review N1: sealing returns a real ciphertext (tag included) or an error, never the
    /// silent empty ciphertext the old `unwrap_or_default` produced. The failure branch needs
    /// more than 256 GiB of input and is not exercised; its error has a fixed message.
    #[test]
    fn seal_returns_ciphertext_or_error() {
        let key = [3u8; KEY_LEN];
        for len in [0usize, 1, 4096] {
            let s = seal_with(&key, b"aad", &vec![7u8; len]).expect("seal");
            assert_eq!(s.ciphertext.len(), len + 16, "ciphertext + Poly1305 tag");
            assert_eq!(open_with(&key, b"aad", &s).expect("open").len(), len);
        }
        assert_eq!(VaultError::Seal.to_string(), "could not encrypt data");
    }
}
