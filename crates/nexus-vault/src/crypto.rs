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
pub(crate) fn seal_with(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Sealed {
    seal_with_nonce(key, random::<NONCE_LEN>(), aad, plaintext)
}

/// Encrypt with a caller-chosen nonce. Only for reproducible test vectors and `seal_with`.
pub(crate) fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Sealed {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .unwrap_or_default(); // only fails on absurd lengths (> 2^64); empty fails to open
    Sealed { nonce: nonce.to_vec(), ciphertext }
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
