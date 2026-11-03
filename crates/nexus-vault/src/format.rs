//! On-disk shapes: the vault header and a sealed field.

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::kdf::{KdfParams, SALT_LEN};

/// Magic string at the start of every header.
pub const MAGIC: &str = "NEXUSVAULT";
/// Current header format version.
pub const FORMAT_VERSION: u16 = 1;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;

/// Ciphertext + nonce of one field. Serialised as hex in JSON for easy inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// 24-byte random nonce.
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    /// Ciphertext followed by the 16-byte Poly1305 tag.
    #[serde(with = "hex::serde")]
    pub ciphertext: Vec<u8>,
}

/// Plaintext, authenticated vault header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Always [`MAGIC`].
    pub magic: String,
    /// Format version.
    pub version: u16,
    /// KDF algorithm name; only `argon2id` exists today.
    pub kdf: String,
    /// KDF cost parameters.
    pub kdf_params: KdfParams,
    /// Salt for the KDF.
    #[serde(with = "hex::serde")]
    pub salt: Vec<u8>,
    /// DEK wrapped under the KEK. AAD = [`Header::aad`].
    pub wrapped_dek: Sealed,
}

impl Header {
    /// Bytes bound into the DEK wrap: everything except the wrap itself.
    /// Changing any KDF parameter or the salt after the fact breaks unlocking.
    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(self.magic.as_bytes());
        v.push(0x1f);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.push(0x1f);
        v.extend_from_slice(self.kdf.as_bytes());
        v.push(0x1f);
        v.extend_from_slice(&self.kdf_params.m_kib.to_le_bytes());
        v.extend_from_slice(&self.kdf_params.t.to_le_bytes());
        v.extend_from_slice(&self.kdf_params.p.to_le_bytes());
        v.push(0x1f);
        v.extend_from_slice(&self.salt);
        v
    }

    /// Serialise to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|e| VaultError::Format(e.to_string()))
    }

    /// Parse and sanity-check a header. KDF floor is enforced here, before any key is derived.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > 64 * 1024 {
            return Err(VaultError::Format("header too large".into()));
        }
        let h: Self =
            serde_json::from_slice(bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        if h.magic != MAGIC {
            return Err(VaultError::Format("bad magic".into()));
        }
        if h.version != FORMAT_VERSION {
            return Err(VaultError::Format(format!("unsupported version {}", h.version)));
        }
        if h.kdf != "argon2id" {
            return Err(VaultError::Format(format!("unsupported kdf {}", h.kdf)));
        }
        if h.salt.len() != SALT_LEN {
            return Err(VaultError::Format("bad salt length".into()));
        }
        if h.wrapped_dek.nonce.len() != NONCE_LEN {
            return Err(VaultError::Format("bad nonce length".into()));
        }
        h.kdf_params.validate()?;
        Ok(h)
    }
}
