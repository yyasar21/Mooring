//! On-disk shapes: the vault header and a sealed field.
//!
//! Header versions:
//! * v1 (A0): `magic`, `version`, `kdf`, `kdf_params`, `salt`, `wrapped_dek`.
//! * v2 (A1, ADR-0006): adds `vault_id` and the optional `keyring_wrap`; both are bound into
//!   [`Header::aad`]. v1 headers still parse (the new fields default) and report
//!   [`Header::needs_upgrade`]; the vault upgrades them on the next password unlock.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::VaultError;
use crate::kdf::{KdfParams, SALT_LEN};

/// Magic string at the start of every header.
pub const MAGIC: &str = "MOORINGVAULT";
/// Current header format version.
pub const FORMAT_VERSION: u16 = 2;
/// Oldest header version that can still be read.
pub const MIN_FORMAT_VERSION: u16 = 1;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Largest header accepted by [`Header::from_bytes`].
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

const SEP: u8 = 0x1f;

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
    /// Stable vault identity (v2). Nil on a v1 header until it is upgraded.
    #[serde(default, skip_serializing_if = "Uuid::is_nil")]
    pub vault_id: Uuid,
    /// KDF algorithm name; only `argon2id` exists today.
    pub kdf: String,
    /// KDF cost parameters.
    pub kdf_params: KdfParams,
    /// Salt for the KDF.
    #[serde(with = "hex::serde")]
    pub salt: Vec<u8>,
    /// DEK wrapped under the KEK. AAD = [`Header::aad`].
    pub wrapped_dek: Sealed,
    /// Optional second wrap of the DEK under an OS-keyring `WrapKey` (v2, ADR-0006).
    /// AAD = [`Header::aad`] of the header without this field ‖ 0x1F ‖ `b"keyring"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_wrap: Option<Sealed>,
}

impl Header {
    /// Bytes bound into the password wrap of the DEK: everything except `wrapped_dek`.
    /// Changing any KDF parameter, the salt, the vault id or the keyring wrap breaks unlocking.
    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut v = self.base_aad();
        if self.version >= 2 {
            v.push(SEP);
            match &self.keyring_wrap {
                None => v.push(0),
                Some(k) => {
                    v.push(1);
                    v.extend_from_slice(&k.nonce);
                    v.extend_from_slice(&k.ciphertext);
                }
            }
        }
        v
    }

    /// v1 fields; v2 appends the vault id. Kept byte-identical to A0 for version 1.
    fn base_aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128);
        v.extend_from_slice(self.magic.as_bytes());
        v.push(SEP);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.push(SEP);
        v.extend_from_slice(self.kdf.as_bytes());
        v.push(SEP);
        v.extend_from_slice(&self.kdf_params.m_kib.to_le_bytes());
        v.extend_from_slice(&self.kdf_params.t.to_le_bytes());
        v.extend_from_slice(&self.kdf_params.p.to_le_bytes());
        v.push(SEP);
        v.extend_from_slice(&self.salt);
        if self.version >= 2 {
            v.push(SEP);
            v.extend_from_slice(self.vault_id.as_bytes());
        }
        v
    }

    /// True for a header older than [`FORMAT_VERSION`]; it is rewritten on the next unlock.
    #[must_use]
    pub fn needs_upgrade(&self) -> bool {
        self.version < FORMAT_VERSION
    }

    /// Whether biometric / OS-keyring unlock is enabled for this vault.
    #[must_use]
    pub fn keyring_enabled(&self) -> bool {
        self.keyring_wrap.is_some()
    }

    /// Serialise to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|e| VaultError::Format(e.to_string()))
    }

    /// Parse and sanity-check a header. KDF floor is enforced here, before any key is derived.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(VaultError::Format("header too large".into()));
        }
        let h: Self =
            serde_json::from_slice(bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        h.check()?;
        Ok(h)
    }

    /// Structural checks shared by [`Header::from_bytes`] and export import.
    pub(crate) fn check(&self) -> Result<(), VaultError> {
        if self.magic != MAGIC {
            return Err(VaultError::Format("bad magic".into()));
        }
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&self.version) {
            return Err(VaultError::Format(format!("unsupported version {}", self.version)));
        }
        if self.kdf != "argon2id" {
            return Err(VaultError::Format(format!("unsupported kdf {}", self.kdf)));
        }
        if self.salt.len() != SALT_LEN {
            return Err(VaultError::Format("bad salt length".into()));
        }
        if self.wrapped_dek.nonce.len() != NONCE_LEN {
            return Err(VaultError::Format("bad nonce length".into()));
        }
        if self.version == 1 && (!self.vault_id.is_nil() || self.keyring_wrap.is_some()) {
            return Err(VaultError::Format("v2 fields in a v1 header".into()));
        }
        if self.version >= 2 && self.vault_id.is_nil() {
            return Err(VaultError::Format("missing vault id".into()));
        }
        if self.keyring_wrap.as_ref().is_some_and(|k| k.nonce.len() != NONCE_LEN) {
            return Err(VaultError::Format("bad keyring nonce length".into()));
        }
        self.kdf_params.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(b: u8) -> Sealed {
        Sealed { nonce: vec![b; NONCE_LEN], ciphertext: vec![b; 48] }
    }

    fn v2() -> Header {
        Header {
            magic: MAGIC.into(),
            version: 2,
            vault_id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            kdf: "argon2id".into(),
            kdf_params: KdfParams::TEST,
            salt: vec![7; SALT_LEN],
            wrapped_dek: sealed(1),
            keyring_wrap: None,
        }
    }

    #[test]
    fn v2_round_trips_and_binds_new_fields() {
        let h = v2();
        let back = Header::from_bytes(&h.to_bytes().expect("bytes")).expect("parse");
        assert_eq!(back, h);
        assert!(!back.needs_upgrade());

        let mut other_id = h.clone();
        other_id.vault_id = Uuid::from_u128(1);
        assert_ne!(other_id.aad(), h.aad());

        let mut with_wrap = h.clone();
        with_wrap.keyring_wrap = Some(sealed(2));
        assert_ne!(with_wrap.aad(), h.aad());
        let mut other_wrap = with_wrap.clone();
        other_wrap.keyring_wrap = Some(sealed(3));
        assert_ne!(other_wrap.aad(), with_wrap.aad());
    }

    #[test]
    fn v1_header_parses_and_needs_upgrade_with_legacy_aad() {
        let json = format!(
            r#"{{"magic":"MOORINGVAULT","version":1,"kdf":"argon2id",
                "kdf_params":{{"m_kib":8192,"t":1,"p":1}},"salt":"{}",
                "wrapped_dek":{{"nonce":"{}","ciphertext":"{}"}}}}"#,
            "07".repeat(SALT_LEN),
            "01".repeat(NONCE_LEN),
            "01".repeat(48)
        );
        let h = Header::from_bytes(json.as_bytes()).expect("v1 parses");
        assert_eq!(h.version, 1);
        assert!(h.vault_id.is_nil());
        assert!(h.needs_upgrade());
        // A0 AAD layout: magic,ver,kdf,params,salt with 0x1F separators and nothing after.
        let mut legacy = b"MOORINGVAULT\x1f\x01\x00\x1fargon2id\x1f".to_vec();
        legacy.extend_from_slice(&8192u32.to_le_bytes());
        legacy.extend_from_slice(&1u32.to_le_bytes());
        legacy.extend_from_slice(&1u32.to_le_bytes());
        legacy.push(0x1f);
        legacy.extend_from_slice(&[7; SALT_LEN]);
        assert_eq!(h.aad(), legacy);
    }

    #[test]
    fn structural_checks() {
        let bad = |f: fn(&mut Header)| {
            let mut h = v2();
            f(&mut h);
            Header::from_bytes(&h.to_bytes().expect("bytes")).err()
        };
        assert!(matches!(bad(|h| h.magic = "X".into()), Some(VaultError::Format(_))));
        assert!(matches!(bad(|h| h.version = 3), Some(VaultError::Format(_))));
        assert!(matches!(bad(|h| h.version = 0), Some(VaultError::Format(_))));
        assert!(matches!(bad(|h| h.vault_id = Uuid::nil()), Some(VaultError::Format(_))));
        assert!(matches!(bad(|h| h.version = 1), Some(VaultError::Format(_))));
        assert!(matches!(bad(|h| h.salt.pop().map_or((), drop)), Some(VaultError::Format(_))));
        assert!(matches!(
            bad(|h| h.keyring_wrap = Some(Sealed { nonce: vec![0; 3], ciphertext: vec![] })),
            Some(VaultError::Format(_))
        ));
        assert!(matches!(bad(|h| h.kdf_params.m_kib = 64), Some(VaultError::KdfParams(_))));
        assert!(matches!(bad(|h| h.kdf_params.m_kib = u32::MAX), Some(VaultError::KdfParams(_))));
        assert!(matches!(bad(|h| h.kdf_params.t = 17), Some(VaultError::KdfParams(_))));
        assert!(matches!(bad(|h| h.kdf_params.p = 17), Some(VaultError::KdfParams(_))));
        assert!(bad(|_| ()).is_none());
        let huge = vec![b' '; MAX_HEADER_BYTES + 1];
        assert!(matches!(Header::from_bytes(&huge), Err(VaultError::Format(_))));
    }
}
