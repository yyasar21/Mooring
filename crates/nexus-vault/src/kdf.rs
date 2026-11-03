//! Argon2id parameters and derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Length of the derived key encryption key.
pub const KEY_LEN: usize = 32;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters, stored in the vault header.
///
/// Defaults follow the OWASP 2024 "first choice" shape scaled up for a desktop app:
/// 256 MiB memory, 3 passes, 4 lanes. A1 adds calibration against the host machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (passes).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl KdfParams {
    /// Production defaults.
    pub const DEFAULT: Self = Self { m_kib: 256 * 1024, t: 3, p: 4 };

    /// Cheap parameters for unit tests only. Never written by the application.
    pub const TEST: Self = Self { m_kib: 8 * 1024, t: 1, p: 1 };

    /// Lower bounds the vault refuses to go below when *reading* a header, so a downgraded
    /// header cannot make brute force cheap.
    pub const FLOOR: Self = Self { m_kib: 8 * 1024, t: 1, p: 1 };

    /// Check against the floor and Argon2's own limits.
    pub fn validate(self) -> Result<(), VaultError> {
        if self.m_kib < Self::FLOOR.m_kib || self.t < Self::FLOOR.t || self.p < Self::FLOOR.p {
            return Err(VaultError::KdfParams("below the minimum floor".into()));
        }
        Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map(|_| ())
            .map_err(|e| VaultError::KdfParams(e.to_string()))
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Derive the key encryption key from the password.
pub(crate) fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    params.validate()?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| VaultError::KdfParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| VaultError::KdfParams(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_is_enforced() {
        assert!(KdfParams { m_kib: 1024, t: 1, p: 1 }.validate().is_err());
        assert!(KdfParams::TEST.validate().is_ok());
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn same_inputs_same_key_different_salt_different_key() {
        let a = derive_kek(b"pw", &[1; SALT_LEN], KdfParams::TEST).expect("kdf");
        let b = derive_kek(b"pw", &[1; SALT_LEN], KdfParams::TEST).expect("kdf");
        let c = derive_kek(b"pw", &[2; SALT_LEN], KdfParams::TEST).expect("kdf");
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }
}
