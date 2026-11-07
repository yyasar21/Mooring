//! Mooring vault (ADR-0002).
//!
//! ```text
//! master password ──Argon2id(salt, m, t, p)──► KEK (32 B, zeroized)
//! KEK ──XChaCha20-Poly1305──► wraps DEK (32 B, random, zeroized)
//! DEK ──XChaCha20-Poly1305, AAD = record id ‖ 0x1F ‖ field ──► every secret field
//! DEK ──HKDF-SHA256(salt, info)──► SubKey (sync blobs, ADR-0017)
//! ```
//!
//! * Changing the password re-wraps the DEK; records are untouched.
//! * Every sealed field carries its own 24-byte random nonce.
//! * The header is JSON, versioned, and authenticated: it is the AAD of the DEK wrap, so a
//!   tampered KDF parameter or salt makes unlocking fail instead of silently weakening it.
//! * Keys live in [`zeroize::Zeroizing`] buffers and are wiped on lock/drop. Nothing in this
//!   crate implements `Debug` or `Display` for secret material.
//!
//! Storage (which file, which database column) is the caller's business; this crate only
//! turns bytes into sealed bytes and back.

#![forbid(unsafe_code)]

pub mod autolock;
mod crypto;
mod error;
mod export;
mod format;
mod kdf;
mod keyring;
mod subkey;
mod vault;
#[cfg(test)]
mod vectors;

pub use autolock::{AutoLockClock, AutoLockPolicy, LockEvent, LockReason};
pub use error::VaultError;
pub use export::{
    export_age, export_age_bytes, export_age_bytes_with_work_factor, import_age, import_age_bytes,
    ExportDocument, ExportedRecord, EXPORT_SCRYPT_LOG_N, MAX_EXPORT_BYTES, MAX_IMPORT_SCRYPT_LOG_N,
    MIN_EXPORT_PASSPHRASE_CHARS,
};
pub use format::{Header, Sealed, FORMAT_VERSION, MAGIC, MAX_HEADER_BYTES, MIN_FORMAT_VERSION};
pub use kdf::{
    calibrate_with, HostLimits, KdfParams, CALIBRATION_CANDIDATES_MIB, CALIBRATION_T,
    CALIBRATION_TARGET,
};
pub use keyring::{MemoryWrapKeyStore, WrapKeyStore};
pub use subkey::SubKey;
pub use uuid::Uuid;
pub use vault::{Vault, VaultState};
