//! Nexus Remote vault (ADR-0002).
//!
//! ```text
//! master password ──Argon2id(salt, m, t, p)──► KEK (32 B, zeroized)
//! KEK ──XChaCha20-Poly1305──► wraps DEK (32 B, random, zeroized)
//! DEK ──XChaCha20-Poly1305, AAD = record id ‖ 0x1F ‖ field ──► every secret field
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
mod format;
mod kdf;
mod keyring;
mod vault;

pub use autolock::{AutoLockClock, AutoLockPolicy, LockEvent, LockReason};
pub use error::VaultError;
pub use format::{Header, Sealed, FORMAT_VERSION, MAGIC, MAX_HEADER_BYTES, MIN_FORMAT_VERSION};
pub use kdf::{
    calibrate_with, HostLimits, KdfParams, CALIBRATION_CANDIDATES_MIB, CALIBRATION_T,
    CALIBRATION_TARGET,
};
pub use keyring::{MemoryWrapKeyStore, WrapKeyStore};
pub use uuid::Uuid;
pub use vault::{Vault, VaultState};
