//! Process-wide state: the vault (header persisted, DEK in memory only) and the audit log.

use std::path::PathBuf;
use std::sync::Mutex;

use nexus_audit::{AuditError, AuditLog};
use nexus_vault::{Vault, VaultError};

/// Shared application state managed by Tauri.
#[derive(Debug)]
pub struct AppState {
    /// Where the vault header and audit log live (`$APP_DATA/nexus`).
    pub data_dir: PathBuf,
    /// `None` until a vault is created or its header loaded.
    pub vault: Mutex<Option<Vault>>,
    /// Hash-chained audit log.
    pub audit: Mutex<AuditLog>,
}

/// Errors while loading state at startup.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Audit log could not be opened.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// Vault header on disk is unreadable.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl AppState {
    /// File holding the plaintext, authenticated vault header.
    const HEADER_FILE: &'static str = "vault.header.json";
    /// Audit log file.
    const AUDIT_FILE: &'static str = "audit.jsonl";

    /// Load the header if one exists; the vault starts locked.
    pub fn new(data_dir: PathBuf) -> Result<Self, StateError> {
        let header_path = data_dir.join(Self::HEADER_FILE);
        let vault = match std::fs::read(&header_path) {
            Ok(bytes) => Some(Vault::from_header_bytes(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let audit = AuditLog::open(data_dir.join(Self::AUDIT_FILE))?;
        Ok(Self { data_dir, vault: Mutex::new(vault), audit: Mutex::new(audit) })
    }

    /// Persist the current vault header (contains no secret material).
    pub fn save_header(&self, vault: &Vault) -> Result<(), StateError> {
        let bytes = vault.header().to_bytes()?;
        let path = self.data_dir.join(Self::HEADER_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}
