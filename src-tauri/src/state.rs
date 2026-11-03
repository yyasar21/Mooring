//! Process-wide state: the vault (header persisted, DEK in memory only), the audit log, the
//! connection store and the live sessions.
//!
//! Lock order, everywhere: `vault` → `store` → `audit`. `sessions` is never held together with
//! another lock, and no `std` mutex guard is held across an `.await`.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mooring_audit::{AuditError, AuditEvent, AuditLog};
use mooring_store::{Store, StoreError};
use mooring_vault::{Header, KdfParams, Uuid, Vault, VaultError, VaultState};

use crate::clipboard::{self, Clipboard, SystemClipboard, ValueDigest};
use crate::error::{IpcError, IpcResult};
use crate::sessions::SessionHandle;

/// How the vault's KDF cost is chosen at creation and password change (ADR-0006).
#[derive(Debug, Clone, Copy)]
pub enum KdfChoice {
    /// Measure Argon2id on this host (production).
    Calibrate,
    /// Fixed parameters (tests).
    #[cfg(test)]
    Fixed(KdfParams),
}

impl KdfChoice {
    /// Largest memory cost calibration may pick: the top candidate, 1 GiB.
    const MAX_M_KIB: u32 = 1024 * 1024;

    /// Parameters for a new wrap of the DEK.
    pub fn params(self) -> KdfParams {
        match self {
            Self::Calibrate => {
                KdfParams::calibrate(mooring_vault::CALIBRATION_TARGET, Self::MAX_M_KIB)
            }
            #[cfg(test)]
            Self::Fixed(p) => p,
        }
    }
}

/// Knobs that differ between the app and the tests.
#[derive(Clone)]
pub struct Settings {
    /// KDF cost policy.
    pub kdf: KdfChoice,
    /// Try the ssh-agent during SSH auth (ADR-0007 default: true).
    pub ssh_allow_agent: bool,
    /// Clipboard used by `credential_copy_password`.
    pub clipboard: Arc<dyn Clipboard>,
    /// How long a copied password stays on the clipboard.
    pub clipboard_clear_after: Duration,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("kdf", &self.kdf)
            .field("ssh_allow_agent", &self.ssh_allow_agent)
            .field("clipboard_clear_after", &self.clipboard_clear_after)
            .finish_non_exhaustive()
    }
}

impl Settings {
    /// Production settings: calibrated KDF, agent on, system clipboard, 30 s clear.
    pub fn production() -> Self {
        Self {
            kdf: KdfChoice::Calibrate,
            ssh_allow_agent: true,
            clipboard: Arc::new(SystemClipboard::default()),
            clipboard_clear_after: Duration::from_secs(30),
        }
    }
}

/// The store plus the vault id it has been bound to in this process.
#[derive(Debug, Default)]
pub struct StoreSlot {
    /// `None` after [`AppState::shutdown`].
    pub store: Option<Store>,
    bound_to: Option<Uuid>,
}

/// Live sessions by id.
pub type SessionRegistry = Arc<Mutex<HashMap<String, SessionHandle>>>;

/// Shared application state managed by Tauri.
#[derive(Debug)]
pub struct AppState {
    /// `$APP_DATA`: vault header, audit log, `mooring.db`, `known_hosts`.
    pub data_dir: PathBuf,
    /// `None` until a vault is created or its header loaded.
    pub vault: Mutex<Option<Vault>>,
    /// Connection tree and sealed credentials (ADR-0005).
    pub store: Mutex<StoreSlot>,
    /// Hash-chained audit log; shared with session tasks.
    pub audit: Arc<Mutex<AuditLog>>,
    /// Live sessions; shared with session tasks (they remove themselves).
    pub sessions: SessionRegistry,
    /// Test/production knobs.
    pub settings: Settings,
    /// Digest of the password `credential_copy_password` last put on the clipboard and has not
    /// cleared yet. Taken by the 30 s timer, by [`AppState::shutdown`] and by `vault_lock`, so
    /// the clear also happens when the process exits before the timer fires (review 2, M-1).
    pub pending_clipboard: Arc<Mutex<Option<ValueDigest>>>,
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
    /// Store could not be opened.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Name of the root folder created on first start.
pub const ROOT_FOLDER_NAME: &str = "All connections";

impl AppState {
    /// File holding the plaintext, authenticated vault header.
    pub const HEADER_FILE: &'static str = "vault.header.json";
    /// Previous header, kept until the next successful unlock (review L2).
    pub const HEADER_BACKUP: &'static str = "vault.header.json.bak";
    /// Audit log file.
    pub const AUDIT_FILE: &'static str = "audit.jsonl";
    /// Store database.
    pub const DB_FILE: &'static str = "mooring.db";
    /// SSH trust store (ADR-0007).
    pub const KNOWN_HOSTS_FILE: &'static str = "known_hosts";

    /// Load the header if one exists (the vault starts locked), open the audit log and the
    /// store, and create the root folder on first start.
    pub fn new(data_dir: PathBuf, settings: Settings) -> Result<Self, StateError> {
        let header_path = data_dir.join(Self::HEADER_FILE);
        let vault = match std::fs::read(&header_path) {
            Ok(bytes) => Some(Vault::from_header_bytes(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let audit = AuditLog::open(data_dir.join(Self::AUDIT_FILE))?;
        let store = Store::open(data_dir.join(Self::DB_FILE))?;
        if store.root_folder()?.is_none() {
            store.create_folder(None, ROOT_FOLDER_NAME)?;
        }
        Ok(Self {
            data_dir,
            vault: Mutex::new(vault),
            store: Mutex::new(StoreSlot { store: Some(store), bound_to: None }),
            audit: Arc::new(Mutex::new(audit)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            settings,
            pending_clipboard: Arc::new(Mutex::new(None)),
        })
    }

    /// `$APP_DATA/known_hosts`.
    pub fn known_hosts_path(&self) -> PathBuf {
        self.data_dir.join(Self::KNOWN_HOSTS_FILE)
    }

    /// Lock the vault mutex.
    pub fn vault(&self) -> IpcResult<MutexGuard<'_, Option<Vault>>> {
        self.vault.lock().map_err(|_| IpcError::poisoned())
    }

    /// Run `f` with an unlocked vault and the store bound to that vault. Binding happens on
    /// first use after unlock: a v1 header reports a nil id until its first password unlock
    /// upgrades it, so binding earlier would pin the store to nil (A1-QA-2).
    pub fn with_ready<T>(&self, f: impl FnOnce(&Vault, &Store) -> IpcResult<T>) -> IpcResult<T> {
        let vault = self.vault()?;
        let vault = vault.as_ref().ok_or_else(|| IpcError::new("vault.missing", "no vault yet"))?;
        if vault.state() != VaultState::Unlocked {
            return Err(IpcError::locked());
        }
        let mut slot = self.store.lock().map_err(|_| IpcError::poisoned())?;
        let id = vault.vault_id();
        let slot = &mut *slot;
        let store = slot.store.as_ref().ok_or_else(closed_store)?;
        if slot.bound_to != Some(id) {
            store.set_vault_id(&id.to_string())?;
            slot.bound_to = Some(id);
        }
        f(vault, store)
    }

    /// Persist the current vault header (contains no secret material).
    pub fn save_header(&self, vault: &Vault) -> Result<(), StateError> {
        self.save_header_bytes(vault.header())
    }

    /// Durable header write (review L2): the previous header is copied to
    /// [`Self::HEADER_BACKUP`], the new one goes to a temp file (0600) that is `sync_all`ed and
    /// renamed over the header, then the directory is synced. A crash leaves either the old or
    /// the new header, never a torn one.
    pub fn save_header_bytes(&self, header: &Header) -> Result<(), StateError> {
        let bytes = header.to_bytes()?;
        let path = self.data_dir.join(Self::HEADER_FILE);
        if path.exists() {
            std::fs::copy(&path, self.data_dir.join(Self::HEADER_BACKUP))?;
        }
        let tmp = self.data_dir.join(format!("{}.tmp", Self::HEADER_FILE));
        let mut f = create_private(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)?;
        sync_dir(&self.data_dir);
        Ok(())
    }

    /// Drop the header backup once the current header has proven it unlocks. A stale backup
    /// would keep an old-password header around after a password change (review ruling c).
    pub fn drop_header_backup(&self) {
        let bak = self.data_dir.join(Self::HEADER_BACKUP);
        match std::fs::remove_file(&bak) {
            Ok(()) => tracing::debug!("vault header backup removed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(kind = ?e.kind(), "could not remove vault header backup"),
        }
    }

    /// Append an audit event. A failed write is logged; it never fails the user's action.
    pub fn audit(&self, event: AuditEvent) {
        record_audit(&self.audit, event);
    }

    /// Synchronously clear a copied password that is still pending, if the clipboard still
    /// holds it (a value the user copied since is left alone). Returns whether it cleared.
    pub fn clear_pending_clipboard(&self) -> bool {
        let pending = self.pending_clipboard.lock().ok().and_then(|mut p| p.take());
        let Some(expected) = pending else {
            return false;
        };
        let Ok(cleared) = clipboard::clear_if_unchanged(&*self.settings.clipboard, &expected)
        else {
            tracing::warn!("could not clear the clipboard");
            return false;
        };
        if cleared {
            tracing::info!("copied password cleared from the clipboard");
        }
        cleared
    }

    /// Clear a pending copied password (M-1), close the store explicitly (checkpoint + FTS
    /// purge, review condition 1) and drop the live sessions. Called from `RunEvent::Exit`.
    pub fn shutdown(&self) {
        self.clear_pending_clipboard();
        if let Ok(mut sessions) = self.sessions.lock() {
            for (_, handle) in sessions.drain() {
                handle.abort();
            }
        }
        let store = self.store.lock().ok().and_then(|mut slot| slot.store.take());
        if let Some(store) = store {
            match store.close() {
                Ok(()) => tracing::info!("store closed"),
                Err(e) => tracing::warn!(error = %e, "store close failed"),
            }
        }
    }
}

fn closed_store() -> IpcError {
    IpcError::new("store.io", "the connection database is closed")
}

/// Append to a shared audit log (used by session tasks too).
pub fn record_audit(log: &Mutex<AuditLog>, event: AuditEvent) {
    let Ok(mut log) = log.lock() else {
        tracing::error!("audit log mutex poisoned");
        return;
    };
    if let Err(e) = log.record(event) {
        tracing::error!(error = %e, "audit write failed");
    }
}

fn create_private(path: &Path) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Make the rename durable (unix). Best effort: some filesystems refuse a directory fsync.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Err(e) = File::open(dir).and_then(|d| d.sync_all()) {
        tracing::debug!(kind = ?e.kind(), "directory sync skipped");
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
pub(crate) mod testing {
    //! Fixtures shared by the command tests: a temp data dir, `KdfParams::TEST`, no agent, an
    //! in-memory clipboard and a short clear delay.

    use super::*;
    use crate::clipboard::MemoryClipboard;
    use secrecy::SecretString;

    /// Test-only master password (synthetic).
    pub const MASTER: &str = "test-only master pw";

    pub struct Fixture {
        pub dir: tempfile::TempDir,
        pub state: AppState,
        pub clipboard: Arc<MemoryClipboard>,
    }

    pub fn settings(clipboard: Arc<MemoryClipboard>) -> Settings {
        Settings {
            kdf: KdfChoice::Fixed(KdfParams::TEST),
            ssh_allow_agent: false,
            clipboard,
            clipboard_clear_after: Duration::from_millis(200),
        }
    }

    /// Fresh state without a vault.
    pub fn empty() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let clipboard = Arc::new(MemoryClipboard::default());
        let state = AppState::new(dir.path().to_path_buf(), settings(Arc::clone(&clipboard)))
            .expect("state");
        Fixture { dir, state, clipboard }
    }

    /// Fresh state with an unlocked vault.
    pub fn unlocked() -> Fixture {
        let f = empty();
        crate::commands::vault::create(&f.state, SecretString::from(MASTER.to_owned()))
            .expect("create vault");
        f
    }

    /// Audit event names written so far.
    pub fn audit_events(state: &AppState) -> Vec<String> {
        let path = state.data_dir.join(AppState::AUDIT_FILE);
        let text = std::fs::read_to_string(path).unwrap_or_default();
        text.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.get("event").and_then(|e| e.as_str()).map(str::to_owned))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn new_state_creates_root_and_private_db() {
        let f = empty();
        let slot = f.state.store.lock().expect("lock");
        let root = slot.store.as_ref().expect("store").root_folder().expect("q").expect("root");
        assert_eq!(root.name, ROOT_FOLDER_NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(f.dir.path().join(AppState::DB_FILE))
                .expect("db")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn header_write_is_private_keeps_backup_and_backup_can_be_dropped() {
        let f = unlocked();
        let header = f.dir.path().join(AppState::HEADER_FILE);
        let bak = f.dir.path().join(AppState::HEADER_BACKUP);
        assert!(header.exists());
        assert!(!bak.exists(), "first write has nothing to back up");
        let before = std::fs::read(&header).expect("read");
        {
            let vault = f.state.vault().expect("vault");
            f.state.save_header(vault.as_ref().expect("v")).expect("second write");
        }
        assert_eq!(std::fs::read(&bak).expect("backup"), before);
        assert!(!f.dir.path().join("vault.header.json.tmp").exists(), "temp renamed away");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&header).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        f.state.drop_header_backup();
        assert!(!bak.exists());
    }

    #[test]
    fn with_ready_requires_unlock_and_binds_vault_id() {
        let f = empty();
        assert_eq!(f.state.with_ready(|_, _| Ok(())).expect_err("missing").code, "vault.missing");
        crate::commands::vault::create(&f.state, secrecy::SecretString::from(MASTER.to_owned()))
            .expect("create");
        let id = f.state.vault().expect("v").as_ref().expect("v").vault_id();
        let bound = f.state.with_ready(|_, s| Ok(s.vault_id()?)).expect("ok");
        assert_eq!(bound, Some(id.to_string()));
        crate::commands::vault::lock(&f.state, None).expect("lock");
        assert_eq!(f.state.with_ready(|_, _| Ok(())).expect_err("locked").code, "vault.locked");
    }

    #[test]
    fn shutdown_closes_the_store() {
        let f = unlocked();
        f.state.shutdown();
        assert!(f.state.store.lock().expect("lock").store.is_none());
        let e = f.state.with_ready(|_, _| Ok(())).expect_err("closed");
        assert_eq!(e.code, "store.io");
    }
}
