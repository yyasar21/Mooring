//! Fixtures shared by the command tests and, with `test-util`, the integration tests: a temp
//! data dir, `KdfParams::TEST`, no agent, an in-memory clipboard and a short clear delay.
use std::sync::Arc;
use std::time::Duration;

use mooring_vault::KdfParams;

use super::{AppState, KdfChoice, Settings};
use crate::clipboard::MemoryClipboard;
use crate::dirs::Dirs;
use secrecy::SecretString;

/// Test-only master password (synthetic).
pub const MASTER: &str = "test-only master pw";

#[derive(Debug)]
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
        graphical: Arc::new(crate::session_factory::BuiltinFactory),
        reconnect_unit: Duration::from_millis(1),
        biometric: Arc::new(crate::biometric::memory::MemoryBiometricStore::new("macos")),
        fast_exports: true,
        // The release behaviour is the one most tests pin; dev-only paths set `Channel::Dev`.
        channel: crate::build_identity::Channel::Release,
    }
}

/// Fresh state (no vault) whose biometric store is a scriptable memory store reporting
/// `platform` (ADR-0022 tests).
pub fn with_biometric(
    platform: &'static str,
) -> (Fixture, Arc<crate::biometric::memory::MemoryBiometricStore>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let clipboard = Arc::new(MemoryClipboard::default());
    let bio = Arc::new(crate::biometric::memory::MemoryBiometricStore::new(platform));
    let mut s = settings(Arc::clone(&clipboard));
    s.biometric = Arc::clone(&bio) as Arc<dyn crate::biometric::BiometricStore>;
    let state = AppState::new(dirs(dir.path()), s).expect("state");
    (Fixture { dir, state, clipboard }, bio)
}

/// Non-portable [`Dirs`] rooted at `data` (cache under it), as the OS layout gives them.
pub fn dirs(data: &std::path::Path) -> Dirs {
    Dirs::plain(data.to_path_buf(), data.join("cache"))
}

/// Portable [`Dirs`] rooted at `root` (ADR-0021): `root/{data,cache}`, `portable_root = root`.
pub fn portable_dirs(root: &std::path::Path) -> Dirs {
    let data = root.join("data");
    let cache = root.join("cache");
    std::fs::create_dir_all(&data).expect("data");
    std::fs::create_dir_all(&cache).expect("cache");
    Dirs { data, cache, portable_root: Some(root.to_path_buf()), mode_unavailable: false }
}

/// Fresh state without a vault.
pub fn empty() -> Fixture {
    with_dirs(dirs)
}

/// Fresh state without a vault, in portable mode (ADR-0021).
pub fn empty_portable() -> Fixture {
    with_dirs(|dir| portable_dirs(&dir.join(crate::dirs::Dirs::ROOT)))
}

/// Fresh state without a vault, with `settings` (e.g. the dev channel, ADR-0028). The
/// fixture's `clipboard` is a fresh one, not the one inside `settings`.
pub fn with_settings(settings: Settings) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = AppState::new(dirs(dir.path()), settings).expect("state");
    Fixture { dir, state, clipboard: Arc::new(MemoryClipboard::default()) }
}

/// [`with_settings`] with the testing settings on the dev channel, vault unlocked.
pub fn unlocked_dev() -> Fixture {
    let mut s = settings(Arc::new(MemoryClipboard::default()));
    s.channel = crate::build_identity::Channel::Dev;
    let f = with_settings(s);
    crate::commands::vault::create(&f.state, SecretString::from(MASTER.to_owned()))
        .expect("create vault");
    f
}

fn with_dirs(dirs: impl FnOnce(&std::path::Path) -> Dirs) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clipboard = Arc::new(MemoryClipboard::default());
    let state = AppState::new(dirs(dir.path()), settings(Arc::clone(&clipboard))).expect("state");
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
