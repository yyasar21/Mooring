//! In-app updates (ADR-0018 §3, A4 U0): the runtime shared by the `update_*` commands and
//! the opt-in background check.
//!
//! * The plugin is registered **only** when `plugins.updater.pubkey` is non-empty
//!   ([`configured_pubkey`]); otherwise [`UpdateRuntime::unconfigured`] makes every command
//!   answer `update.unconfigured`. No capability grants `updater:*`: the plugin's JS commands
//!   are unreachable from every window and only Rust talks to it.
//! * One network check at a time (`update.busy`), at least [`MIN_CHECK_GAP`] between manual
//!   checks (`update.rate_limited`). An install takes the same single flight and is throttled
//!   the same way against the previous install attempt (review 7 N-51).
//! * The install-mode matrix ([`install_mode`]) is decided in Rust before the plugin is
//!   asked, so its elevation paths (pkexec / sudo / `AppleScript`) are never reached.

pub mod background;
pub mod install_mode;
pub mod notes;
pub mod source;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use semver::Version;

use self::install_mode::{Bundle, InstallFacts, InstallMode, InstallProbe, OsProbe};
use self::source::{RemoteUpdate, UpdateSource};
use crate::error::{IpcError, IpcResult};

/// Smallest gap between two network checks started by the user.
pub const MIN_CHECK_GAP: Duration = Duration::from_secs(60);

/// The in-flight operation, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Busy {
    Check,
    Install,
}

#[derive(Debug, Default)]
struct Inner {
    busy: Option<Busy>,
    last_network: Option<Instant>,
    /// Start of the previous install attempt that reached the source (N-51).
    last_install: Option<Instant>,
    last_available: Option<RemoteUpdate>,
}

fn rate_limited(last: Option<Instant>, now: Instant) -> Result<(), IpcError> {
    let Some(last) = last else { return Ok(()) };
    let elapsed = now.saturating_duration_since(last);
    if elapsed < MIN_CHECK_GAP {
        let wait = MIN_CHECK_GAP.saturating_sub(elapsed).as_secs().max(1);
        return Err(IpcError::new("update.rate_limited", format!("checked a moment ago; try again in {wait} s")));
    }
    Ok(())
}

/// Managed state of the updater.
pub struct UpdateRuntime {
    source: Option<Arc<dyn UpdateSource>>,
    probe: Arc<dyn InstallProbe>,
    current: Version,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for UpdateRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateRuntime")
            .field("configured", &self.source.is_some())
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

/// Releases the single flight when dropped (also on an early `?`).
pub struct Flight<'a> {
    inner: &'a Mutex<Inner>,
}

impl std::fmt::Debug for Flight<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Flight")
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).busy = None;
    }
}

impl UpdateRuntime {
    /// A runtime whose every command answers `update.unconfigured` (no pubkey in the build).
    pub fn unconfigured(current: Version) -> Self {
        Self { source: None, probe: Arc::new(OsProbe), current, inner: Mutex::default() }
    }

    /// A runtime over `source`, with `probe` deciding the install mode.
    pub fn new(source: Arc<dyn UpdateSource>, probe: Arc<dyn InstallProbe>, current: Version) -> Self {
        Self { source: Some(source), probe, current, inner: Mutex::default() }
    }

    /// The running version (from `CARGO_PKG_VERSION` in the app).
    pub fn current(&self) -> &Version {
        &self.current
    }

    /// The source, or `update.unconfigured`.
    pub fn source(&self) -> IpcResult<&Arc<dyn UpdateSource>> {
        self.source.as_ref().ok_or_else(|| {
            IpcError::new("update.unconfigured", "updates are not configured for this build")
        })
    }

    /// Whether a source is configured.
    pub fn configured(&self) -> bool {
        self.source.is_some()
    }

    /// Take the single flight for a check. With `enforce_gap`, a check less than
    /// [`MIN_CHECK_GAP`] after the previous network check is `update.rate_limited`.
    pub fn begin_check(&self, now: Instant, enforce_gap: bool) -> IpcResult<Flight<'_>> {
        let mut inner = self.inner.lock().map_err(|_| IpcError::poisoned())?;
        if inner.busy.is_some() {
            return Err(busy());
        }
        if enforce_gap {
            rate_limited(inner.last_network, now)?;
        }
        inner.busy = Some(Busy::Check);
        inner.last_network = Some(now);
        Ok(Flight { inner: &self.inner })
    }

    /// Take the single flight for an install. Its re-check is not held to the *check* gap
    /// (it is the user's confirmation of a check they just saw), but installs are throttled
    /// against each other: less than [`MIN_CHECK_GAP`] after the previous install attempt is
    /// `update.rate_limited` (review 7 N-51: a T5 looping `update_install` gets one network
    /// request per minute at most).
    pub fn begin_install(&self, now: Instant) -> IpcResult<Flight<'_>> {
        let mut inner = self.inner.lock().map_err(|_| IpcError::poisoned())?;
        if inner.busy.is_some() {
            return Err(busy());
        }
        rate_limited(inner.last_install, now)?;
        inner.busy = Some(Busy::Install);
        inner.last_network = Some(now);
        inner.last_install = Some(now);
        Ok(Flight { inner: &self.inner })
    }

    /// Remember what the last check offered (the badge the background check shows).
    pub fn set_last_available(&self, available: Option<RemoteUpdate>) {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).last_available = available;
    }

    /// What the last check offered.
    pub fn last_available(&self) -> Option<RemoteUpdate> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).last_available.clone()
    }

    /// Whether an operation is in flight.
    pub fn busy(&self) -> bool {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).busy.is_some()
    }

    /// The install-mode decision for this process.
    pub fn install_mode(&self) -> InstallMode {
        let facts = self.probe.facts().unwrap_or_else(|| InstallFacts {
            bundle: Bundle::Unknown,
            install_path: std::path::PathBuf::new(),
            writable: false,
            cask_present: false,
        });
        install_mode::decide(&facts)
    }

    /// Strict semver: `offered` is an update only when greater than the running version
    /// (a pre-release of the same version is not, review: downgrades refused twice —
    /// here and in the plugin comparator).
    pub fn is_newer(&self, offered: &Version) -> bool {
        *offered > self.current
    }
}

fn busy() -> IpcError {
    IpcError::new("update.busy", "an update check or install is already running")
}

/// `plugins.updater.pubkey` from the Tauri config, when non-empty (the condition for
/// registering the plugin at all).
pub fn configured_pubkey(config: &tauri::Config) -> Option<String> {
    config
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "tests.rs"]
pub(crate) mod tests;
