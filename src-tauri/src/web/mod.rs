//! Web sessions (ADR-0013): one isolated `web-<connectionId>` window per web connection.
//!
//! This module is the testable part: the open plan (options → allow-list, storage), the
//! window registry, the `WebEvent` wire shape and title sanitising. [`window`] builds the
//! Tauri window with the guards; `commands::web` holds the IPC commands.

pub mod policy;
pub mod refusals;
pub mod sweep;
pub mod window;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mooring_core::{Protocol, ProtocolOptions};
use serde::Serialize;
use tauri::Url;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::guard::WEB_PREFIX;
use crate::state::AppState;
use policy::{display_origin, NavPolicy};

/// Longest page title passed to the UI, in characters.
pub const MAX_TITLE_CHARS: usize = 256;
/// Directory under `$APP_DATA` holding the persistent per-connection stores.
pub const WEB_DATA_DIR: &str = "web";
/// Directory under `$APP_CACHE` holding the Windows per-window ephemeral profiles (L-29).
pub const WEB_EPHEMERAL_DIR: &str = "web-ephemeral";

/// An event on the `onEvent` channel of `web_open` (`snake_case`, `kind` tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebEvent {
    /// The page title changed (sanitised, ≤ 256 characters; page-controlled text).
    Title {
        /// Title.
        title: String,
    },
    /// A top-level page finished loading at `origin`.
    Navigated {
        /// `scheme://host[:port]`.
        origin: String,
    },
    /// A top-level navigation was refused (the user may add `origin` to the connection).
    Blocked {
        /// Origin only, never the path.
        origin: String,
    },
    /// A download was refused.
    DownloadBlocked {
        /// Origin of the download URL.
        origin: String,
    },
    /// The window is gone (always last).
    Closed,
}

/// Where a window's events go. Returns `false` when the UI side is gone.
pub type WebSink = Arc<dyn Fn(WebEvent) -> bool + Send + Sync>;

/// One open web window.
#[derive(Clone)]
pub struct WebEntry {
    /// `web-<connectionId>`.
    pub label: String,
    /// Current top-level origin.
    pub origin: String,
    /// Last sanitised page title.
    pub title: String,
    /// Effective storage: `true` only when a per-connection store is in use.
    pub persistent: bool,
    /// Windows ephemeral profile directory (review 5 L-29), removed when the window is gone.
    pub ephemeral_dir: Option<PathBuf>,
    /// RFC 3339.
    pub opened_at: String,
    /// The main window's channel.
    pub sink: WebSink,
    /// Audited-refusal budget (N-43).
    pub refusals: Arc<refusals::RefusalBudget>,
}

impl std::fmt::Debug for WebEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebEntry")
            .field("label", &self.label)
            .field("origin", &self.origin)
            .field("persistent", &self.persistent)
            .finish_non_exhaustive()
    }
}

/// Open web windows by connection id.
pub type WebRegistry = Arc<Mutex<HashMap<String, WebEntry>>>;

/// One row of `web_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebWindowInfo {
    /// Connection id.
    pub connection_id: String,
    /// `web-<connectionId>`.
    pub window_label: String,
    /// Current origin.
    pub origin: String,
    /// Sanitised page title.
    pub title: String,
    /// Effective storage.
    pub persistent: bool,
    /// RFC 3339.
    pub opened_at: String,
}

/// How the window stores cookies and site data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Storage {
    /// `incognito(true)`: nothing reaches disk (default, owner decision 7).
    Ephemeral,
    /// Windows: `incognito(true)` **and** `data_directory(<cache>/web-ephemeral/<id>)`, so
    /// each ephemeral window gets its own `WebView2` environment instead of the one `InPrivate`
    /// session every controller of the shared environment would share (review 5 L-29). The
    /// directory is removed with the window and swept at start.
    EphemeralDirectory(PathBuf),
    /// Windows / Linux: `data_directory($APP_DATA/web/<connectionId>)`.
    Directory(PathBuf),
    /// macOS ≥ 14: `data_store_identifier` = the connection UUID bytes.
    Identifier([u8; 16]),
}

/// The platform facts the storage choice depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOs {
    /// `WebView2`: per-webview data directories; an `InPrivate` session is per environment.
    Windows,
    /// `WebKitGTK`: per-webview data directories; a fresh non-persistent store per webview.
    Linux,
    /// `WKWebView`: a data store identifier needs macOS 14.
    MacOs {
        /// Major version, `0` when unknown.
        major: u32,
    },
}

impl StorageOs {
    /// This machine.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            let version = sysinfo::System::os_version().unwrap_or_default();
            Self::MacOs { major: macos_major(&version) }
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// Major number of a macOS version string (`"14.2.1"` → 14); `0` when unparsable.
pub fn macos_major(version: &str) -> u32 {
    version.trim().split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0)
}

/// Everything needed to build one web window.
#[derive(Debug, Clone)]
pub struct WebPlan {
    /// Connection id (canonical UUID string).
    pub connection_id: String,
    /// `web-<connectionId>`.
    pub label: String,
    /// Connection name (validated: no controls or bidi).
    pub name: String,
    /// Start URL.
    pub url: Url,
    /// Navigation allow-list.
    pub policy: NavPolicy,
    /// Storage.
    pub storage: Storage,
    /// The user asked for persistence but this OS cannot isolate it (macOS 11–13).
    pub persistent_refused: bool,
}

impl WebPlan {
    /// Start origin.
    pub fn origin(&self) -> String {
        display_origin(&self.url)
    }

    /// Whether a per-connection store is in use (what `web_list` reports as `persistent`).
    pub fn persistent(&self) -> bool {
        matches!(self.storage, Storage::Directory(_) | Storage::Identifier(_))
    }

    /// The Windows ephemeral profile directory, when the plan has one.
    pub fn ephemeral_dir(&self) -> Option<&PathBuf> {
        self.storage.ephemeral_dir()
    }
}

impl Storage {
    /// The Windows ephemeral profile directory, when this storage has one.
    pub fn ephemeral_dir(&self) -> Option<&PathBuf> {
        match self {
            Storage::EphemeralDirectory(dir) => Some(dir),
            _ => None,
        }
    }
}

/// Count one refused navigation of `connection_id`'s window; `true` while it still gets a
/// row of its own (N-43). A window without an entry (closed, between `closed_entry` and
/// `Destroyed`) is neither audited nor reported to the UI (6b N-43 b).
pub fn refusal_audited(registry: &WebRegistry, connection_id: &str) -> bool {
    registry.lock().ok().and_then(|m| m.get(connection_id).map(|e| e.refusals.refused())).unwrap_or(false)
}

/// Directory of the persistent store of `connection_id` (a canonical UUID string).
pub fn store_dir(state: &AppState, connection_id: &str) -> PathBuf {
    state.data_dir.join(WEB_DATA_DIR).join(connection_id)
}

/// Directory of the Windows ephemeral profile of `connection_id` (review 5 L-29).
pub fn ephemeral_dir(state: &AppState, connection_id: &str) -> PathBuf {
    state.cache_dir.join(WEB_EPHEMERAL_DIR).join(connection_id)
}

/// Ephemeral storage on `os`: a per-window profile directory on Windows, plain incognito
/// elsewhere (review 5 L-29). `connection_id` must be a canonical UUID string.
pub fn ephemeral_storage(state: &AppState, connection_id: &str, os: StorageOs) -> Storage {
    match os {
        StorageOs::Windows => Storage::EphemeralDirectory(ephemeral_dir(state, connection_id)),
        StorageOs::Linux | StorageOs::MacOs { .. } => Storage::Ephemeral,
    }
}

/// Resolve a web connection into a window plan. The vault must be unlocked; only the stored,
/// validated connection data is used (review 4 B-4: nothing from the `WebView` names a URL).
pub fn plan(
    state: &AppState,
    connection_id: &str,
    os: StorageOs,
    dev_url: Option<Url>,
) -> IpcResult<WebPlan> {
    let id = dto::connection_id("connectionId", connection_id)?;
    let (name, options) = state.with_ready(|_, store| {
        let c = store.get_connection(id)?;
        if c.protocol != Protocol::Web {
            return Err(IpcError::invalid("connectionId", "not a web connection"));
        }
        Ok((c.name, store.connection_options(id)?))
    })?;
    let ProtocolOptions::Web(opts) = options else {
        return Err(IpcError::invalid("connectionId", "not a web connection"));
    };
    let (policy, url) = NavPolicy::from_options(&opts, dev_url)?;
    let connection_id = id.to_string();
    let uuid = uuid::Uuid::parse_str(&connection_id)
        .map_err(|_| IpcError::invalid("connectionId", "not a UUID"))?;
    let (storage, persistent_refused) = match (opts.persistent, os) {
        (false, os) => (ephemeral_storage(state, &connection_id, os), false),
        (true, StorageOs::Windows | StorageOs::Linux) => {
            (Storage::Directory(store_dir(state, &connection_id)), false)
        }
        (true, StorageOs::MacOs { major }) if major >= 14 => {
            (Storage::Identifier(*uuid.as_bytes()), false)
        }
        (true, StorageOs::MacOs { .. }) => (Storage::Ephemeral, true),
    };
    Ok(WebPlan {
        label: format!("{WEB_PREFIX}{connection_id}"),
        connection_id,
        name,
        url,
        policy,
        storage,
        persistent_refused,
    })
}

/// A page title as the UI may show it: controls and bidi/invisible characters removed,
/// whitespace runs collapsed, at most [`MAX_TITLE_CHARS`] characters.
pub fn sanitize_title(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !mooring_core::is_bidi_or_invisible(*c))
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(MAX_TITLE_CHARS).collect()
}

/// The native window title: fixed by Mooring, so the real origin is always visible.
pub fn native_title(name: &str, origin: &str) -> String {
    format!("Mooring \u{b7} {name} \u{b7} {origin}")
}

/// `web_list()`, sorted by open time.
pub fn list(state: &AppState) -> IpcResult<Vec<WebWindowInfo>> {
    let map = state.web.lock().map_err(|_| IpcError::poisoned())?;
    let mut rows: Vec<WebWindowInfo> = map
        .iter()
        .map(|(id, e)| WebWindowInfo {
            connection_id: id.clone(),
            window_label: e.label.clone(),
            origin: e.origin.clone(),
            title: e.title.clone(),
            persistent: e.persistent,
            opened_at: e.opened_at.clone(),
        })
        .collect();
    rows.sort_by(|a, b| a.opened_at.cmp(&b.opened_at).then(a.connection_id.cmp(&b.connection_id)));
    Ok(rows)
}

/// Remove the window of `connection_id` from the registry. Returns its entry when it was
/// there; the caller then audits `web_closed` and sends `closed` exactly once.
pub fn forget(state: &AppState, connection_id: &str) -> Option<WebEntry> {
    state.web.lock().ok()?.remove(connection_id)
}

/// Remove the persistent store directory of a connection (`web_clear_data`,
/// `connection_delete`). Returns whether a directory was removed.
pub fn remove_store_dir(state: &AppState, connection_id: &str) -> IpcResult<bool> {
    let id = dto::connection_id("connectionId", connection_id)?.to_string();
    remove_dir(&store_dir(state, &id))
}

/// Remove the Windows ephemeral profile of a closed window (L-29). Best effort: a profile
/// `WebView2` still holds is swept at the next start.
pub fn remove_ephemeral_dir(dir: &std::path::Path) {
    if let Err(e) = remove_dir(dir) {
        tracing::warn!(code = e.code, "ephemeral web profile kept until the next start");
    }
}

fn remove_dir(dir: &std::path::Path) -> IpcResult<bool> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => {
            tracing::warn!(kind = ?e.kind(), "web store removal failed");
            Err(IpcError::new("web.clear_failed", "the browsing data could not be removed"))
        }
    }
}

#[cfg(test)]
#[path = "web_tests.rs"]
pub(crate) mod tests;
