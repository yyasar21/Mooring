//! Start-up sweeps of the web storage directories (review 5 L-29, L-30).
//!
//! * `$APP_DATA/web/*`: after unlock, every entry that is not the canonical UUID of an
//!   existing web connection with `persistent: true` is removed (a store left by a folder
//!   cascade, a crash between the row delete and the directory removal, or a connection whose
//!   `persistent` was switched off).
//! * `$APP_CACHE/web-ephemeral/*`: at start, before any window exists, everything goes (a
//!   Windows profile `WebView2` still held when its window was destroyed, or a crash).

use std::collections::HashSet;
use std::path::Path;

use mooring_core::{Protocol, ProtocolOptions};

use super::{WEB_DATA_DIR, WEB_EPHEMERAL_DIR};
use crate::error::IpcResult;
use crate::state::AppState;

/// Ids (canonical UUID strings) of the web connections whose store may stay on disk.
fn persistent_web_ids(state: &AppState) -> IpcResult<HashSet<String>> {
    state.with_ready(|_, store| {
        let mut keep = HashSet::new();
        for f in store.list_folders()? {
            for c in store.list_connections(f.id)? {
                if c.protocol != Protocol::Web {
                    continue;
                }
                // Unreadable options: keep the store rather than wipe a user's cookies on a
                // transient error; `web_open` re-validates before any use.
                let persistent = match store.connection_options(c.id) {
                    Ok(ProtocolOptions::Web(o)) => o.persistent,
                    Ok(_) => false,
                    Err(_) => true,
                };
                if persistent {
                    keep.insert(c.id.to_string());
                }
            }
        }
        Ok(keep)
    })
}

/// Remove every entry of `dir` whose name is not in `keep`. Returns the removed names.
fn sweep_dir(dir: &Path, keep: &HashSet<String>) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep.contains(&name) {
            continue;
        }
        let path = entry.path();
        let done = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
        match done {
            Ok(()) => removed.push(name),
            Err(e) => tracing::warn!(kind = ?e.kind(), "web storage sweep: entry kept"),
        }
    }
    removed
}

/// After unlock: wipe orphan persistent stores. Returns how many entries were removed.
pub fn orphan_stores(state: &AppState) -> usize {
    let keep = match persistent_web_ids(state) {
        Ok(keep) => keep,
        Err(e) => {
            tracing::warn!(code = e.code, "web store sweep skipped");
            return 0;
        }
    };
    let removed = sweep_dir(&state.data_dir.join(WEB_DATA_DIR), &keep);
    if !removed.is_empty() {
        tracing::info!(count = removed.len(), "orphan web stores removed");
    }
    removed.len()
}

/// At start: wipe every ephemeral profile not held by an open window (none at start).
pub fn ephemeral_profiles(state: &AppState) -> usize {
    let open: HashSet<String> =
        state.web.lock().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    let removed = sweep_dir(&state.cache_dir.join(WEB_EPHEMERAL_DIR), &open);
    if !removed.is_empty() {
        tracing::info!(count = removed.len(), "stale ephemeral web profiles removed");
    }
    removed.len()
}
