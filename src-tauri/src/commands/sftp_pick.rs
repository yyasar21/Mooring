//! `sftp_pick_local({ sessionId, mode })` (ADR-0010 §SFTP, security review 4 B-4).
//!
//! The native file dialog is opened from Rust (`tauri-plugin-dialog`'s Rust API with a
//! callback and a `oneshot`, never a `blocking_*` call on a runtime worker). The chosen path is
//! validated (canonical, not inside the app data directory; a file must be a regular file with
//! a confinable name) and stored in [`crate::picks::Picks`]; the `WebView` receives only an
//! opaque `pickId` and the display name. While the dialog is open the auto-lock ignores the
//! main window's focus loss (M-9, bounded by N-20). A locked vault refuses the call with
//! `vault.locked` (review 4, N-19): a locked UI never asks for a pick, so such a dialog over the
//! lock screen could only come from a hostile `WebView`.
//!
//! Tests inject a [`LocalPicker`] that answers with a fixed path instead of a dialog.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::oneshot;

use crate::autolock::AutoLock;
use crate::commands::sftp_transfers::dialog_dir;
use crate::error::{IpcError, IpcResult};
use crate::picks::PickMode;
use crate::state::AppState;

/// Answer of the dialog: the chosen path, or `None` when the user cancelled.
pub type PickReply = Box<dyn FnOnce(Option<PathBuf>) + Send>;

/// Something that asks the user for a local folder or file.
pub trait LocalPicker: Send + Sync {
    /// Open the picker and call `reply` exactly once (possibly from another thread).
    fn pick(&self, mode: PickMode, reply: PickReply);

    /// [`pick`](Self::pick) with a file-type filter (`import_pick`, ADR-0019 §3); an empty
    /// `extensions` list means no filter. The default ignores the filter.
    fn pick_filtered(&self, mode: PickMode, _label: &str, _extensions: &[&str], reply: PickReply) {
        self.pick(mode, reply);
    }

    /// A native *save* dialog suggesting `file_name` (`vault_export_pick`, ADR-0023 §2). The
    /// default answers like a file pick (test pickers).
    fn pick_save(&self, _file_name: &str, _label: &str, _extensions: &[&str], reply: PickReply) {
        self.pick(PickMode::File, reply);
    }
}

/// The production picker: the OS dialog, parented to the main window.
pub struct DialogPicker<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> std::fmt::Debug for DialogPicker<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialogPicker").finish_non_exhaustive()
    }
}

impl<R: Runtime> DialogPicker<R> {
    /// The dialog parented to `app`'s main window.
    pub fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: Runtime> LocalPicker for DialogPicker<R> {
    fn pick(&self, mode: PickMode, reply: PickReply) {
        self.pick_filtered(mode, "", &[], reply);
    }

    fn pick_filtered(&self, mode: PickMode, label: &str, extensions: &[&str], reply: PickReply) {
        use tauri_plugin_dialog::DialogExt;
        let mut builder = self.app.dialog().file();
        if let Some(main) = self.app.get_webview_window(crate::navigation::MAIN_WINDOW) {
            builder = builder.set_parent(&main);
        }
        if !extensions.is_empty() {
            builder = builder.add_filter(label, extensions);
        }
        let done = move |p: Option<tauri_plugin_dialog::FilePath>| {
            reply(p.and_then(|p| p.into_path().ok()));
        };
        match mode {
            PickMode::Folder => builder.pick_folder(done),
            PickMode::File => builder.pick_file(done),
        }
    }

    fn pick_save(&self, file_name: &str, label: &str, extensions: &[&str], reply: PickReply) {
        use tauri_plugin_dialog::DialogExt;
        let mut builder = self.app.dialog().file().set_file_name(file_name);
        if let Some(main) = self.app.get_webview_window(crate::navigation::MAIN_WINDOW) {
            builder = builder.set_parent(&main);
        }
        if !extensions.is_empty() {
            builder = builder.add_filter(label, extensions);
        }
        builder.save_file(move |p| reply(p.and_then(|p| p.into_path().ok())));
    }
}

/// A picker that always answers with the same path (tests, `test-util`).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone)]
pub struct FixedPicker(pub Option<PathBuf>);

#[cfg(any(test, feature = "test-util"))]
impl LocalPicker for FixedPicker {
    fn pick(&self, _mode: PickMode, reply: PickReply) {
        reply(self.0.clone());
    }
}

/// `{ pickId, name }`: the opaque id for `sftp_download` / `sftp_upload` and the display name
/// (last path segment only, never the full path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Picked {
    /// 128-bit hex id, single-use, bound to the session, valid for 10 minutes.
    pub pick_id: String,
    /// File or folder name to show.
    pub name: String,
}

fn bad(reason: &str) -> IpcError {
    IpcError::invalid("pick", reason)
}

/// Validate what the dialog returned. Returns the canonical path and its display name.
fn check_choice(state: &AppState, mode: PickMode, raw: &Path) -> IpcResult<(PathBuf, String)> {
    let path = match mode {
        PickMode::Folder => dialog_dir(state, "pick", raw)?,
        PickMode::File => {
            let name = raw.file_name().ok_or_else(|| bad("names no file"))?;
            // The remote side needs the name as text.
            name.to_str().ok_or_else(|| bad("file name is not UTF-8"))?;
            let parent = raw.parent().ok_or_else(|| bad("names no file"))?;
            let base = dialog_dir(state, "pick", parent)?;
            let local = mooring_proto_ssh::LocalPath::new(&base, name).map_err(IpcError::from)?;
            local.check_existing_file().map_err(IpcError::from)?;
            base.join(name)
        }
    };
    let name = path
        .file_name()
        .map_or_else(|| "/".to_owned(), |n| n.to_string_lossy().into_owned());
    Ok((path, name))
}

/// `sftp_pick_local`: ask the user, store the choice, return `{ pickId, name }`, or `None`
/// when the user cancelled (or the vault was locked while the dialog was open).
pub async fn pick_local(
    state: &AppState,
    picker: &dyn LocalPicker,
    autolock: Option<&AutoLock>,
    session_id: &str,
    mode: &str,
) -> IpcResult<Option<Picked>> {
    let mode = PickMode::parse(mode)?;
    if !matches!(crate::commands::vault::status(state)?, crate::commands::vault::VaultStatus::Unlocked) {
        return Err(IpcError::locked());
    }
    // The session must exist now; the pick is bound to it.
    crate::commands::forward::control_of(state, session_id)?;
    let epoch = state.picks.epoch();
    let chosen = {
        let _open = autolock.map(AutoLock::dialog_guard);
        let (tx, rx) = oneshot::channel();
        picker.pick(mode, Box::new(move |p| drop(tx.send(p))));
        rx.await.ok().flatten()
    };
    let Some(raw) = chosen else {
        return Ok(None);
    };
    let (path, name) = check_choice(state, mode, &raw)?;
    Ok(state
        .picks
        .insert(epoch, session_id, mode, path, Instant::now())
        .map(|pick_id| Picked { pick_id, name }))
}

/// `sftp_pick_local({ sessionId, mode: "folder" | "file" })` → `{ pickId, name } | null`.
#[tauri::command]
pub async fn sftp_pick_local<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    session_id: String,
    mode: String,
) -> IpcResult<Option<Picked>> {
    let picker = DialogPicker { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    pick_local(&state, &picker, autolock.as_deref(), &session_id, &mode).await
}

#[cfg(test)]
#[path = "sftp_pick_tests.rs"]
mod tests;
