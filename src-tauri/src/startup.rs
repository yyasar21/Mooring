//! Start-up checks that run before any window exists (ADR-0021 §1, §3): the directory
//! resolver and the fatal path (native message box, exit code 2, no window, no fallback).

use std::path::PathBuf;

use tauri::{AppHandle, Manager, Runtime};

use crate::dirs::{Dirs, DirsError};

/// Exit code of a refused start (the message box names the directory first).
pub const EXIT_REFUSED: i32 = 2;
/// Exit anyway when the message box cannot be shown (headless session, broken toolkit).
pub const DIALOG_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(120);

/// Code and message of a refused start (no secret, no path beyond the named directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `portable.*` / `app.data_dir`.
    pub code: &'static str,
    /// What the message box says.
    pub message: String,
}

impl From<DirsError> for Refusal {
    fn from(e: DirsError) -> Self {
        Self { code: e.code(), message: e.to_string() }
    }
}

/// `portable.webview_missing` (Windows): the plain exe needs the Evergreen `WebView2` runtime.
pub fn webview_missing() -> Refusal {
    Refusal {
        code: "portable.webview_missing",
        message: "Mooring needs the Microsoft Edge WebView2 Runtime, which is not installed for \
                  this user. Run Microsoft's Evergreen bootstrapper (no administrator rights \
                  needed, see README.txt in the Mooring folder) and start Mooring again."
            .to_owned(),
    }
}

/// Resolve the directories for this process: the marker next to the executable (or the
/// `AppImage` / `.app`), the OS directories otherwise. Fails loudly, never falls back.
pub fn resolve_dirs<R: Runtime>(app: &tauri::App<R>) -> Result<Dirs, Refusal> {
    // The path only locates the marker; it never decides what is trusted.
    let exe = std::env::current_exe().map_err(|_| Refusal {
        code: "app.data_dir",
        message: "The executable path could not be resolved.".to_owned(),
    })?; // nosemgrep
    let appimage = std::env::var_os("APPIMAGE").map(PathBuf::from);
    let os_default = || Ok((app.path().app_data_dir()?, app.path().app_cache_dir()?));
    let probe = |p: &std::path::Path| crate::updater::install_mode::dir_writable(Some(p));
    Ok(Dirs::resolve(&exe, appimage.as_deref(), &os_default, &probe)?)
}

/// Portable mode on Windows: refuse before any window when no `WebView2` runtime is present
/// (ADR-0021 §3). Elsewhere the toolkit is part of the OS.
pub fn check_webview(dirs: &Dirs) -> Result<(), Refusal> {
    if cfg!(windows) && dirs.portable() && tauri::webview_version().is_err() {
        return Err(webview_missing());
    }
    Ok(())
}

/// Show `refusal` in a native error box and exit with [`EXIT_REFUSED`] when it is dismissed.
/// The dialog is queued on the event loop (setup runs before it), so this returns and the
/// caller must create **no window**; a watchdog exits anyway after [`DIALOG_WATCHDOG`].
pub fn refuse<R: Runtime>(app: &AppHandle<R>, refusal: &Refusal) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
    tracing::error!(code = refusal.code, "start refused");
    app.dialog()
        .message(refusal.message.clone())
        .title("Mooring cannot start")
        .kind(MessageDialogKind::Error)
        .show(|_| std::process::exit(EXIT_REFUSED));
    std::thread::spawn(|| {
        std::thread::sleep(DIALOG_WATCHDOG);
        std::process::exit(EXIT_REFUSED);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_carry_the_code_and_name_the_directory() {
        let r: Refusal = DirsError::Unwritable(PathBuf::from("/media/usb/Mooring")).into();
        assert_eq!(r.code, "portable.unwritable");
        assert!(r.message.contains("/media/usb/Mooring"));
        let r: Refusal = DirsError::MarkerInvalid(PathBuf::from("/x/portable")).into();
        assert_eq!(r.code, "portable.marker_invalid");
        let r: Refusal = DirsError::DataDirInvalid(PathBuf::from("/x/Mooring Data")).into();
        assert_eq!(r.code, "portable.data_dir_invalid");
        let w = webview_missing();
        assert_eq!(w.code, "portable.webview_missing");
        assert!(w.message.contains("WebView2") && w.message.contains("README.txt"));
        assert_eq!(EXIT_REFUSED, 2);
    }

    #[cfg(not(windows))]
    #[test]
    fn webview_check_only_bites_on_windows() {
        let d = Dirs { data: PathBuf::new(), cache: PathBuf::new(), portable_root: Some(PathBuf::from("/x")) };
        assert_eq!(check_webview(&d), Ok(()));
    }
}
