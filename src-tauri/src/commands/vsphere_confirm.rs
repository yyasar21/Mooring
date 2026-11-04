//! Rust-native confirmations of the vSphere commands (ADR-0015 §3–4): power actions, the
//! TOFU certificate prompt and the VMRC hand-off. The dialog is `tauri-plugin-dialog`'s Rust
//! API (a callback and a `oneshot`, as `sftp_pick_local`), parented to the main window; the
//! `WebView` has no dialog permission, so an IPC call alone can never answer one. While it is
//! open the auto-lock ignores the main window's focus loss (the `dialog_open` exemption,
//! bounded by N-20). Tests inject [`FixedConfirm`].
//!
//! [`UrlOpener`] hands a VMRC ticket URL to the OS URL handler with a fixed argv (no shell):
//! `open` (macOS), `xdg-open` (Linux), `rundll32 url.dll,FileProtocolHandler` (Windows).

#[cfg(any(test, feature = "test-util"))]
use std::sync::Mutex;

use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;

use crate::autolock::AutoLock;

/// One question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// Window title.
    pub title: String,
    /// Body text (names the VM / vCenter / certificate).
    pub text: String,
    /// Label of the confirming button.
    pub ok: String,
    /// Warning icon (destructive action, untrusted certificate).
    pub warning: bool,
}

/// The answer callback: `true` = confirmed.
pub type ConfirmReply = Box<dyn FnOnce(bool) + Send>;

/// Something that asks the user a yes/no question outside the `WebView`.
pub trait Confirm: Send + Sync {
    /// Show `ask` and call `reply` exactly once (possibly from another thread).
    fn ask(&self, ask: Ask, reply: ConfirmReply);
}

/// The production dialog.
pub struct DialogConfirm<R: Runtime> {
    /// App handle.
    pub app: AppHandle<R>,
}

impl<R: Runtime> std::fmt::Debug for DialogConfirm<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialogConfirm").finish_non_exhaustive()
    }
}

impl<R: Runtime> Confirm for DialogConfirm<R> {
    fn ask(&self, ask: Ask, reply: ConfirmReply) {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
        let kind = if ask.warning { MessageDialogKind::Warning } else { MessageDialogKind::Info };
        let mut builder = self
            .app
            .dialog()
            .message(ask.text)
            .title(ask.title)
            .kind(kind)
            .buttons(MessageDialogButtons::OkCancelCustom(ask.ok, "Cancel".to_owned()));
        if let Some(main) = self.app.get_webview_window(crate::navigation::MAIN_WINDOW) {
            builder = builder.parent(&main);
        }
        builder.show(reply);
    }
}

/// A [`Confirm`] plus the auto-lock whose focus exemption is held while it asks.
#[derive(Clone, Copy)]
pub struct Prompt<'a> {
    /// The dialog.
    pub confirm: &'a dyn Confirm,
    /// The auto-lock (`None` in tests).
    pub autolock: Option<&'a AutoLock>,
}

impl std::fmt::Debug for Prompt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prompt").finish_non_exhaustive()
    }
}

impl<'a> Prompt<'a> {
    /// Without an auto-lock (tests).
    pub fn new(confirm: &'a dyn Confirm) -> Self {
        Self { confirm, autolock: None }
    }

    /// Ask and wait for the answer.
    pub async fn ask(&self, ask: Ask) -> bool {
        confirm(self.confirm, self.autolock, ask).await
    }
}

/// Ask through `confirm` with the auto-lock focus exemption held while the dialog is open.
pub async fn confirm(confirm: &dyn Confirm, autolock: Option<&AutoLock>, ask: Ask) -> bool {
    let _open = autolock.map(AutoLock::dialog_guard);
    let (tx, rx) = oneshot::channel();
    confirm.ask(ask, Box::new(move |ok| {
        let _ = tx.send(ok);
    }));
    rx.await.unwrap_or(false)
}

/// A fixed answer that records every question (tests, `test-util`).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct FixedConfirm {
    /// The answer.
    pub answer: bool,
    /// Questions asked so far.
    pub asked: Mutex<Vec<Ask>>,
}

#[cfg(any(test, feature = "test-util"))]
impl FixedConfirm {
    /// Answers `answer` to everything.
    pub fn new(answer: bool) -> Self {
        Self { answer, asked: Mutex::new(Vec::new()) }
    }

    /// Questions asked so far.
    pub fn asked(&self) -> Vec<Ask> {
        self.asked.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Confirm for FixedConfirm {
    fn ask(&self, ask: Ask, reply: ConfirmReply) {
        if let Ok(mut g) = self.asked.lock() {
            g.push(ask);
        }
        reply(self.answer);
    }
}

/// The OS URL handler could not be started (no detail: the URL is a secret ticket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFailed;

/// Opens a URL with the OS handler.
pub trait UrlOpener: Send + Sync {
    /// Hand `url` (already validated) to the OS.
    fn open(&self, url: &str) -> Result<(), OpenFailed>;
}

/// The production opener: a fixed argv, no shell, output discarded.
#[derive(Debug, Default)]
pub struct OsOpener;

impl UrlOpener for OsOpener {
    fn open(&self, url: &str) -> Result<(), OpenFailed> {
        use std::process::{Command, Stdio};
        let mut cmd = if cfg!(target_os = "macos") {
            Command::new("open")
        } else if cfg!(windows) {
            let mut c = Command::new("rundll32");
            c.arg("url.dll,FileProtocolHandler");
            c
        } else {
            Command::new("xdg-open")
        };
        cmd.arg(url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        match cmd.spawn() {
            Ok(_child) => Ok(()),
            Err(e) => {
                tracing::warn!(kind = ?e.kind(), "OS URL handler could not be started");
                Err(OpenFailed)
            }
        }
    }
}

/// Records what it was asked to open (tests, `test-util`; synthetic tickets only).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct RecordingOpener(pub Mutex<Vec<String>>);

#[cfg(any(test, feature = "test-util"))]
impl UrlOpener for RecordingOpener {
    fn open(&self, url: &str) -> Result<(), OpenFailed> {
        self.0.lock().map_err(|_| OpenFailed)?.push(url.to_owned());
        Ok(())
    }
}
