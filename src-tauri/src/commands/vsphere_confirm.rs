//! Rust-native confirmations of the vSphere commands (ADR-0015 §3–4): power actions, the
//! TOFU certificate prompt and the VMRC hand-off. The dialog is `tauri-plugin-dialog`'s Rust
//! API (a callback and a `oneshot`, as `sftp_pick_local`), parented to the main window; the
//! `WebView` has no dialog permission, so an IPC call alone can never answer one. While it is
//! open the auto-lock ignores the main window's focus loss (the `dialog_open` exemption,
//! bounded by N-20). Tests inject [`FixedConfirm`].
//!
//! Review 6 M-16: "Cancel" is the **first** button (`rfd` sets no default, every OS defaults
//! to the first one, so Return refuses), the result is mapped by label only, and every ask
//! goes through the [`ConfirmGate`] (one dialog at a time, cool-down after a cancelled
//! destructive one).
//!
//! [`UrlOpener`] hands a VMRC ticket URL to the OS URL handler with a fixed argv (no shell):
//! `open` (macOS), `xdg-open` (Linux), `rundll32 url.dll,FileProtocolHandler` (Windows).

#[cfg(any(test, feature = "test-util"))]
use std::sync::Mutex;

use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;

use crate::autolock::AutoLock;
use crate::confirm_gate::{ConfirmGate, Scope};
use crate::error::IpcResult;

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
        use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
        let kind = if ask.warning { MessageDialogKind::Warning } else { MessageDialogKind::Info };
        let mut builder = self
            .app
            .dialog()
            .message(ask.text)
            .title(ask.title)
            .kind(kind)
            .buttons(buttons(&ask.ok));
        if let Some(main) = self.app.get_webview_window(crate::navigation::MAIN_WINDOW) {
            builder = builder.parent(&main);
        }
        let ok = ask.ok;
        builder.show_with_result(move |r| reply(confirmed(&r, &ok)));
    }
}

/// The refusing button first (M-16): Return / the OS default refuses.
pub const CANCEL: &str = "Cancel";

fn buttons(ok: &str) -> tauri_plugin_dialog::MessageDialogButtons {
    tauri_plugin_dialog::MessageDialogButtons::OkCancelCustom(CANCEL.to_owned(), ok.to_owned())
}

/// Only the button carrying the confirming label confirms; positions (`Ok`, `Yes`) never do.
pub fn confirmed(r: &tauri_plugin_dialog::MessageDialogResult, ok: &str) -> bool {
    matches!(r, tauri_plugin_dialog::MessageDialogResult::Custom(s) if s == ok && s != CANCEL)
}

/// The button labels in dialog order (tests pin "Cancel" first).
pub fn button_order(ok: &str) -> [String; 2] {
    match buttons(ok) {
        tauri_plugin_dialog::MessageDialogButtons::OkCancelCustom(a, b) => [a, b],
        _ => [String::new(), String::new()],
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

    /// Ask and wait for the answer, through `gate` (`confirm.busy` / `confirm.cooldown`
    /// without a dialog).
    pub async fn ask(&self, gate: &ConfirmGate, scope: Scope<'_>, ask: Ask) -> IpcResult<bool> {
        let slot = gate.acquire(scope)?;
        let yes = confirm(self.confirm, self.autolock, ask).await;
        slot.done(yes);
        Ok(yes)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mooring_audit::AuditLog;
    use tauri_plugin_dialog::MessageDialogResult as Res;

    use super::*;
    use crate::commands::sync_gate::{self, TrustAnswer};

    #[test]
    fn cancel_is_the_first_button_everywhere() {
        assert_eq!(button_order("Power off"), ["Cancel".to_owned(), "Power off".to_owned()]);
        match sync_gate::trust_buttons() {
            tauri_plugin_dialog::MessageDialogButtons::YesNoCancelCustom(a, b, c) => {
                assert_eq!((a.as_str(), b.as_str(), c.as_str()), (CANCEL, sync_gate::ONCE, sync_gate::PIN));
            }
            other => panic!("unexpected buttons: {other:?}"),
        }
        assert_eq!(sync_gate::ONCE, "Trust once (this sync only)");
    }

    #[test]
    fn results_are_mapped_by_label_never_by_position() {
        assert!(confirmed(&Res::Custom("Power off".into()), "Power off"));
        for r in [Res::Ok, Res::Yes, Res::No, Res::Cancel, Res::Custom("Cancel".into()), Res::Custom("Reset".into())] {
            assert!(!confirmed(&r, "Power off"), "{r:?}");
        }
        assert!(!confirmed(&Res::Custom("Cancel".into()), "Cancel"), "the refusing label never confirms");
        assert_eq!(sync_gate::trust_answer(&Res::Custom(sync_gate::PIN.into())), TrustAnswer::Pin);
        assert_eq!(sync_gate::trust_answer(&Res::Custom(sync_gate::ONCE.into())), TrustAnswer::Once);
        for r in [Res::Yes, Res::No, Res::Ok, Res::Cancel, Res::Custom("Cancel".into())] {
            assert_eq!(sync_gate::trust_answer(&r), TrustAnswer::Reject, "{r:?}");
        }
    }

    /// Holds the reply until the test releases it (a dialog that stays open).
    #[derive(Default)]
    struct Parked(Mutex<Option<ConfirmReply>>);

    impl Confirm for Parked {
        fn ask(&self, _ask: Ask, reply: ConfirmReply) {
            *self.0.lock().expect("lock") = Some(reply);
        }
    }

    fn ask() -> Ask {
        Ask { title: "t".into(), text: "x".into(), ok: "Power off".into(), warning: true }
    }

    #[tokio::test]
    async fn one_native_dialog_at_a_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::open(dir.path().join("audit.jsonl")).expect("audit");
        let gate = Arc::new(ConfirmGate::new(Arc::new(Mutex::new(log))));
        let parked = Arc::new(Parked::default());
        let scope = Scope { kind: "vsphere_power", target: "c/vm-1", destructive: true };
        let (g, p) = (Arc::clone(&gate), Arc::clone(&parked));
        let first = tokio::spawn(async move { Prompt::new(&*p).ask(&g, scope, ask()).await });
        while parked.0.lock().expect("lock").is_none() {
            tokio::task::yield_now().await;
        }
        assert!(gate.is_open());
        let yes = FixedConfirm::new(true);
        let e = Prompt::new(&yes).ask(&gate, Scope { kind: "vmrc", target: "c/vm-2", destructive: false }, ask()).await;
        assert_eq!(e.expect_err("second dialog").code, "confirm.busy");
        assert!(yes.asked().is_empty(), "refused without a dialog");
        let reply = parked.0.lock().expect("lock").take().expect("parked reply");
        reply(false);
        assert!(!first.await.expect("join").expect("asked"));
        assert!(!gate.is_open());
        // Cancelled destructive: the same target cools down, another one is free.
        assert_eq!(Prompt::new(&yes).ask(&gate, scope, ask()).await.expect_err("cool-down").code, "confirm.cooldown");
        assert!(Prompt::new(&yes).ask(&gate, Scope { target: "c/vm-2", ..scope }, ask()).await.expect("other vm"));
    }
}
