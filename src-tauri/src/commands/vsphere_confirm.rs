//! Rust-native confirmations of the vSphere commands (ADR-0015 §3–4): power actions, the
//! TOFU certificate prompt and the VMRC hand-off. The dialog is `tauri-plugin-dialog`'s Rust
//! API (a callback and a `oneshot`, as `sftp_pick_local`), parented to the main window; the
//! `WebView` has no dialog permission, so an IPC call alone can never answer one. While it is
//! open the auto-lock ignores the main window's focus loss (the `dialog_open` exemption,
//! bounded by N-20). Tests inject [`FixedConfirm`].
//!
//! Review 6 M-16 / 6b B-6: every confirmation has **three** buttons. The first slot (the OS
//! default, Return) and the plugin's *cancel slot* (Escape, the close box, Alt+F4, Cmd+W) carry
//! refusing labels; the confirming label sits in the middle. `tauri-plugin-dialog` rewrites
//! rfd's positional `Cancel` into the cancel-slot label on every desktop OS, so a dismissed
//! dialog arrives as [`NOT_NOW`] and refuses. Results are mapped by label only, and every ask
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

/// The refusing label of the first slot (M-16): Return / the OS default refuses.
pub const CANCEL: &str = "Cancel";
/// The refusing label of the cancel slot (B-6): Escape / close box / Alt+F4 / Cmd+W refuse.
/// Distinct text from [`CANCEL`] so a label never names two buttons.
pub const NOT_NOW: &str = "Not now";

/// `true` for the labels that refuse ([`CANCEL`], [`NOT_NOW`]).
pub fn refuses(label: &str) -> bool {
    label == CANCEL || label == NOT_NOW
}

/// The three slots of a confirmation: refusing / `ok` / refusing (B-6).
pub fn buttons(ok: &str) -> tauri_plugin_dialog::MessageDialogButtons {
    tauri_plugin_dialog::MessageDialogButtons::YesNoCancelCustom(CANCEL.to_owned(), ok.to_owned(), NOT_NOW.to_owned())
}

/// Only the button carrying the confirming label confirms; positions (`Ok`, `Yes`, `No`) and
/// the refusing labels never do.
pub fn confirmed(r: &tauri_plugin_dialog::MessageDialogResult, ok: &str) -> bool {
    matches!(r, tauri_plugin_dialog::MessageDialogResult::Custom(s) if s == ok && !refuses(s))
}

/// The first slot (OS default, Return) and the cancel slot (Escape / close) of `buttons`:
/// both must refuse (B-6 invariant). `None` for a shape the plugin has no cancel slot for.
pub fn slots(buttons: &tauri_plugin_dialog::MessageDialogButtons) -> Option<(String, String)> {
    use tauri_plugin_dialog::MessageDialogButtons as B;
    match buttons {
        B::YesNoCancelCustom(first, _, cancel) | B::OkCancelCustom(first, cancel) => {
            Some((first.clone(), cancel.clone()))
        }
        _ => None,
    }
}

/// The button labels in dialog order.
pub fn button_order(ok: &str) -> [String; 3] {
    match buttons(ok) {
        tauri_plugin_dialog::MessageDialogButtons::YesNoCancelCustom(a, b, c) => [a, b, c],
        _ => [String::new(), String::new(), String::new()],
    }
}

/// Replay of `tauri-plugin-dialog` 2.8.4 `desktop.rs:228-253`: the positional result rfd
/// returns is rewritten into the label of the slot at that position, on every desktop OS. rfd
/// returns the positional `Cancel` for Escape, the close box, Alt+F4 and Cmd+W. Tests and the
/// doubles feed OS results through this table.
#[cfg(any(test, feature = "test-util"))]
pub fn plugin_remap(
    r: tauri_plugin_dialog::MessageDialogResult,
    buttons: &tauri_plugin_dialog::MessageDialogButtons,
) -> tauri_plugin_dialog::MessageDialogResult {
    use tauri_plugin_dialog::{MessageDialogButtons as B, MessageDialogResult as R};
    match (r, buttons) {
        (R::Ok, B::OkCustom(s)) => R::Custom(s.clone()),
        (R::Ok, B::OkCancelCustom(ok, _)) => R::Custom(ok.clone()),
        (R::Yes, B::YesNoCancelCustom(yes, _, _)) => R::Custom(yes.clone()),
        (R::No, B::YesNoCancelCustom(_, no, _)) => R::Custom(no.clone()),
        // Escape / close box / Alt+F4 / Cmd+W: the cancel slot's label, whatever the shape.
        (R::Cancel, B::OkCancelCustom(_, cancel) | B::YesNoCancelCustom(_, _, cancel)) => {
            R::Custom(cancel.clone())
        }
        (r, _) => r,
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
    /// The answer (when `result` is `None`).
    pub answer: bool,
    /// An OS result instead: fed through [`plugin_remap`] and [`confirmed`] like a real dialog.
    pub result: Option<tauri_plugin_dialog::MessageDialogResult>,
    /// Questions asked so far.
    pub asked: Mutex<Vec<Ask>>,
}

#[cfg(any(test, feature = "test-util"))]
impl FixedConfirm {
    /// Answers `answer` to everything.
    pub fn new(answer: bool) -> Self {
        Self { answer, result: None, asked: Mutex::new(Vec::new()) }
    }

    /// Answers every question with the OS result `r` (positional, as rfd returns it).
    pub fn with_result(r: tauri_plugin_dialog::MessageDialogResult) -> Self {
        Self { answer: false, result: Some(r), asked: Mutex::new(Vec::new()) }
    }

    /// Questions asked so far.
    pub fn asked(&self) -> Vec<Ask> {
        self.asked.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Confirm for FixedConfirm {
    fn ask(&self, ask: Ask, reply: ConfirmReply) {
        let answer = match &self.result {
            Some(r) => confirmed(&plugin_remap(r.clone(), &buttons(&ask.ok)), &ask.ok),
            None => self.answer,
        };
        if let Ok(mut g) = self.asked.lock() {
            g.push(ask);
        }
        reply(answer);
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
    use crate::commands::sync_gate::{self, SyncPrompter, TrustAnswer};

    /// Every native confirmation's buttons, by name (B-6: the catalogue the invariant runs over).
    fn every_dialog() -> Vec<(&'static str, tauri_plugin_dialog::MessageDialogButtons, &'static str)> {
        vec![
            ("vsphere_power", buttons("Power off"), "Power off"),
            ("vmrc", buttons("Open"), "Open"),
            ("vsphere_trust", buttons("Trust"), "Trust"),
            ("sync_trust", sync_gate::trust_buttons(), sync_gate::ONCE),
            ("sync_remember", sync_gate::remember_buttons(), sync_gate::PIN),
            ("sync_fork", buttons("Discard and resolve"), "Discard and resolve"),
        ]
    }

    #[test]
    fn the_first_and_the_cancel_slot_refuse_in_every_dialog() {
        for (name, b, ok) in every_dialog() {
            let (first, cancel) = slots(&b).unwrap_or_else(|| panic!("{name}: no cancel slot"));
            assert!(refuses(&first), "{name}: first slot (Return) is {first:?}");
            assert!(refuses(&cancel), "{name}: cancel slot (Escape / close) is {cancel:?}");
            assert_ne!(first, cancel, "{name}: the two refusing labels must differ");
            assert!(!refuses(ok), "{name}: the confirming label {ok:?} must not refuse");
        }
        assert_eq!(button_order("Power off"), ["Cancel".to_owned(), "Power off".to_owned(), "Not now".to_owned()]);
        assert_eq!(sync_gate::ONCE, "Trust once (this sync only)");
    }

    /// The plugin's remap (`desktop.rs:228-253`) replayed: Escape / close / Alt+F4 / Cmd+W
    /// (rfd's positional `Cancel`) and Return (the first slot) refuse; only the middle button
    /// confirms.
    #[test]
    fn the_plugin_remap_of_escape_and_return_refuses() {
        for (name, b, ok) in every_dialog() {
            let escape = plugin_remap(Res::Cancel, &b);
            let default = plugin_remap(Res::Yes, &b);
            let click = plugin_remap(Res::No, &b);
            assert!(matches!(&escape, Res::Custom(s) if s == NOT_NOW), "{name}: {escape:?}");
            assert!(matches!(&default, Res::Custom(s) if s == CANCEL), "{name}: {default:?}");
            assert!(matches!(&click, Res::Custom(s) if s == ok), "{name}: {click:?}");
            match name {
                "sync_trust" => {
                    assert!(!sync_gate::trust_once(&escape) && !sync_gate::trust_once(&default));
                    assert!(sync_gate::trust_once(&click));
                }
                "sync_remember" => {
                    assert_eq!(sync_gate::remember_answer(&escape), TrustAnswer::Once, "Not now = trust once");
                    assert_eq!(sync_gate::remember_answer(&default), TrustAnswer::Reject);
                    assert_eq!(sync_gate::remember_answer(&click), TrustAnswer::Pin);
                }
                _ => {
                    assert!(!confirmed(&escape, ok) && !confirmed(&default, ok), "{name}");
                    assert!(confirmed(&click, ok), "{name}");
                }
            }
        }
    }

    #[test]
    fn results_are_mapped_by_label_never_by_position() {
        assert!(confirmed(&Res::Custom("Power off".into()), "Power off"));
        for r in [Res::Ok, Res::Yes, Res::No, Res::Cancel, Res::Custom("Cancel".into()), Res::Custom("Not now".into()), Res::Custom("Reset".into())] {
            assert!(!confirmed(&r, "Power off"), "{r:?}");
        }
        assert!(!confirmed(&Res::Custom("Cancel".into()), "Cancel"), "the refusing label never confirms");
        assert!(!confirmed(&Res::Custom("Not now".into()), "Not now"));
        assert!(sync_gate::trust_once(&Res::Custom(sync_gate::ONCE.into())));
        assert_eq!(sync_gate::remember_answer(&Res::Custom(sync_gate::PIN.into())), TrustAnswer::Pin);
        for r in [Res::Yes, Res::No, Res::Ok, Res::Cancel, Res::Custom("Cancel".into()), Res::Custom(sync_gate::PIN.into())] {
            assert!(!sync_gate::trust_once(&r), "{r:?}");
        }
        for r in [Res::Yes, Res::No, Res::Ok, Res::Cancel, Res::Custom("Cancel".into()), Res::Custom(sync_gate::ONCE.into())] {
            assert_eq!(sync_gate::remember_answer(&r), TrustAnswer::Reject, "{r:?}");
        }
    }

    #[test]
    fn the_doubles_take_os_results_through_the_plugin_remap() {
        let a = ask();
        for (r, want) in [(Res::Cancel, false), (Res::Yes, false), (Res::No, true), (Res::Ok, false)] {
            let (tx, rx) = std::sync::mpsc::channel();
            FixedConfirm::with_result(r.clone()).ask(a.clone(), Box::new(move |ok| tx.send(ok).expect("send")));
            assert_eq!(rx.recv().expect("reply"), want, "{r:?}");
        }
        let info = test_info();
        let p = sync_gate::ScriptedPrompter::with_results(Res::No, Res::Cancel);
        let (tx, rx) = std::sync::mpsc::channel();
        p.trust("s3.example.test:443", &info, Box::new(move |a| tx.send(a).expect("send")));
        assert_eq!(rx.recv().expect("reply"), TrustAnswer::Once, "click once, then Escape = once");
        assert_eq!(p.asked(), ["trust:s3.example.test:443", "remember:s3.example.test:443"]);
        let p = sync_gate::ScriptedPrompter::with_results(Res::Cancel, Res::No);
        let (tx, rx) = std::sync::mpsc::channel();
        p.trust("s3.example.test:443", &info, Box::new(move |a| tx.send(a).expect("send")));
        assert_eq!(rx.recv().expect("reply"), TrustAnswer::Reject, "Escape on dialog 1: no dialog 2");
        assert_eq!(p.asked(), ["trust:s3.example.test:443"]);
        let p = sync_gate::ScriptedPrompter::with_results(Res::No, Res::Yes);
        let (tx, rx) = std::sync::mpsc::channel();
        p.trust("s3.example.test:443", &info, Box::new(move |a| tx.send(a).expect("send")));
        assert_eq!(rx.recv().expect("reply"), TrustAnswer::Reject, "Return on dialog 2 refuses");
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

    fn test_info() -> mooring_core::known_certs::CertificateInfo {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        mooring_core::known_certs::CertificateInfo::new(b"der", "CN=s3.example.test", "CN=test", now, now, &[], Vec::new())
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
