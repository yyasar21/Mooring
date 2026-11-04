//! The sync Gate (ADR-0017 §4, A3 S2): Rust-native dialogs for the S3 endpoint certificate
//! (`CertProtocol::Sync`, `known_sync_certs`) and for the destructive fork resolution.
//!
//! The `WebView` never answers either question. `mooring-http` refuses an unknown leaf with
//! `http.trust_prompt`; the Gate asks "Trust and remember" (pin through
//! `KnownCerts::add_and_save`, the single pin writer) / "Trust once" (`trusted_once` for this
//! run) / "Cancel", then the run is retried once. Background runs pass no prompter and report
//! `http.trust_prompt` in `sync_status` instead of opening a dialog unasked. While a dialog is
//! open the auto-lock ignores focus loss (`AutoLock::dialog_guard`, bounded as for the SFTP
//! pick).
//!
//! Review 6 M-16: "Cancel" is the first (default) button of both dialogs, results are mapped
//! by label only, and every prompt holds a `ConfirmGate` slot (`confirm.busy`; a cancelled
//! trust-and-remember or fork resolution cools the same target down). N-45: "Trust once" says
//! it covers this sync only.

use std::future::Future;

use mooring_core::known_certs::{host_key, CertificateInfo, KnownCerts};
use mooring_http::HttpError;
use mooring_sync::SyncError;
use tauri::{AppHandle, Manager, Runtime};
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::autolock::AutoLock;
use crate::commands::vsphere_confirm::{confirmed, CANCEL};
pub use crate::confirm_gate::Scope;
use crate::confirm_gate::ConfirmGate;
use crate::error::IpcError;
use crate::session_audit::cert;
use crate::state::AppState;

/// The user's answer to a certificate prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnswer {
    /// Pin the leaf in `known_sync_certs`.
    Pin,
    /// Trust it for this run only.
    Once,
    /// Refuse.
    Reject,
}

/// Something that asks the user (a native dialog; tests script it). Each method calls
/// `reply` exactly once, possibly from another thread.
pub trait SyncPrompter: Send + Sync {
    /// Certificate prompt for `host` (`host:port`).
    fn trust(&self, host: &str, info: &CertificateInfo, reply: Box<dyn FnOnce(TrustAnswer) + Send>);
    /// A yes/no confirmation; `ok` names the destructive button.
    fn confirm(&self, title: &str, message: &str, ok: &str, reply: Box<dyn FnOnce(bool) + Send>);
}

/// The production prompter: `tauri-plugin-dialog` message boxes parented to the main window.
pub struct DialogPrompter<R: Runtime> {
    /// App handle.
    pub app: AppHandle<R>,
}

impl<R: Runtime> std::fmt::Debug for DialogPrompter<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialogPrompter").finish_non_exhaustive()
    }
}

/// Pin button label.
pub const PIN: &str = "Trust and remember";
/// Trust-once button label (N-45: names its scope).
pub const ONCE: &str = "Trust once (this sync only)";

/// The trust dialog's buttons in dialog order: the refusing one first (M-16).
pub fn trust_buttons() -> tauri_plugin_dialog::MessageDialogButtons {
    tauri_plugin_dialog::MessageDialogButtons::YesNoCancelCustom(CANCEL.into(), ONCE.into(), PIN.into())
}

/// Map a trust dialog result by label only (never by position).
pub fn trust_answer(r: &tauri_plugin_dialog::MessageDialogResult) -> TrustAnswer {
    use tauri_plugin_dialog::MessageDialogResult as Res;
    match r {
        Res::Custom(s) if s == PIN => TrustAnswer::Pin,
        Res::Custom(s) if s == ONCE => TrustAnswer::Once,
        _ => TrustAnswer::Reject,
    }
}

impl<R: Runtime> DialogPrompter<R> {
    fn builder(&self, title: &str, message: String) -> tauri_plugin_dialog::MessageDialogBuilder<R> {
        use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
        let mut b = self.app.dialog().message(message).title(title).kind(MessageDialogKind::Warning);
        if let Some(main) = self.app.get_webview_window(crate::navigation::MAIN_WINDOW) {
            b = b.parent(&main);
        }
        b
    }
}

impl<R: Runtime> SyncPrompter for DialogPrompter<R> {
    fn trust(&self, host: &str, info: &CertificateInfo, reply: Box<dyn FnOnce(TrustAnswer) + Send>) {
        let text = format!(
            "The sync storage {host} presented a certificate Mooring does not trust yet.\n\n\
             Subject: {}\nIssuer: {}\nFingerprint: {}\n\nOnly trust it if you can verify the \
             fingerprint with the storage administrator.",
            info.subject,
            info.issuer,
            info.display_fingerprint()
        );
        self.builder("Untrusted sync storage certificate", text)
            .buttons(trust_buttons())
            .show_with_result(move |r| reply(trust_answer(&r)));
    }

    fn confirm(&self, title: &str, message: &str, ok: &str, reply: Box<dyn FnOnce(bool) + Send>) {
        use tauri_plugin_dialog::MessageDialogButtons as B;
        let ok = ok.to_owned();
        self.builder(title, message.to_owned())
            .buttons(B::OkCancelCustom(CANCEL.into(), ok.clone()))
            .show_with_result(move |r| reply(confirmed(&r, &ok)));
    }
}

/// A prompter with fixed answers (tests, `test-util`).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct ScriptedPrompter {
    /// Answer to every certificate prompt.
    pub trust: TrustAnswer,
    /// Answer to every confirmation.
    pub confirm: bool,
    /// Prompts shown so far (`trust:<host>` / `confirm:<title>`).
    pub asked: std::sync::Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-util"))]
impl ScriptedPrompter {
    /// Answers `trust` and `confirm`.
    pub fn new(trust: TrustAnswer, confirm: bool) -> Self {
        Self { trust, confirm, asked: std::sync::Mutex::default() }
    }

    /// Prompts shown so far.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().map(|a| a.clone()).unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl SyncPrompter for ScriptedPrompter {
    fn trust(&self, host: &str, _info: &CertificateInfo, reply: Box<dyn FnOnce(TrustAnswer) + Send>) {
        if let Ok(mut a) = self.asked.lock() {
            a.push(format!("trust:{host}"));
        }
        reply(self.trust);
    }
    fn confirm(&self, title: &str, _message: &str, _ok: &str, reply: Box<dyn FnOnce(bool) + Send>) {
        if let Ok(mut a) = self.asked.lock() {
            a.push(format!("confirm:{title}"));
        }
        reply(self.confirm);
    }
}

/// Ask for a destructive confirmation (`scope`) with the gate slot and the auto-lock dialog
/// exemption held. `confirm.busy` / `confirm.cooldown` refuse without a dialog.
pub async fn confirm(
    gate: &ConfirmGate,
    scope: Scope<'_>,
    prompter: &dyn SyncPrompter,
    autolock: Option<&AutoLock>,
    title: &str,
    message: &str,
    ok: &str,
) -> Result<bool, IpcError> {
    let slot = gate.acquire(scope)?;
    let _open = autolock.map(AutoLock::dialog_guard);
    let (tx, rx) = oneshot::channel();
    prompter.confirm(title, message, ok, Box::new(move |yes| {
        let _ = tx.send(yes);
    }));
    let yes = rx.await.unwrap_or(false);
    slot.done(yes);
    Ok(yes)
}

async fn ask_trust(
    gate: &ConfirmGate,
    prompter: &dyn SyncPrompter,
    autolock: Option<&AutoLock>,
    host: &str,
    info: &CertificateInfo,
) -> Result<TrustAnswer, IpcError> {
    let slot = gate.acquire(Scope { kind: "sync_trust", target: host, destructive: true })?;
    let _open = autolock.map(AutoLock::dialog_guard);
    let (tx, rx) = oneshot::channel();
    prompter.trust(host, info, Box::new(move |a| {
        let _ = tx.send(a);
    }));
    let answer = rx.await.unwrap_or(TrustAnswer::Reject);
    slot.done(answer != TrustAnswer::Reject);
    Ok(answer)
}

/// Why a gated step failed: an app error (config, credential) or an engine error.
#[derive(Debug)]
pub enum Failure {
    /// Command-layer error.
    Ipc(IpcError),
    /// Engine / transport error.
    Sync(SyncError),
}

impl From<IpcError> for Failure {
    fn from(e: IpcError) -> Self {
        Self::Ipc(e)
    }
}

impl From<SyncError> for Failure {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}

impl From<Failure> for IpcError {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Ipc(e) => e,
            Failure::Sync(e) => crate::commands::sync::sync_error(&e),
        }
    }
}

/// Run `op`; on `http.trust_prompt` ask through `prompter` (if any) and retry once with the
/// pin written or with `trusted_once`. Every decision is audited (`cert_decision`, protocol
/// `sync`).
pub async fn with_trust<T, F, Fut>(
    state: &AppState,
    prompter: Option<&dyn SyncPrompter>,
    autolock: Option<&AutoLock>,
    mut op: F,
) -> Result<T, Failure>
where
    F: FnMut(Option<[u8; 32]>) -> Fut,
    Fut: Future<Output = Result<T, Failure>>,
{
    let first = op(None).await;
    let (Err(Failure::Sync(SyncError::Http(HttpError::TrustPrompt(d)))), Some(p)) =
        (&first, prompter)
    else {
        return first;
    };
    let d = d.clone();
    let host = host_key(&d.host, d.port);
    let fp = d.info.display_fingerprint();
    let audit = |decision: &str| state.audit(cert("sync".into(), host.clone(), fp.clone(), decision, None));
    let once = match ask_trust(&state.confirm, p, autolock, &host, &d.info).await? {
        TrustAnswer::Reject => {
            audit("rejected");
            return first;
        }
        TrustAnswer::Once => {
            audit("trusted_once");
            Some(d.fingerprint)
        }
        TrustAnswer::Pin => {
            let path = state.data_dir.join(d.protocol.file_name());
            match KnownCerts::add_and_save(&path, &d.host, d.port, &d.fingerprint, OffsetDateTime::now_utc()) {
                Ok(()) => {
                    audit("accepted");
                    None
                }
                Err(e) => {
                    tracing::warn!(error = %e, "sync certificate pin not stored; trusted for this run");
                    audit("accepted_session_only");
                    Some(d.fingerprint)
                }
            }
        }
    };
    op(once).await
}
