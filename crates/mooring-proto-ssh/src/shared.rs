//! State shared between the `SshSession` front, the driver task and the russh handler.
//!
//! [`PromptBroker`] is how a question raised deep inside the handshake (TOFU, a
//! keyboard-interactive prompt) reaches the UI as `SessionEvent::Prompt` and comes back as
//! `SessionInput::Answer` without the protocol code blocking on UI code (ADR-0004).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use mooring_core::session::{CloseCode, PromptAccount, PromptPurpose, SessionEvent};
use secrecy::SecretString;
use tokio::sync::{mpsc, oneshot};

use crate::audit::AuditLog;
use crate::forward::ForwardRegistry;
use crate::sftp::SftpSlot;

/// Longest prompt text shown to the user, in characters.
pub(crate) const MAX_PROMPT_CHARS: usize = 256;

/// Strip control characters (terminal escape injection) and cap the length of
/// server-supplied text before it is shown.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(MAX_PROMPT_CHARS).collect()
}

/// An answer to a prompt: free text (TOFU, keyboard-interactive) or the sign-in form of a
/// `prompt` credential. Never printed.
pub(crate) enum Reply {
    Text(SecretString),
    Credential(CredentialReply),
}

/// The connect-time sign-in form (`SessionInput::CredentialAnswer`).
pub(crate) struct CredentialReply {
    pub(crate) username: String,
    pub(crate) domain: Option<String>,
    pub(crate) password: SecretString,
}

impl std::fmt::Debug for CredentialReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialReply").field("username", &self.username).finish_non_exhaustive()
    }
}

/// Which answer shape the open prompt expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Text,
    Credential,
}

type Pending = Option<(u32, Expect, oneshot::Sender<Reply>)>;

/// One outstanding question at a time, answered by id.
#[derive(Clone, Default)]
pub struct PromptBroker {
    next_id: Arc<AtomicU32>,
    pending: Arc<Mutex<Pending>>,
    shut: Arc<AtomicBool>,
}

/// First prompt id of a hop chain's broker (ADR-0025): hop prompts and the target session's
/// prompts share one `Answer { id }` space, so the two counters must not overlap.
pub const HOP_PROMPT_ID_BASE: u32 = 1 << 24;

impl std::fmt::Debug for PromptBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptBroker")
            .field("shut", &self.shut.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PromptBroker {
    /// A broker whose ids start after `base` (see [`HOP_PROMPT_ID_BASE`]).
    #[must_use]
    pub fn starting_after(base: u32) -> Self {
        Self { next_id: Arc::new(AtomicU32::new(base)), ..Self::default() }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn raise(
        &self,
        events: &mpsc::Sender<SessionEvent>,
        event: impl FnOnce(u32) -> SessionEvent,
        expect: Expect,
    ) -> Option<Reply> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.slot();
            if self.shut.load(Ordering::Acquire) {
                return None;
            }
            *slot = Some((id, expect, tx));
        }
        events.send(event(id)).await.ok()?;
        rx.await.ok()
    }

    /// A fresh id from the prompt id space, for informational events (ADR-0024 touch banner)
    /// that are never answered.
    pub(crate) fn next_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    /// Emit a text prompt and wait for its answer. `None` when the session is closing.
    /// `hop` tags a jump host's prompt (ADR-0025), `None` is the target.
    pub(crate) async fn ask(
        &self,
        events: &mpsc::Sender<SessionEvent>,
        message: String,
        secret: bool,
        purpose: PromptPurpose,
        hop: Option<u8>,
    ) -> Option<SecretString> {
        let event = |id| SessionEvent::Prompt {
            id,
            message,
            secret,
            purpose,
            account: None,
            certificate: None,
            hop,
        };
        match self.raise(events, event, Expect::Text).await? {
            Reply::Text(t) => Some(t),
            Reply::Credential(_) => None,
        }
    }

    /// Emit the sign-in form of a `prompt` credential and wait for it.
    pub(crate) async fn ask_credential(
        &self,
        events: &mpsc::Sender<SessionEvent>,
        account: PromptAccount,
        hop: Option<u8>,
    ) -> Option<CredentialReply> {
        let event = |id| SessionEvent::Prompt {
            id,
            message: "Sign in".to_owned(),
            secret: true,
            purpose: PromptPurpose::Credential,
            account: Some(account),
            certificate: None,
            hop,
        };
        match self.raise(events, event, Expect::Credential).await? {
            Reply::Credential(c) => Some(c),
            Reply::Text(_) => None,
        }
    }

    /// Deliver an answer. `false` when no prompt with this id is outstanding or the answer has
    /// the wrong shape (a text answer to the sign-in form or the reverse).
    pub(crate) fn answer(&self, id: u32, reply: Reply) -> bool {
        let mut slot = self.slot();
        match slot.take() {
            Some((pending, expect, tx))
                if pending == id
                    && matches!(
                        (expect, &reply),
                        (Expect::Text, Reply::Text(_)) | (Expect::Credential, Reply::Credential(_))
                    ) =>
            {
                tx.send(reply).is_ok()
            }
            other => {
                *slot = other;
                false
            }
        }
    }

    /// Deliver a free-text answer (TOFU `yes`/`no`, keyboard-interactive). Public for the
    /// Tauri layer's hop-chain phase (ADR-0025), where the chain has no session yet.
    pub fn answer_text(&self, id: u32, text: SecretString) -> bool {
        self.answer(id, Reply::Text(text))
    }

    /// Deliver a sign-in form answer (`prompt` credential of a hop).
    pub fn answer_credential(
        &self,
        id: u32,
        username: String,
        domain: Option<String>,
        password: SecretString,
    ) -> bool {
        self.answer(id, Reply::Credential(CredentialReply { username, domain, password }))
    }

    /// Cancel the outstanding prompt and refuse new ones.
    pub fn shutdown(&self) {
        let mut slot = self.slot();
        self.shut.store(true, Ordering::Release);
        slot.take();
    }
}

/// Shared between front, driver and handler.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) events: mpsc::Sender<SessionEvent>,
    pub(crate) broker: PromptBroker,
    pub(crate) audit: AuditLog,
    pub(crate) forwards: ForwardRegistry,
    pub(crate) sftp: SftpSlot,
    /// ADR-0025: the hop this connection is (0-based), `None` for the target session.
    pub(crate) hop: Option<u8>,
    reason: Mutex<Option<(CloseCode, String)>>,
    peer: Mutex<Option<String>>,
    closing: AtomicBool,
}

impl Shared {
    pub(crate) fn new(events: mpsc::Sender<SessionEvent>) -> Self {
        Self::with_parts(events, PromptBroker::default(), AuditLog::default(), None)
    }

    /// A `Shared` for one hop of a chain: the chain's event channel, broker and audit buffer,
    /// tagged with the hop index so prompts and trust events name the hop.
    pub(crate) fn with_parts(
        events: mpsc::Sender<SessionEvent>,
        broker: PromptBroker,
        audit: AuditLog,
        hop: Option<u8>,
    ) -> Self {
        Self {
            events,
            broker,
            audit,
            forwards: ForwardRegistry::default(),
            sftp: SftpSlot::default(),
            hop,
            reason: Mutex::new(None),
            peer: Mutex::new(None),
            closing: AtomicBool::new(false),
        }
    }

    /// Record why the handshake stopped (first reason wins). Must be safe to show.
    pub(crate) fn set_reason(&self, code: CloseCode, reason: impl Into<String>) {
        let mut slot = self.reason.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some((code, reason.into()));
        }
    }

    pub(crate) fn take_reason(&self) -> Option<(CloseCode, String)> {
        self.reason.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    pub(crate) fn set_peer(&self, peer: String) {
        *self.peer.lock().unwrap_or_else(PoisonError::into_inner) = Some(peer);
    }

    pub(crate) fn peer(&self) -> Option<String> {
        self.peer.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub(crate) fn begin_close(&self) {
        self.closing.store(true, Ordering::Release);
        self.broker.shutdown();
        self.release_channels();
    }

    /// Close every forward and the SFTP session. Called when the session closes for any
    /// reason (user close, remote end, connection loss). Idempotent.
    pub(crate) fn release_channels(&self) {
        self.forwards.close_all(&self.audit);
        self.sftp.close();
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn sanitize_strips_escapes_and_caps() {
        assert_eq!(sanitize("Pass\x1b[31mword:\r\n"), "Pass[31mword:");
        assert_eq!(sanitize(&"x".repeat(1000)).len(), MAX_PROMPT_CHARS);
    }

    #[tokio::test]
    async fn broker_round_trip_and_wrong_id() {
        let (tx, mut rx) = mpsc::channel(4);
        let broker = PromptBroker::default();
        let b2 = broker.clone();
        let kbd = PromptPurpose::KeyboardInteractive;
        let task = tokio::spawn(async move { b2.ask(&tx, "q".into(), true, kbd, Some(1)).await });
        let Some(SessionEvent::Prompt { id, secret, purpose, .. }) = rx.recv().await else {
            panic!("expected prompt");
        };
        assert!(secret);
        assert_eq!(purpose, kbd);
        let text = |s: &str| Reply::Text(SecretString::from(s.to_owned()));
        assert!(!broker.answer(id + 1, text("no")));
        let form = CredentialReply {
            username: "u".into(),
            domain: None,
            password: SecretString::from("p".to_owned()),
        };
        assert!(!broker.answer(id, Reply::Credential(form)), "wrong shape is refused");
        assert!(broker.answer(id, text("yes")));
        let got = task.await.expect("join").expect("answered");
        assert_eq!(got.expose_secret(), "yes");
        assert!(!broker.answer(id, text("again")));
    }

    #[tokio::test]
    async fn credential_form_round_trip() {
        let (tx, mut rx) = mpsc::channel(4);
        let broker = PromptBroker::default();
        let b2 = broker.clone();
        let account = PromptAccount { needs_username: true, ..PromptAccount::default() };
        let task = tokio::spawn(async move { b2.ask_credential(&tx, account, None).await });
        let Some(SessionEvent::Prompt { id, purpose, account, .. }) = rx.recv().await else {
            panic!("expected prompt");
        };
        assert_eq!(purpose, PromptPurpose::Credential);
        assert!(account.is_some_and(|a| a.needs_username));
        assert!(!broker.answer(id, Reply::Text(SecretString::from("x".to_owned()))));
        let form = CredentialReply {
            username: "bob".into(),
            domain: Some("CORP".into()),
            password: SecretString::from("p".to_owned()),
        };
        assert!(broker.answer(id, Reply::Credential(form)));
        let got = task.await.expect("join").expect("answered");
        assert_eq!((got.username.as_str(), got.domain.as_deref()), ("bob", Some("CORP")));
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_and_future_prompts() {
        let (tx, mut rx) = mpsc::channel(4);
        let broker = PromptBroker::default();
        let b2 = broker.clone();
        let tx2 = tx.clone();
        let other = PromptPurpose::Other;
        let task = tokio::spawn(async move { b2.ask(&tx2, "q".into(), false, other, None).await });
        let _ = rx.recv().await;
        broker.shutdown();
        assert!(task.await.expect("join").is_none());
        assert!(broker.ask(&tx, "q2".into(), false, other, None).await.is_none());
    }

    #[tokio::test]
    async fn hop_broker_ids_start_above_the_base_and_carry_the_hop() {
        let (tx, mut rx) = mpsc::channel(4);
        let broker = PromptBroker::starting_after(HOP_PROMPT_ID_BASE);
        let b2 = broker.clone();
        let task = tokio::spawn(async move {
            b2.ask(&tx, "q".into(), false, PromptPurpose::HostKeyTrust, Some(0)).await
        });
        let Some(SessionEvent::Prompt { id, hop, .. }) = rx.recv().await else { panic!("prompt") };
        assert!(id > HOP_PROMPT_ID_BASE);
        assert_eq!(hop, Some(0));
        assert!(broker.answer_text(id, SecretString::from("yes".to_owned())));
        assert!(task.await.expect("join").is_some());
    }
}
