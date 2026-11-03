//! State shared between the `SshSession` front, the driver task and the russh handler.
//!
//! [`PromptBroker`] is how a question raised deep inside the handshake (TOFU, a
//! keyboard-interactive prompt) reaches the UI as `SessionEvent::Prompt` and comes back as
//! `SessionInput::Answer` without the protocol code blocking on UI code (ADR-0004).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use mooring_core::session::{PromptAccount, PromptPurpose, SessionEvent};
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
pub(crate) struct PromptBroker {
    next_id: Arc<AtomicU32>,
    pending: Arc<Mutex<Pending>>,
    shut: Arc<AtomicBool>,
}

impl std::fmt::Debug for PromptBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptBroker")
            .field("shut", &self.shut.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PromptBroker {
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

    /// Emit a text prompt and wait for its answer. `None` when the session is closing.
    pub(crate) async fn ask(
        &self,
        events: &mpsc::Sender<SessionEvent>,
        message: String,
        secret: bool,
        purpose: PromptPurpose,
    ) -> Option<SecretString> {
        let event = |id| SessionEvent::Prompt { id, message, secret, purpose, account: None };
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
    ) -> Option<CredentialReply> {
        let event = |id| SessionEvent::Prompt {
            id,
            message: "Sign in".to_owned(),
            secret: true,
            purpose: PromptPurpose::Credential,
            account: Some(account),
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

    /// Cancel the outstanding prompt and refuse new ones.
    pub(crate) fn shutdown(&self) {
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
    reason: Mutex<Option<String>>,
    peer: Mutex<Option<String>>,
    closing: AtomicBool,
}

impl Shared {
    pub(crate) fn new(events: mpsc::Sender<SessionEvent>) -> Self {
        Self {
            events,
            broker: PromptBroker::default(),
            audit: AuditLog::default(),
            forwards: ForwardRegistry::default(),
            sftp: SftpSlot::default(),
            reason: Mutex::new(None),
            peer: Mutex::new(None),
            closing: AtomicBool::new(false),
        }
    }

    /// Record why the handshake stopped (first reason wins). Must be safe to show.
    pub(crate) fn set_reason(&self, reason: impl Into<String>) {
        let mut slot = self.reason.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(reason.into());
        }
    }

    pub(crate) fn take_reason(&self) -> Option<String> {
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
        let task = tokio::spawn(async move { b2.ask(&tx, "q".into(), true, kbd).await });
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
        let task = tokio::spawn(async move { b2.ask_credential(&tx, account).await });
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
        let task = tokio::spawn(async move { b2.ask(&tx2, "q".into(), false, other).await });
        let _ = rx.recv().await;
        broker.shutdown();
        assert!(task.await.expect("join").is_none());
        assert!(broker.ask(&tx, "q2".into(), false, other).await.is_none());
    }
}
