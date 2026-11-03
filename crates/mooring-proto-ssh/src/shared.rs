//! State shared between the `SshSession` front, the driver task and the russh handler.
//!
//! [`PromptBroker`] is how a question raised deep inside the handshake (TOFU, a
//! keyboard-interactive prompt) reaches the UI as `SessionEvent::Prompt` and comes back as
//! `SessionInput::Answer` without the protocol code blocking on UI code (ADR-0004).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use mooring_core::session::SessionEvent;
use secrecy::SecretString;
use tokio::sync::{mpsc, oneshot};

use crate::audit::AuditLog;

/// Longest prompt text shown to the user, in characters.
pub(crate) const MAX_PROMPT_CHARS: usize = 256;

/// Strip control characters (terminal escape injection) and cap the length of
/// server-supplied text before it is shown.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(MAX_PROMPT_CHARS).collect()
}

type Pending = Option<(u32, oneshot::Sender<SecretString>)>;

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

    /// Emit a prompt and wait for its answer. `None` when the session is closing.
    pub(crate) async fn ask(
        &self,
        events: &mpsc::Sender<SessionEvent>,
        message: String,
        secret: bool,
    ) -> Option<SecretString> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.slot();
            if self.shut.load(Ordering::Acquire) {
                return None;
            }
            *slot = Some((id, tx));
        }
        events.send(SessionEvent::Prompt { id, message, secret }).await.ok()?;
        rx.await.ok()
    }

    /// Deliver an answer. `false` when no prompt with this id is outstanding.
    pub(crate) fn answer(&self, id: u32, text: SecretString) -> bool {
        let mut slot = self.slot();
        match slot.take() {
            Some((pending, tx)) if pending == id => tx.send(text).is_ok(),
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
        let task = tokio::spawn(async move { b2.ask(&tx, "q".into(), true).await });
        let Some(SessionEvent::Prompt { id, secret, .. }) = rx.recv().await else {
            panic!("expected prompt");
        };
        assert!(secret);
        assert!(!broker.answer(id + 1, SecretString::from("no")));
        assert!(broker.answer(id, SecretString::from("yes")));
        let got = task.await.expect("join").expect("answered");
        assert_eq!(got.expose_secret(), "yes");
        assert!(!broker.answer(id, SecretString::from("again")));
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_and_future_prompts() {
        let (tx, mut rx) = mpsc::channel(4);
        let broker = PromptBroker::default();
        let b2 = broker.clone();
        let tx2 = tx.clone();
        let task = tokio::spawn(async move { b2.ask(&tx2, "q".into(), false).await });
        let _ = rx.recv().await;
        broker.shutdown();
        assert!(task.await.expect("join").is_none());
        assert!(broker.ask(&tx, "q2".into(), false).await.is_none());
    }
}
