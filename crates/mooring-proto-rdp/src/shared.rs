//! State shared by the `RdpSession` front and its driver task: the event channel, the prompt
//! broker (one open question at a time, answered by id), the audit sink and the close signal.
//! A question raised by the driver (certificate TOFU, sign-in form) reaches the UI as
//! `SessionEvent::Prompt` and returns as `SessionInput::Answer` / `CredentialAnswer`; the
//! driver never blocks a TLS handshake on it (ADR-0011: fail, prompt, reconnect).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};

use mooring_core::known_certs::CertificateInfo;
use mooring_core::session::{PromptAccount, PromptPurpose, SessionEvent};
use secrecy::SecretString;
use tokio::sync::{mpsc, oneshot, watch};

use crate::options::AuditSink;

/// Longest server-influenced text in a prompt, in characters.
pub(crate) const MAX_PROMPT_CHARS: usize = 256;

/// Strip control characters and cap length.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(MAX_PROMPT_CHARS).collect()
}

/// An answer. Never printed.
pub(crate) enum Reply {
    Text(SecretString),
    Credential { username: String, domain: Option<String>, password: SecretString },
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Text(_) => "Reply::Text(<redacted>)",
            Self::Credential { .. } => "Reply::Credential(<redacted>)",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Text,
    Credential,
}

type Pending = Option<(u32, Expect, oneshot::Sender<Reply>)>;

/// Front ↔ driver state.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) events: mpsc::Sender<SessionEvent>,
    pub(crate) audit: AuditSink,
    next_id: AtomicU32,
    pending: Mutex<Pending>,
    connected: AtomicBool,
    closing: watch::Sender<bool>,
}

impl Shared {
    pub(crate) fn new(events: mpsc::Sender<SessionEvent>, audit: AuditSink) -> Self {
        Self {
            events,
            audit,
            next_id: AtomicU32::new(0),
            pending: Mutex::new(None),
            connected: AtomicBool::new(false),
            closing: watch::channel(false).0,
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stop: wakes the driver wherever it waits and drops any open prompt.
    pub(crate) fn begin_close(&self) {
        self.closing.send_replace(true);
        self.slot().take();
    }

    pub(crate) fn is_closing(&self) -> bool {
        *self.closing.borrow()
    }

    /// Resolves once `begin_close` was called.
    pub(crate) async fn closed(&self) {
        let mut rx = self.closing.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    pub(crate) fn set_connected(&self) {
        self.connected.store(true, Ordering::Release);
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    async fn raise(
        &self,
        event: impl FnOnce(u32) -> SessionEvent,
        expect: Expect,
    ) -> Option<Reply> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.slot();
            if self.is_closing() {
                return None;
            }
            *slot = Some((id, expect, tx));
        }
        self.events.send(event(id)).await.ok()?;
        tokio::select! {
            r = rx => r.ok(),
            () = self.closed() => None,
        }
    }

    /// `certificate_trust` prompt; `Some(true)` only for an explicit `yes`.
    pub(crate) async fn ask_trust(&self, message: String, cert: CertificateInfo) -> Option<bool> {
        let event = |id| SessionEvent::Prompt {
            id,
            message,
            secret: false,
            purpose: PromptPurpose::CertificateTrust,
            account: None,
            certificate: Some(cert),
        };
        match self.raise(event, Expect::Text).await? {
            Reply::Text(t) => {
                use secrecy::ExposeSecret;
                Some(t.expose_secret().trim().eq_ignore_ascii_case("yes"))
            }
            Reply::Credential { .. } => Some(false),
        }
    }

    /// The sign-in form of a `prompt` credential.
    pub(crate) async fn ask_credential(&self, account: PromptAccount) -> Option<Reply> {
        let event = |id| SessionEvent::Prompt {
            id,
            message: "Sign in".to_owned(),
            secret: true,
            purpose: PromptPurpose::Credential,
            account: Some(account),
            certificate: None,
        };
        self.raise(event, Expect::Credential).await
    }

    /// Deliver an answer; `false` when no prompt with this id (and shape) is open.
    pub(crate) fn answer(&self, id: u32, reply: Reply) -> bool {
        let mut slot = self.slot();
        let shape = match reply {
            Reply::Text(_) => Expect::Text,
            Reply::Credential { .. } => Expect::Credential,
        };
        match slot.take() {
            Some((open, expect, tx)) if open == id && expect == shape => tx.send(reply).is_ok(),
            other => {
                *slot = other;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn trust_prompt_round_trip_and_wrong_ids() {
        let (tx, mut rx) = mpsc::channel(4);
        let shared = Arc::new(Shared::new(tx, AuditSink::new()));
        let s = Arc::clone(&shared);
        let info = CertificateInfo::new(
            b"x",
            "CN=a",
            "CN=a",
            time::OffsetDateTime::UNIX_EPOCH,
            time::OffsetDateTime::UNIX_EPOCH,
            &[],
            vec![],
        );
        let ask = tokio::spawn(async move { s.ask_trust("trust?".into(), info).await });
        let Some(SessionEvent::Prompt { id, purpose, certificate, .. }) = rx.recv().await else {
            panic!("expected prompt");
        };
        assert_eq!(purpose, PromptPurpose::CertificateTrust);
        assert!(certificate.is_some());
        assert!(!shared.answer(id + 1, Reply::Text("yes".to_owned().into())));
        let cred = Reply::Credential {
            username: "u".into(),
            domain: None,
            password: "p".to_owned().into(),
        };
        assert!(!shared.answer(id, cred), "wrong shape is refused");
        assert!(shared.answer(id, Reply::Text(" YES ".to_owned().into())));
        assert_eq!(ask.await.expect("join"), Some(true));
    }

    #[tokio::test]
    async fn close_unblocks_a_prompt() {
        let (tx, mut rx) = mpsc::channel(4);
        let shared = Arc::new(Shared::new(tx, AuditSink::new()));
        let s = Arc::clone(&shared);
        let ask = tokio::spawn(async move { s.ask_credential(PromptAccount::default()).await });
        let _ = rx.recv().await;
        shared.begin_close();
        assert!(ask.await.expect("join").is_none());
        assert!(shared.ask_trust("x".into(), dummy()).await.is_none());
    }

    fn dummy() -> CertificateInfo {
        let t = time::OffsetDateTime::UNIX_EPOCH;
        CertificateInfo::new(b"", "", "", t, t, &[], vec![])
    }

    #[test]
    fn sanitize_strips_controls() {
        assert_eq!(sanitize("a\x1b[2Jb\n"), "a[2Jb");
        assert_eq!(sanitize(&"x".repeat(1000)).len(), MAX_PROMPT_CHARS);
    }
}
