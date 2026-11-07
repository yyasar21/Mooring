//! State shared between the `VncSession` front and its driver task: the event channel, the
//! prompt broker (TOFU / credential form), the audit log and the view-only switch.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use mooring_core::audit::ClipboardDirection;
use mooring_core::known_certs::CertificateInfo;
use mooring_core::session::{PromptAccount, PromptPurpose, SessionEvent};
use mooring_core::SessionAudit;
use secrecy::SecretString;
use tokio::sync::{mpsc, oneshot};

/// Audit events recorded by a session, drained by the Tauri layer
/// (`Session::take_audit_events`): [`mooring_core::AuditBuffer`], also
/// `mooring_proto_rdp::AuditSink`.
pub type AuditLog = mooring_core::AuditBuffer;

#[cfg(test)]
use mooring_core::audit::MAX_AUDIT;

/// `session.clipboard` coalescing: at most one entry per second per direction.
#[derive(Debug, Default)]
pub(crate) struct ClipAudit {
    last: [Option<Instant>; 2],
    pending: [u64; 2],
}

impl ClipAudit {
    const fn idx(d: ClipboardDirection) -> usize {
        match d {
            ClipboardDirection::ToRemote => 0,
            ClipboardDirection::FromRemote => 1,
        }
    }

    pub(crate) fn record(&mut self, log: &AuditLog, direction: ClipboardDirection, bytes: u64) {
        let i = Self::idx(direction);
        self.pending[i] = self.pending[i].saturating_add(bytes);
        let now = Instant::now();
        if self.last[i].is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1)) {
            log.push(SessionAudit::Clipboard { direction, bytes: self.pending[i] });
            self.pending[i] = 0;
            self.last[i] = Some(now);
        }
    }

    pub(crate) fn flush(&mut self, log: &AuditLog) {
        for direction in [ClipboardDirection::ToRemote, ClipboardDirection::FromRemote] {
            let i = Self::idx(direction);
            if self.pending[i] > 0 {
                log.push(SessionAudit::Clipboard { direction, bytes: self.pending[i] });
                self.pending[i] = 0;
            }
        }
    }
}

/// An answer to a prompt. Never printed.
pub(crate) enum Reply {
    Text(SecretString),
    Credential { username: String, password: SecretString },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Text,
    Credential,
}

type Pending = Option<(u32, Expect, oneshot::Sender<Reply>)>;

/// Everything the front and the driver share.
pub(crate) struct Shared {
    pub(crate) events: mpsc::Sender<SessionEvent>,
    pub(crate) audit: AuditLog,
    pub(crate) view_only: AtomicBool,
    pub(crate) dropped: AtomicU64,
    next_id: AtomicU32,
    pending: Mutex<Pending>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("view_only", &self.view_only.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Shared {
    pub(crate) fn new(
        events: mpsc::Sender<SessionEvent>,
        audit: AuditLog,
        view_only: bool,
    ) -> Self {
        Self {
            events,
            audit,
            view_only: AtomicBool::new(view_only),
            dropped: AtomicU64::new(0),
            next_id: AtomicU32::new(1),
            pending: Mutex::new(None),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn raise(
        &self,
        expect: Expect,
        event: impl FnOnce(u32) -> SessionEvent,
    ) -> Option<Reply> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        *self.slot() = Some((id, expect, tx));
        if self.events.send(event(id)).await.is_err() {
            return None;
        }
        rx.await.ok()
    }

    /// Ask the user to trust a certificate; `true` only for an explicit `yes`.
    pub(crate) async fn ask_certificate(&self, host_port: &str, info: CertificateInfo) -> bool {
        let message = format!(
            "The certificate of {host_port} is not trusted ({}). Trust it and reconnect?",
            info.display_fingerprint()
        );
        let reply = self
            .raise(Expect::Text, |id| SessionEvent::Prompt {
                id,
                message,
                secret: false,
                purpose: PromptPurpose::CertificateTrust,
                account: None,
                certificate: Some(info),
                hop: None,
            })
            .await;
        matches!(reply, Some(Reply::Text(t)) if {
            use secrecy::ExposeSecret;
            t.expose_secret().trim().eq_ignore_ascii_case("yes")
        })
    }

    /// The connect-time sign-in form; `None` = cancelled or closed.
    pub(crate) async fn ask_credential(
        &self,
        account: PromptAccount,
    ) -> Option<(String, SecretString)> {
        let reply = self
            .raise(Expect::Credential, |id| SessionEvent::Prompt {
                id,
                message: "Sign in to the VNC server".to_owned(),
                secret: true,
                purpose: PromptPurpose::Credential,
                account: Some(account),
                certificate: None,
                hop: None,
            })
            .await?;
        match reply {
            Reply::Credential { username, password } => Some((username, password)),
            Reply::Text(_) => None,
        }
    }

    /// Deliver an answer; `false` when no open prompt has this id and shape.
    pub(crate) fn answer(&self, id: u32, reply: Reply) -> bool {
        let mut slot = self.slot();
        let shape = match reply {
            Reply::Text(_) => Expect::Text,
            Reply::Credential { .. } => Expect::Credential,
        };
        match slot.take() {
            Some((pid, expect, tx)) if pid == id && expect == shape => tx.send(reply).is_ok(),
            other => {
                *slot = other;
                false
            }
        }
    }

    /// Unblock any open prompt (the session is closing).
    pub(crate) fn cancel_prompt(&self) {
        self.slot().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn audit_log_caps_and_drains() {
        let log = AuditLog::default();
        for _ in 0..MAX_AUDIT + 5 {
            log.push(SessionAudit::AuthFailed);
        }
        assert_eq!(log.take().len(), MAX_AUDIT);
        assert!(log.take().is_empty());
    }

    #[test]
    fn clipboard_audit_is_coalesced() {
        let log = AuditLog::default();
        let mut c = ClipAudit::default();
        c.record(&log, ClipboardDirection::FromRemote, 3);
        c.record(&log, ClipboardDirection::FromRemote, 4);
        c.record(&log, ClipboardDirection::ToRemote, 5);
        c.flush(&log);
        let got = log.take();
        assert_eq!(
            got,
            vec![
                SessionAudit::Clipboard { direction: ClipboardDirection::FromRemote, bytes: 3 },
                SessionAudit::Clipboard { direction: ClipboardDirection::ToRemote, bytes: 5 },
                SessionAudit::Clipboard { direction: ClipboardDirection::FromRemote, bytes: 4 },
            ]
        );
    }

    #[tokio::test]
    async fn answers_must_match_id_and_shape() {
        let (tx, mut rx) = mpsc::channel(4);
        let shared = Arc::new(Shared::new(tx, AuditLog::default(), false));
        let s2 = Arc::clone(&shared);
        let ask =
            tokio::spawn(
                async move { s2.ask_certificate("h.example.test:5900", test_info()).await },
            );
        let Some(SessionEvent::Prompt { id, purpose, certificate, .. }) = rx.recv().await else {
            panic!()
        };
        assert_eq!(purpose, PromptPurpose::CertificateTrust);
        assert!(certificate.is_some());
        let cred = Reply::Credential {
            username: String::new(),
            password: SecretString::from(String::new()),
        };
        assert!(!shared.answer(id, cred), "wrong shape");
        assert!(!shared.answer(id + 1, Reply::Text(SecretString::from("yes".to_owned()))));
        assert!(shared.answer(id, Reply::Text(SecretString::from(" YES ".to_owned()))));
        assert!(ask.await.expect("join"));
    }

    fn test_info() -> CertificateInfo {
        let t = time::OffsetDateTime::UNIX_EPOCH;
        CertificateInfo::new(b"der", "CN=x", "CN=x", t, t, &[], vec![])
    }
}
