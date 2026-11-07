//! The per-session task: sign-in form (if any) → connection attempts with certificate TOFU
//! (fail, prompt, reconnect on a new TCP connection) → active stage → `Closed`.

use std::sync::Arc;
use std::time::Duration;

use mooring_core::frame::FrameSink;
use mooring_core::known_certs::{display_fingerprint, peer_identity, CertProblem};
use mooring_core::options::ClipboardPolicy;
use mooring_core::session::{CloseCode, SessionEvent};
use mooring_core::Protocol;
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::active::{Active, Channels, Command};
use crate::active_clip::ClipState;
use crate::clipboard::ClipQueue;
use crate::connect::{attempt, Attempt, Target};
use crate::creds::{from_reply, CredSource, Creds};
use crate::errors::{end, End};
use crate::options::LocalClipboard;
use crate::shared::Shared;
use crate::tls::Decision;

/// Certificate rounds per connect: the first may prompt, the second must hit the new pin.
const MAX_TRUST_ROUNDS: usize = 2;

pub(crate) struct Driver {
    pub(crate) target: Target,
    pub(crate) source: CredSource,
    pub(crate) shared: Arc<Shared>,
    pub(crate) sink: FrameSink,
    pub(crate) commands: mpsc::Receiver<Command>,
    pub(crate) clipboard: Option<Arc<dyn LocalClipboard>>,
    pub(crate) policy: ClipboardPolicy,
    pub(crate) handshake_timeout: Duration,
}

fn problem_text(problems: &[CertProblem]) -> String {
    let words: Vec<&str> = problems
        .iter()
        .map(|p| match p {
            CertProblem::SelfSigned => "self-signed",
            CertProblem::UnknownIssuer => "unknown issuer",
            CertProblem::NameMismatch => "name mismatch",
            CertProblem::Expired => "expired",
            CertProblem::NotYetValid => "not yet valid",
        })
        .collect();
    if words.is_empty() {
        "not pinned".to_owned()
    } else {
        words.join(", ")
    }
}

impl Driver {
    pub(crate) async fn run(self) {
        let shared = Arc::clone(&self.shared);
        let (code, reason) = self.run_inner().await;
        tracing::debug!(code = ?code, "rdp session ended");
        let _ = shared.events.send(SessionEvent::Closed { reason, code }).await;
    }

    async fn resolve(&mut self) -> Result<Creds, End> {
        let source = std::mem::replace(
            &mut self.source,
            CredSource::Prompt(mooring_core::session::PromptAccount::default()),
        );
        match source {
            CredSource::Ready(c) => Ok(c),
            CredSource::Prompt(account) => match self.shared.ask_credential(account).await {
                Some(reply) => {
                    from_reply(reply).ok_or_else(|| end(CloseCode::User, "sign-in cancelled"))
                }
                None => Err(end(CloseCode::User, "closed by user")),
            },
        }
    }

    async fn run_inner(mut self) -> End {
        let creds = match self.resolve().await {
            Ok(c) => c,
            Err(e) => return e,
        };
        let clip_queue =
            ClipState::enabled(self.clipboard.as_ref(), self.policy).then(ClipQueue::default);
        let channels = Channels { cliprdr: clip_queue.clone() };
        let mut session_pin: Option<[u8; 32]> = self.target.session_pin;
        for _ in 0..MAX_TRUST_ROUNDS {
            if let Some(pin) = session_pin {
                self.target.session_pin = Some(pin);
            }
            let audit = self.shared.audit.clone();
            let run = tokio::time::timeout(
                self.handshake_timeout,
                attempt(&self.target, &creds, channels.clone(), &audit),
            );
            let outcome = tokio::select! {
                r = run => r,
                () = self.shared.closed() => return end(CloseCode::User, "closed by user"),
            };
            match outcome {
                Err(_) => return end(CloseCode::Network, "the RDP handshake timed out"),
                Ok(Attempt::Failed(e)) => return e,
                Ok(Attempt::NeedsTrust(d)) => match self.trust(&d).await {
                    Ok(()) => session_pin = Some(d.fingerprint),
                    Err(e) => return e,
                },
                Ok(Attempt::Connected(est)) => {
                    // B-5: refuse a hostile desktop size before anything is allocated for it.
                    if let Err(e) = crate::active::check_desktop(est.result.desktop_size) {
                        return e;
                    }
                    // The password is not needed after NLA: zeroize our copy now.
                    drop(creds);
                    self.shared.set_connected();
                    let connected = SessionEvent::Connected {
                        protocol: Protocol::Rdp,
                        peer_identity: Some(peer_identity(&est.fingerprint)),
                        security: Some(est.security.to_owned()),
                        hop: None,
                    };
                    if self.shared.events.send(connected).await.is_err() {
                        return end(CloseCode::User, "closed by user");
                    }
                    let clip = ClipState::new(clip_queue, self.clipboard.clone(), self.policy);
                    return match Active::new(
                        *est,
                        &self.shared,
                        self.sink.clone(),
                        &mut self.commands,
                        clip,
                    ) {
                        Ok((active, framed)) => active.run(framed).await,
                        Err(e) => e,
                    };
                }
            }
        }
        end(CloseCode::ProtocolError, "the server certificate could not be established")
    }

    /// The TOFU prompt. `Ok` = trusted for this session (kept in memory only): the caller
    /// reconnects. Writing the pin and auditing the answer belong to the Tauri layer
    /// (ADR-0011 R2 contract): in the app the answer never reaches this session, which is
    /// closed and reconnected with `trusted_once` / the new pin instead.
    async fn trust(&self, d: &Decision) -> Result<(), End> {
        let (host, port) = (self.target.host.clone(), self.target.port);
        let now = OffsetDateTime::now_utc();
        let info =
            crate::cert::certificate_info(&d.der, &host, now, &d.problems).map_err(|_| {
                end(CloseCode::ProtocolError, "the server certificate could not be parsed")
            })?;
        let fp = display_fingerprint(&d.fingerprint);
        let message = format!(
            "The certificate of {host}:{port} is not trusted ({}). Fingerprint {fp}. Trust it and reconnect?",
            problem_text(&info.problems)
        );
        match self.shared.ask_trust(message, info).await {
            Some(true) => Ok(()),
            Some(false) => {
                Err(end(CloseCode::TrustRejected, "the server certificate was not trusted"))
            }
            None => Err(end(CloseCode::User, "closed by user")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_words() {
        assert_eq!(problem_text(&[]), "not pinned");
        assert_eq!(
            problem_text(&[CertProblem::SelfSigned, CertProblem::Expired]),
            "self-signed, expired"
        );
    }
}
