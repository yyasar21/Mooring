//! The task of one RDP / VNC session (ADR-0011): owns the [`FramePump`], intercepts the
//! `certificate_trust` answer (pin, then reconnect on a new TCP connection), filters input
//! in view-only mode and reconnects with backoff after a dropped connection.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::frame::FrameSink;
use mooring_core::known_certs::{CertificateInfo, KnownCerts};
use mooring_core::session::{CloseCode, PromptPurpose, Session, SessionEvent, SessionInput, Size};
use mooring_core::Protocol;
use secrecy::ExposeSecret;
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::clipboard::Clipboard;
use crate::commands::connect_plan;
use crate::error::{IpcError, IpcResult};
use crate::frame_pump::{FrameFlow, FrameOut, FramePump};
use crate::reconnect;
use crate::session_audit::cert;
use crate::session_factory::{GraphicalConnect, SessionFactory};
use crate::session_task::{drive, finish, End, Intercept, Interceptor};
use crate::sessions::{GraphicalControl, Phase, PhaseCell, SessionCommand, TaskContext, WireEvent};
use crate::state::{record_audit, Ready};

/// Resolves the connection and connects again, from the vault every time (ADR-0011).
#[derive(Clone)]
pub struct Launcher {
    /// Vault + store.
    pub ready: Ready,
    /// RDP / VNC constructors.
    pub factory: Arc<dyn SessionFactory>,
    /// Connection id (canonical).
    pub connection_id: String,
    /// Latest desktop size the UI asked for.
    pub size: Arc<Mutex<Size>>,
    /// `$APP_DATA/known_<proto>_certs`.
    pub known_certs: PathBuf,
    /// Tracked clipboard.
    pub clipboard: Arc<dyn Clipboard>,
    /// Shared framebuffer.
    pub frames: FrameSink,
    /// Audit log (`credential_used` per attempt).
    pub audit: Arc<Mutex<AuditLog>>,
}

impl std::fmt::Debug for Launcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launcher").field("connection_id", &self.connection_id).finish_non_exhaustive()
    }
}

/// The result of one connect: the session plus what the task needs from the plan.
pub struct Launched {
    /// The new session (TCP up).
    pub session: Box<dyn Session>,
    /// Protocol.
    pub protocol: Protocol,
    /// Host and port of the pin.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Options in effect.
    pub options: mooring_core::ProtocolOptions,
}

impl std::fmt::Debug for Launched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launched").field("protocol", &self.protocol).finish_non_exhaustive()
    }
}

impl Launcher {
    /// Plan (credential from the vault), audit `credential_used` and connect.
    pub async fn connect(&self, trusted_once: Option<[u8; 32]>) -> IpcResult<Launched> {
        let size = *self.size.lock().map_err(|_| IpcError::poisoned())?;
        let plan = connect_plan::plan(&self.ready, &self.connection_id, size).await?;
        for cred in plan.used {
            record_audit(&self.audit, AuditEvent::CredentialUsed {
                credential: cred,
                purpose: "connect".to_owned(),
                connection: Some(self.connection_id.clone()),
            });
        }
        let (host, port) = (plan.params.host.clone(), plan.params.port);
        let req = GraphicalConnect {
            protocol: plan.protocol,
            params: plan.params,
            options: plan.options.clone(),
            known_certs: self.known_certs.clone(),
            frames: self.frames.clone(),
            clipboard: Arc::clone(&self.clipboard),
            trusted_once,
        };
        let session = self.factory.connect(req).await?;
        Ok(Launched { session, protocol: plan.protocol, host, port, options: plan.options })
    }
}

/// Everything the graphical task owns.
pub struct GraphicalTask {
    /// First connection.
    pub first: Launched,
    /// Reconnects.
    pub launcher: Launcher,
    /// Credits shared with `session_frame_ack`.
    pub flow: FrameFlow,
    /// Raw frame channel.
    pub out: FrameOut,
    /// Backoff unit.
    pub reconnect_unit: Duration,
    /// VNC view-only switch (`session_set_view_only`).
    pub view_only: Arc<AtomicBool>,
}

impl std::fmt::Debug for GraphicalTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphicalTask").field("first", &self.first).finish_non_exhaustive()
    }
}

/// Map a connect error to the close code the UI and the retry rule use.
pub fn close_code_of(e: &IpcError) -> CloseCode {
    match e.code {
        "vault.locked" | "vault.missing" => CloseCode::VaultLocked,
        "session.trust_mismatch" => CloseCode::TrustMismatch,
        "session.trust_rejected" => CloseCode::TrustRejected,
        "session.unsupported_security" | "protocol.unavailable" | "input.invalid" => {
            CloseCode::ProtocolError
        }
        c if c.starts_with("credential.") => CloseCode::AuthFailed,
        _ => CloseCode::Network,
    }
}

/// The answer to a `certificate_trust` prompt (U2): `yes`, `once` or anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustAnswer {
    Pin,
    Once,
    Reject,
}

impl TrustAnswer {
    fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "yes" => Self::Pin,
            "once" => Self::Once,
            _ => Self::Reject,
        }
    }
}

/// Certificate prompt, view-only filter and size tracking for [`drive`].
struct Gate {
    pending: Option<(u32, CertificateInfo)>,
    protocol: Protocol,
    host: String,
    port: u16,
    path: PathBuf,
    audit: Arc<Mutex<AuditLog>>,
    size: Arc<Mutex<Size>>,
    view_only: Arc<AtomicBool>,
}

impl Gate {
    /// M-13: record that this VNC host negotiated `VeNCrypt` X509, so a later offer without
    /// it is a `trust_mismatch` even when the certificate was CA-valid (never pinned). The
    /// Gate stays the single writer of `known_vnc_certs`.
    fn mark_tls_seen(&self) {
        match KnownCerts::mark_tls_and_save(&self.path, &self.host, self.port, OffsetDateTime::now_utc()) {
            Ok(true) => tracing::info!("vnc host marked as TLS-required"),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "TLS-required marker not stored"),
        }
    }

    /// `yes` pins, `once` trusts for this connect only (no pin, `trusted_once`), anything
    /// else rejects.
    fn answer(&self, answer: TrustAnswer, info: &CertificateInfo) -> End {
        let host = mooring_core::known_certs::host_key(&self.host, self.port);
        let fp = info.display_fingerprint();
        let audit = |decision| {
            record_audit(&self.audit, cert(self.protocol.name().to_owned(), host.clone(), fp.clone(), decision, None));
        };
        if answer == TrustAnswer::Reject {
            audit("rejected");
            let reason = format!("certificate for {host} was not trusted");
            return End::Closed { reason, code: CloseCode::TrustRejected };
        }
        let sha: Option<[u8; 32]> = hex::decode(&info.sha256).ok().and_then(|v| v.try_into().ok());
        let Some(sha) = sha else {
            let reason = "the server certificate could not be read".to_owned();
            return End::Closed { reason, code: CloseCode::ProtocolError };
        };
        if answer == TrustAnswer::Once {
            audit("trusted_once");
            return End::TrustAccepted { trusted_once: Some(sha) };
        }
        match KnownCerts::add_and_save(&self.path, &self.host, self.port, &sha, OffsetDateTime::now_utc()) {
            Ok(()) => {
                audit("accepted");
                End::TrustAccepted { trusted_once: None }
            }
            Err(e) => {
                tracing::warn!(error = %e, "certificate pin not stored; trusted for this connect only");
                audit("accepted_session_only");
                End::TrustAccepted { trusted_once: Some(sha) }
            }
        }
    }
}

impl Interceptor for Gate {
    fn on_event(&mut self, event: &SessionEvent) {
        if let SessionEvent::Connected { security: Some(s), .. } = event {
            if self.protocol == Protocol::Vnc && s == "vencrypt-x509" {
                self.mark_tls_seen();
            }
        }
        if let SessionEvent::Prompt {
            id,
            purpose: PromptPurpose::CertificateTrust,
            certificate: Some(info),
            ..
        } = event
        {
            self.pending = Some((*id, info.clone()));
        }
    }

    fn on_input(&mut self, input: &SessionInput) -> Intercept {
        match input {
            SessionInput::Answer { id, text } if self.pending.as_ref().is_some_and(|p| p.0 == *id) => {
                let Some((_, info)) = self.pending.take() else { return Intercept::Pass };
                Intercept::End(self.answer(TrustAnswer::parse(text.expose_secret()), &info))
            }
            SessionInput::Resize { size } => {
                if let Ok(mut s) = self.size.lock() {
                    *s = *size;
                }
                Intercept::Pass
            }
            // ReleaseAll always passes so nothing stays pressed (U1 contract).
            SessionInput::Pointer { .. }
            | SessionInput::Key { .. }
            | SessionInput::Wheel { .. }
            | SessionInput::Unicode { .. }
            | SessionInput::ClipboardOffer
                if self.view_only.load(Ordering::Relaxed) =>
            {
                Intercept::Drop
            }
            _ => Intercept::Pass,
        }
    }

    fn waiting(&self) -> bool {
        self.pending.is_some()
    }
}

/// Wait `delay`, answering commands. `false` when the user closed the session meanwhile.
async fn wait(commands: &mut mpsc::Receiver<SessionCommand>, delay: Duration) -> bool {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            () = &mut sleep => return true,
            cmd = commands.recv() => match cmd {
                Some(SessionCommand::Input(_, reply)) => {
                    let _ = reply.send(Err(IpcError::new("session.not_connected", "session is reconnecting")));
                }
                Some(SessionCommand::Close(reply)) => {
                    let _ = reply.send(());
                    return false;
                }
                None => return false,
            },
        }
    }
}

impl GraphicalTask {
    /// Protocol of the session.
    pub fn protocol(&self) -> Protocol {
        self.first.protocol
    }

    /// What IPC reaches (`session_frame_ack`, `session_screenshot`, `session_attach`).
    pub fn control(&self) -> GraphicalControl {
        GraphicalControl {
            frames: self.launcher.frames.clone(),
            flow: self.flow.clone(),
            view_only: Arc::clone(&self.view_only),
        }
    }

    /// Run until the session ends for good.
    pub async fn run(self, mut commands: mpsc::Receiver<SessionCommand>, ctx: TaskContext, phase: PhaseCell) {
        let interval = match &self.first.options {
            mooring_core::ProtocolOptions::Rdp(o) => o.max_fps.interval(),
            mooring_core::ProtocolOptions::Vnc(o) => o.max_fps.interval(),
            _ => crate::frame_pump::DEFAULT_INTERVAL,
        };
        let pump = FramePump::new(self.launcher.frames.clone(), self.flow.clone(), Arc::clone(&self.out), interval);
        let pump = tokio::spawn(pump.run());
        let Launched { mut session, protocol, host, port, .. } = self.first;
        let mut gate = Gate {
            pending: None,
            protocol,
            host,
            port,
            path: self.launcher.known_certs.clone(),
            audit: Arc::clone(&ctx.audit),
            size: Arc::clone(&self.launcher.size),
            view_only: Arc::clone(&self.view_only),
        };
        let (mut attempt, mut ever) = (0u32, false);
        let (reason, code) = 'outer: loop {
            let d = drive(&mut *session, &mut commands, &ctx, &phase, Some(&mut gate)).await;
            gate.pending = None;
            ever |= d.connected;
            if d.connected {
                attempt = 0;
            }
            let (mut reason, mut code) = match d.end {
                End::TrustAccepted { trusted_once } => match self.launcher.connect(trusted_once).await {
                    Ok(l) => {
                        session = l.session;
                        phase.set(Phase::Connecting);
                        continue;
                    }
                    Err(e) => (e.message.clone(), close_code_of(&e)),
                },
                End::Closed { reason, code } => (reason, code),
            };
            let mut by_user = d.closing;
            loop {
                if !reconnect::should_retry(code, ever, by_user, attempt) {
                    break 'outer (reason, code);
                }
                attempt += 1;
                let delay = reconnect::jittered(self.reconnect_unit, attempt).unwrap_or_default();
                phase.set(Phase::Reconnecting);
                let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
                if !(ctx.sink)(WireEvent::Reconnecting { attempt, delay_ms }) || !wait(&mut commands, delay).await {
                    by_user = true;
                    (reason, code) = ("session closed".to_owned(), CloseCode::User);
                    continue;
                }
                phase.set(Phase::Connecting);
                match self.launcher.connect(None).await {
                    Ok(l) => {
                        session = l.session;
                        continue 'outer;
                    }
                    Err(e) => {
                        tracing::info!(code = e.code, attempt, "reconnect attempt failed");
                        (reason, code) = (e.message.clone(), close_code_of(&e));
                    }
                }
            }
        };
        (ctx.sink)(WireEvent::Closed { reason: reason.clone(), code });
        pump.abort();
        finish(commands, ctx, &phase, reason);
    }
}

#[cfg(test)]
#[path = "graphical_tests.rs"]
mod tests;
