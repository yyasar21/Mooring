//! The loop that drives one protocol session (generic over `S: Session`, ADR-0011): commands
//! in, events out, audit drained after every event. SSH runs it once ([`run_ssh`]); the
//! graphical task runs it once per connection and decides about reconnects
//! ([`crate::graphical_task`]).

use mooring_audit::AuditEvent;
use mooring_core::session::{CloseCode, Session, SessionEvent, SessionInput};
use mooring_core::Protocol;
use tokio::sync::mpsc;

use crate::error::IpcError;
use crate::sessions::{audit_session, Phase, PhaseCell, SessionCommand, TaskContext, Transfers, WireEvent};
use crate::state::record_audit;

/// How one connection ended.
#[derive(Debug)]
pub(crate) enum End {
    /// The session closed (its own `Closed`, a stream end or an error).
    Closed {
        /// Safe reason.
        reason: String,
        /// Cause.
        code: CloseCode,
    },
    /// The user answered `yes` to a `certificate_trust` prompt: reconnect at once.
    TrustAccepted {
        /// Leaf to accept once when the pin could not be stored.
        trusted_once: Option<[u8; 32]>,
        /// ADR-0027: the answer was about the RD Gateway's certificate (`known_rdg_certs`).
        gateway: bool,
    },
}

/// Result of [`drive`].
#[derive(Debug)]
pub(crate) struct Driven {
    pub(crate) end: End,
    /// `Connected` was seen on this connection.
    pub(crate) connected: bool,
    /// The user closed the session or the UI went away: never reconnect.
    pub(crate) closing: bool,
}

/// Hook for graphical sessions: inputs and prompts the task handles itself.
pub(crate) trait Interceptor: Send {
    /// A prompt is about to reach the UI.
    fn on_event(&mut self, event: &SessionEvent);
    /// Handle `input` instead of the session. `Some(end)` ends this connection.
    fn on_input(&mut self, input: &SessionInput) -> Intercept;
    /// The session's stream ended while waiting for a user answer: keep waiting.
    fn waiting(&self) -> bool;
}

/// What the interceptor did with an input.
pub(crate) enum Intercept {
    /// Forward to the session.
    Pass,
    /// Swallowed (`Ok` to the caller).
    Drop,
    /// End this connection.
    End(End),
}

/// Drive `session` until it ends. Every event but `Closed` is forwarded to the UI; the
/// caller emits `Closed` (or reconnects).
pub(crate) async fn drive<S: Session + ?Sized>(
    session: &mut S,
    commands: &mut mpsc::Receiver<SessionCommand>,
    ctx: &TaskContext,
    phase: &PhaseCell,
    mut hook: Option<&mut dyn Interceptor>,
) -> Driven {
    let protocol = session.protocol();
    let mut reason = String::from("session ended");
    let (mut closing, mut connected, mut stream_done) = (false, false, false);
    loop {
        tokio::select! {
            biased;
            cmd = commands.recv(), if !closing => match cmd {
                Some(SessionCommand::Input(input, reply)) => {
                    let verdict = hook.as_deref_mut().map_or(Intercept::Pass, |h| h.on_input(&input));
                    match verdict {
                        Intercept::Pass if stream_done => {
                            let _ = reply.send(Err(IpcError::new("session.not_connected", "session is not connected")));
                        }
                        Intercept::Pass => {
                            let r = session.send(input).await.map_err(IpcError::from);
                            let _ = reply.send(r);
                        }
                        Intercept::Drop => {
                            let _ = reply.send(Ok(()));
                        }
                        Intercept::End(end) => {
                            let _ = reply.send(Ok(()));
                            let _ = session.close().await;
                            audit_session(&ctx.audit, &ctx.connection_id, protocol, session.take_audit_events());
                            return Driven { end, connected, closing: false };
                        }
                    }
                }
                Some(SessionCommand::Close(reply)) => {
                    closing = true;
                    if let Err(e) = session.close().await {
                        tracing::debug!(error = %e, "session close reported an error");
                    }
                    let _ = reply.send(());
                    if stream_done {
                        break;
                    }
                }
                None => {
                    closing = true;
                    let _ = session.close().await;
                    if stream_done {
                        break;
                    }
                }
            },
            event = session.next_event(), if !stream_done => {
                audit_session(&ctx.audit, &ctx.connection_id, protocol, session.take_audit_events());
                match event {
                    Ok(Some(SessionEvent::Closed { reason: r, code })) => {
                        if !closing && hook.as_deref().is_some_and(Interceptor::waiting) {
                            // A certificate prompt is open: the answer decides, not the server.
                            stream_done = true;
                            continue;
                        }
                        reason = r;
                        let code = if closing { CloseCode::User } else { code };
                        return Driven { end: End::Closed { reason, code }, connected, closing };
                    }
                    Ok(Some(event)) => {
                        if let SessionEvent::Connected { peer_identity, .. } = &event {
                            connected = true;
                            phase.set(Phase::Connected);
                            record_audit(&ctx.audit, AuditEvent::SessionOpened {
                                connection: ctx.connection_id.clone(),
                                protocol: protocol.name().to_owned(),
                                peer_identity: peer_identity.clone(),
                            });
                        }
                        if let Some(h) = hook.as_deref_mut() {
                            h.on_event(&event);
                        }
                        if !(ctx.sink)(event.into()) && !closing {
                            tracing::info!("session event channel gone; closing");
                            closing = true;
                            let _ = session.close().await;
                        }
                    }
                    Ok(None) => {
                        // Stream ended without a visible Closed.
                        if !closing && hook.as_deref().is_some_and(Interceptor::waiting) {
                            stream_done = true;
                            continue;
                        }
                        let code = if closing { CloseCode::User } else { CloseCode::ServerEnded };
                        return Driven { end: End::Closed { reason, code }, connected, closing };
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "session event error");
                        let _ = session.close().await;
                        let code = if closing { CloseCode::User } else { CloseCode::Network };
                        let end = End::Closed { reason: "session failed".to_owned(), code };
                        return Driven { end, connected, closing };
                    }
                }
            }
        }
    }
    Driven { end: End::Closed { reason, code: CloseCode::User }, connected, closing: true }
}

/// Remove the session from the registry, answer queued commands and write `session_closed`.
pub(crate) fn finish(
    mut commands: mpsc::Receiver<SessionCommand>,
    ctx: TaskContext,
    phase: &PhaseCell,
    reason: String,
) {
    phase.set(Phase::Closed);
    if let Ok(mut map) = ctx.registry.lock() {
        map.remove(&ctx.session_id);
    }
    if let Some(secrets) = &ctx.secrets {
        secrets.release_session(&ctx.session_id, "closed");
    }
    // Answer anything still queued so no IPC call waits forever.
    commands.close();
    while let Ok(cmd) = commands.try_recv() {
        match cmd {
            SessionCommand::Input(_, reply) => {
                let _ = reply.send(Err(IpcError::new("session.not_found", "session is closed")));
            }
            SessionCommand::Close(reply) => {
                let _ = reply.send(());
            }
        }
    }
    record_audit(&ctx.audit, AuditEvent::SessionClosed { connection: ctx.connection_id, reason });
}

/// The SSH task: one connection, no reconnect.
pub(crate) async fn run_ssh<S: Session>(
    mut session: S,
    mut commands: mpsc::Receiver<SessionCommand>,
    ctx: TaskContext,
    phase: PhaseCell,
    transfers: Transfers,
) {
    let driven = drive(&mut session, &mut commands, &ctx, &phase, None).await;
    let (reason, code) = match driven.end {
        End::Closed { reason, code } => (reason, code),
        // Only an interceptor ends with a trust answer; SSH has none.
        End::TrustAccepted { .. } => ("session ended".to_owned(), CloseCode::ProtocolError),
    };
    (ctx.sink)(WireEvent::Closed { reason: reason.clone(), code });
    phase.set(Phase::Closed);
    // Transfers end with their session (each reports `cancelled` and audits itself).
    let pending: Vec<_> = transfers.lock().map(|mut t| t.drain().collect()).unwrap_or_default();
    for (_, t) in pending {
        let _ = t.cancel.send(());
    }
    audit_session(&ctx.audit, &ctx.connection_id, Protocol::Ssh, session.take_audit_events());
    finish(commands, ctx, &phase, reason);
}
