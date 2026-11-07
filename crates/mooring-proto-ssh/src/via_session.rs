//! [`ViaSession`]: any [`Session`] (RDP, VNC) reached through a [`HopChain`] (ADR-0025 §2).
//!
//! `start` returns at once. A task opens the chain (its `HopStatus` events and hop prompts,
//! ids above [`HOP_PROMPT_ID_BASE`], come out of `next_event` first), then builds the target
//! session with the chain as its [`Dialer`](mooring_core::transport::Dialer) and forwards its
//! events. Answers to hop prompts go to the chain's broker; everything else goes to the
//! target once it exists (input sent before that is dropped: the target replays its state on
//! connect). A hop failure ends with `hop_failed` and the target is never dialed; a hop lost
//! later closes the target and ends with `hop_lost`. The chain closes after the target, in
//! reverse hop order.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mooring_core::session::{CloseCode, Session, SessionEvent, SessionInput};
use mooring_core::transport::SharedDialer;
use mooring_core::{MooringError, Protocol, SessionAudit};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::hops::{Hop, HopChain, HopEvents};
use crate::shared::HOP_PROMPT_ID_BASE;

/// Builds the target session over the chain's dialer.
pub type TargetFuture =
    Pin<Box<dyn Future<Output = Result<Box<dyn Session>, MooringError>> + Send>>;

/// How often a running chain is checked for a lost hop.
const HOP_WATCH: Duration = Duration::from_secs(1);
/// How long `close` waits for the task before aborting it.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// Event channel capacity (same bound as the SSH session).
const CAPACITY: usize = 256;

type Reply = oneshot::Sender<Result<(), MooringError>>;

/// A session behind a jump-host chain.
pub struct ViaSession {
    protocol: Protocol,
    events: mpsc::Receiver<SessionEvent>,
    inputs: mpsc::Sender<(SessionInput, Reply)>,
    broker: crate::shared::PromptBroker,
    audit: crate::audit::AuditLog,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    final_event: Option<SessionEvent>,
    closed: bool,
}

impl std::fmt::Debug for ViaSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViaSession")
            .field("protocol", &self.protocol)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

fn closed(code: CloseCode, reason: impl Into<String>) -> SessionEvent {
    SessionEvent::Closed { reason: reason.into(), code }
}

fn no_prompt() -> MooringError {
    MooringError::Invalid { field: "prompt id", reason: "no open prompt with this id".to_owned() }
}

impl ViaSession {
    /// Open `hops` towards `target` in a task, then `make(chain)` the target session.
    pub fn start(
        protocol: Protocol,
        hops: Vec<Hop>,
        target: (String, u16),
        make: impl FnOnce(SharedDialer) -> TargetFuture + Send + 'static,
    ) -> Self {
        let (ev, events) = HopEvents::new(CAPACITY);
        let (inputs, input_rx) = mpsc::channel(CAPACITY);
        let (stop, stop_rx) = oneshot::channel();
        let broker = ev.broker.clone();
        let audit = ev.audit.clone();
        let task = tokio::spawn(run(hops, target, ev, make, input_rx, stop_rx));
        Self {
            protocol,
            events,
            inputs,
            broker,
            audit,
            stop: Some(stop),
            task: Some(task),
            final_event: None,
            closed: false,
        }
    }
}

/// The task: chain, then target, then pump.
async fn run(
    hops: Vec<Hop>,
    target: (String, u16),
    ev: HopEvents,
    make: impl FnOnce(SharedDialer) -> TargetFuture + Send + 'static,
    mut inputs: mpsc::Receiver<(SessionInput, Reply)>,
    mut stop: oneshot::Receiver<()>,
) {
    let tx = ev.events.clone();
    let opening = HopChain::open_hops(hops, (&target.0, target.1), &ev);
    tokio::pin!(opening);
    let opened = loop {
        tokio::select! {
            r = &mut opening => break r,
            Some((_, reply)) = inputs.recv() => { let _ = reply.send(Ok(())); }
            _ = &mut stop => {
                ev.broker.shutdown();
                let _ = tx.send(closed(CloseCode::User, "closed by user")).await;
                return;
            }
        }
    };
    let chain = match opened {
        Ok(chain) => Arc::new(chain),
        Err(e) => {
            let _ = tx.send(closed(e.close_code(), e.reason())).await;
            return;
        }
    };
    let built = tokio::select! {
        r = make(Arc::clone(&chain) as SharedDialer) => r,
        _ = &mut stop => {
            chain.close_with("closed").await;
            let _ = tx.send(closed(CloseCode::User, "closed by user")).await;
            return;
        }
    };
    let session = match built {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(error = %e, "target behind the jump hosts could not be opened");
            chain.close_with("closed").await;
            let _ = tx.send(closed(CloseCode::Network, e.to_string())).await;
            return;
        }
    };
    pump(session, &chain, &ev, inputs, stop).await;
}

async fn pump(
    mut session: Box<dyn Session>,
    chain: &HopChain,
    ev: &HopEvents,
    mut inputs: mpsc::Receiver<(SessionInput, Reply)>,
    mut stop: oneshot::Receiver<()>,
) {
    let mut watch = tokio::time::interval(HOP_WATCH);
    let last = loop {
        tokio::select! {
            event = session.next_event() => {
                drain(&mut *session, ev);
                match event {
                    Ok(Some(SessionEvent::Closed { reason, code })) => break Some((code, reason)),
                    Ok(Some(e)) => {
                        if ev.events.send(e).await.is_err() {
                            let _ = session.close().await;
                            break None;
                        }
                    }
                    Ok(None) => break Some((CloseCode::ServerEnded, "session ended".to_owned())),
                    Err(e) => break Some((CloseCode::ProtocolError, e.to_string())),
                }
            }
            Some((input, reply)) = inputs.recv() => {
                let _ = reply.send(session.send(input).await);
            }
            _ = watch.tick() => {
                if chain.lost_hop().is_some() {
                    let _ = session.close().await;
                    break Some((CloseCode::Network, "connection lost".to_owned()));
                }
            }
            _ = &mut stop => {
                let _ = session.close().await;
                // Replay the target's own final event (it carries its close code).
                let end = match session.next_event().await {
                    Ok(Some(SessionEvent::Closed { reason, code })) => (code, reason),
                    _ => (CloseCode::User, "closed by user".to_owned()),
                };
                break Some(end);
            }
        }
    };
    drain(&mut *session, ev);
    tokio::task::yield_now().await;
    let lost_hop = chain.lost_hop();
    chain.close_with(if lost_hop.is_some() { "hop_lost" } else { "closed" }).await;
    let Some((code, reason)) = last else { return };
    let end = match lost_hop {
        Some(hop) if code != CloseCode::User => {
            closed(CloseCode::HopLost, format!("jump host {} was lost", hop + 1))
        }
        _ => closed(code, reason),
    };
    let _ = ev.events.send(end).await;
}

fn drain(session: &mut dyn Session, ev: &HopEvents) {
    for e in session.take_audit_events() {
        ev.audit.push(e);
    }
}

#[async_trait]
impl Session for ViaSession {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn take_audit_events(&mut self) -> Vec<SessionAudit> {
        self.audit.take()
    }

    async fn send(&mut self, input: SessionInput) -> Result<(), MooringError> {
        if self.closed {
            return Err(MooringError::Closed);
        }
        match input {
            SessionInput::Answer { id, text } if id > HOP_PROMPT_ID_BASE => {
                if self.broker.answer_text(id, text) {
                    Ok(())
                } else {
                    Err(no_prompt())
                }
            }
            SessionInput::CredentialAnswer { id, username, domain, password }
                if id > HOP_PROMPT_ID_BASE =>
            {
                if self.broker.answer_credential(id, username, domain, password) {
                    Ok(())
                } else {
                    Err(no_prompt())
                }
            }
            other => {
                let (reply, rx) = oneshot::channel();
                self.inputs.send((other, reply)).await.map_err(|_| MooringError::Closed)?;
                rx.await.map_err(|_| MooringError::Closed)?
            }
        }
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, MooringError> {
        if let Some(e) = self.final_event.take() {
            self.closed = true;
            return Ok(Some(e));
        }
        if self.closed {
            return Ok(None);
        }
        let event = self.events.recv().await;
        if matches!(event, Some(SessionEvent::Closed { .. }) | None) {
            self.closed = true;
            self.broker.shutdown();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
        }
        Ok(event)
    }

    async fn close(&mut self) -> Result<(), MooringError> {
        if self.closed || self.final_event.is_some() {
            return Ok(());
        }
        self.broker.shutdown();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(mut task) = self.task.take() else { return Ok(()) };
        let deadline = tokio::time::sleep(CLOSE_GRACE);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut task => break,
                event = self.events.recv() => match event {
                    Some(e @ SessionEvent::Closed { .. }) => self.final_event = Some(e),
                    Some(_) => {}
                    None => break,
                },
                () = &mut deadline => {
                    task.abort();
                    break;
                }
            }
        }
        // Events still queued behind the task's end.
        while let Ok(e) = self.events.try_recv() {
            if matches!(e, SessionEvent::Closed { .. }) {
                self.final_event = Some(e);
            }
        }
        if self.final_event.is_none() {
            self.final_event = Some(closed(CloseCode::User, "closed by user"));
        }
        Ok(())
    }
}

impl Drop for ViaSession {
    fn drop(&mut self) {
        self.broker.shutdown();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
