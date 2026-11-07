//! ADR-0025 in the Tauri layer: turn the resolved [`HopPlan`]s of a connection into
//! `mooring_proto_ssh::Hop`s (each hop's own `known_hosts` trust and agent policy, never the
//! leaf's), and put a graphical session behind a [`ViaSession`]. SSH targets open the chain
//! inside their own session task (`SshSession::connect_chain`).

use std::path::PathBuf;
use std::sync::Arc;

use mooring_core::session::Session;
use mooring_core::{MooringError, Protocol};
use mooring_proto_ssh::{Hop, SshOptions, TargetFuture, ViaSession};

use crate::commands::connect_plan::HopPlan;
use crate::error::IpcResult;
use crate::session_factory::{GraphicalConnect, SessionFactory};

/// What every hop of every chain shares: the app's SSH trust store and agent policy.
#[derive(Debug, Clone)]
pub struct HopSettings {
    /// `$APP_DATA/known_hosts` (hops are pinned like any SSH host).
    pub known_hosts: PathBuf,
    /// ADR-0007 agent policy.
    pub allow_agent: bool,
    /// ADR-0024: agent socket override and the `ssh-sk-helper` binary (setting on).
    pub agent_path: Option<PathBuf>,
    /// The `ssh-sk-helper` binary, `None` when the backend is off.
    pub sk_helper: Option<PathBuf>,
}

impl HopSettings {
    /// One `Hop` per plan, indexed in chain order.
    pub(crate) fn hops(&self, plans: Vec<HopPlan>) -> Vec<Hop> {
        plans
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let mut options = SshOptions::new(self.known_hosts.clone());
                options.allow_agent = self.allow_agent;
                crate::sk_keys::apply(&mut options, self.agent_path.clone(), self.sk_helper.clone());
                Hop {
                    params: p.params,
                    options,
                    index: u8::try_from(i).unwrap_or(u8::MAX),
                    connection: p.connection,
                }
            })
            .collect()
    }
}

/// The graphical session of `req`, directly or behind `hops`. Through a chain, the session
/// exists at once (hop progress and prompts are its first events) and the protocol crate
/// dials the target as a `direct-tcpip` of the last hop on every attempt.
pub(crate) async fn graphical(
    factory: Arc<dyn SessionFactory>,
    req: GraphicalConnect,
    hops: Vec<Hop>,
) -> IpcResult<Box<dyn Session>> {
    if hops.is_empty() {
        return factory.connect(req).await;
    }
    let protocol: Protocol = req.protocol;
    let target = (req.params.host.clone(), req.params.port);
    let make = move |dialer| -> TargetFuture {
        Box::pin(async move {
            let mut req = req;
            req.dialer = Some(dialer);
            // IpcError messages are secret-free by construction.
            factory.connect(req).await.map_err(|e| MooringError::Transport(e.message))
        })
    };
    Ok(Box::new(ViaSession::start(protocol, hops, target, make)))
}

/// How an interactive chain open ended early: safe reason and close code.
pub(crate) type ChainEnd = (String, mooring_core::CloseCode);

/// Open `hops` towards `target` for a task that owns its command queue (the Kubernetes
/// cluster task): hop events go to `emit` (`false` = the UI is gone), hop prompts are answered
/// from `rx` (`Answer` / `CredentialAnswer` with the prompt's id), other input is refused
/// until the target is up, `Close` cancels. Hop audit events land in `audit`.
pub(crate) async fn open_interactive(
    hops: Vec<Hop>,
    target: (&str, u16),
    emit: &(dyn Fn(mooring_core::SessionEvent) -> bool + Send + Sync),
    rx: &mut tokio::sync::mpsc::Receiver<crate::sessions::SessionCommand>,
    audit: &mooring_proto_ssh::AuditLog,
) -> Result<Arc<mooring_proto_ssh::HopChain>, ChainEnd> {
    use crate::error::IpcError;
    use crate::sessions::SessionCommand;
    use mooring_core::session::SessionInput;
    use mooring_core::CloseCode;

    let user = || ("closed by user".to_owned(), CloseCode::User);
    let (ev, mut events) = mooring_proto_ssh::HopEvents::new(64);
    let ev = mooring_proto_ssh::HopEvents { audit: audit.clone(), ..ev };
    let broker = ev.broker.clone();
    let opening = mooring_proto_ssh::HopChain::open_hops(hops, target, &ev);
    tokio::pin!(opening);
    let no_prompt = || IpcError::invalid("id", "no open prompt with this id");
    loop {
        tokio::select! {
            r = &mut opening => {
                // Events emitted just before the end (the last `up` / `failed`).
                while let Ok(e) = events.try_recv() {
                    let _ = emit(e);
                }
                return match r {
                    Ok(chain) => Ok(Arc::new(chain)),
                    Err(e) => Err((e.reason(), e.close_code())),
                };
            }
            Some(e) = events.recv() => {
                if !emit(e) {
                    broker.shutdown();
                    return Err(user());
                }
            }
            cmd = rx.recv() => match cmd {
                Some(SessionCommand::Input(SessionInput::Answer { id, text }, reply)) => {
                    let ok = broker.answer_text(id, text);
                    let _ = reply.send(if ok { Ok(()) } else { Err(no_prompt()) });
                }
                Some(SessionCommand::Input(
                    SessionInput::CredentialAnswer { id, username, domain, password },
                    reply,
                )) => {
                    let ok = broker.answer_credential(id, username, domain, password);
                    let _ = reply.send(if ok { Ok(()) } else { Err(no_prompt()) });
                }
                Some(SessionCommand::Input(_, reply)) => {
                    let _ = reply.send(Err(IpcError::new(
                        "session.not_connected",
                        "the jump hosts are still connecting",
                    )));
                }
                Some(SessionCommand::Close(reply)) => {
                    broker.shutdown();
                    let _ = reply.send(());
                    return Err(user());
                }
                None => {
                    broker.shutdown();
                    return Err(user());
                }
            },
        }
    }
}
