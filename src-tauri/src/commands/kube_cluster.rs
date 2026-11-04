//! The task of one cluster session (ADR-0014 K4): connect (with the ADR-0011 certificate
//! prompt; this task is the only writer of `known_kube_certs`), RBAC pre-flight, `connected`,
//! then wait for `session_close` / a vault lock / the UI going away, tear down, `closed`.

use std::path::PathBuf;

use mooring_audit::AuditEvent;
use mooring_core::known_certs::{CertProtocol, KnownCerts};
use mooring_core::session::{CloseCode, PromptPurpose, SessionInput};
use mooring_http::{HttpConfig, HttpError, TrustDecision};
use mooring_proto_kube::{KubeClient, KubeError};
use secrecy::ExposeSecret as _;
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::commands::connect_plan::KubePlan;
use crate::commands::kube_wire::{kube_error, AccessDto, ClusterEvent};
use crate::error::IpcError;
use crate::kube_sessions::KubeControl;
use crate::session_audit::cert;
use crate::session_task::finish;
use crate::sessions::{Phase, PhaseCell, SessionCommand, TaskContext};

/// Where cluster events go; `false` when the UI side is gone.
pub type ClusterSink = std::sync::Arc<dyn Fn(ClusterEvent) -> bool + Send + Sync>;

/// Certificate prompts per open (a pin that does not take must not loop).
const MAX_PROMPTS: u32 = 3;

/// Everything the cluster task owns.
pub(crate) struct ClusterStart {
    pub(crate) ctrl: KubeControl,
    pub(crate) plan: KubePlan,
    pub(crate) known_certs: PathBuf,
    pub(crate) sink: ClusterSink,
    pub(crate) ctx: TaskContext,
}

type Ended = (String, CloseCode);

fn user() -> Ended {
    ("closed by user".to_owned(), CloseCode::User)
}

fn not_connected() -> IpcError {
    IpcError::new("session.not_connected", "the cluster session is not connected yet")
}

/// Wait for `fut` while answering commands; `Err` when the session is closed meanwhile.
async fn race<T>(
    fut: impl std::future::Future<Output = T>,
    rx: &mut mpsc::Receiver<SessionCommand>,
) -> Result<T, Ended> {
    tokio::pin!(fut);
    loop {
        tokio::select! {
            r = &mut fut => return Ok(r),
            cmd = rx.recv() => match cmd {
                Some(SessionCommand::Input(_, reply)) => {
                    let _ = reply.send(Err(not_connected()));
                }
                Some(SessionCommand::Close(reply)) => {
                    let _ = reply.send(());
                    return Err(user());
                }
                None => return Err(user()),
            },
        }
    }
}

/// `yes` pins, `once` trusts for this connect only, anything else rejects.
fn answer(s: &ClusterStart, d: &TrustDecision, text: &str) -> Result<Option<[u8; 32]>, Ended> {
    let host = mooring_core::known_certs::host_key(&d.host, d.port);
    let fp = d.info.display_fingerprint();
    let audit = |decision| s.ctrl.audit(cert("kube".to_owned(), host.clone(), fp.clone(), decision, None));
    match text.trim().to_ascii_lowercase().as_str() {
        "yes" => match KnownCerts::add_and_save(&s.known_certs, &d.host, d.port, &d.fingerprint, OffsetDateTime::now_utc()) {
            Ok(()) => {
                audit("accepted");
                Ok(None)
            }
            Err(e) => {
                tracing::warn!(error = %e, "kube certificate pin not stored; trusted for this connect only");
                audit("accepted_session_only");
                Ok(Some(d.fingerprint))
            }
        },
        "once" => {
            audit("trusted_once");
            Ok(Some(d.fingerprint))
        }
        _ => {
            audit("rejected");
            Err((format!("certificate for {host} was not trusted"), CloseCode::TrustRejected))
        }
    }
}

/// Show the prompt and wait for its answer.
async fn prompt(
    s: &ClusterStart,
    rx: &mut mpsc::Receiver<SessionCommand>,
    id: u32,
    d: &TrustDecision,
) -> Result<Option<[u8; 32]>, Ended> {
    let host = mooring_core::known_certs::host_key(&d.host, d.port);
    let event = ClusterEvent::Prompt {
        id,
        message: format!("The certificate of the Kubernetes API server {host} is not trusted yet."),
        secret: false,
        purpose: PromptPurpose::CertificateTrust,
        account: None,
        certificate: Some(d.info.clone()),
    };
    if !(s.sink)(event) {
        return Err(user());
    }
    loop {
        match rx.recv().await {
            Some(SessionCommand::Input(SessionInput::Answer { id: got, text }, reply)) if got == id => {
                let _ = reply.send(Ok(()));
                return answer(s, d, text.expose_secret());
            }
            Some(SessionCommand::Input(_, reply)) => {
                let _ = reply.send(Err(IpcError::invalid("input", "answer the certificate prompt")));
            }
            Some(SessionCommand::Close(reply)) => {
                let _ = reply.send(());
                return Err(user());
            }
            None => return Err(user()),
        }
    }
}

async fn connect(s: &ClusterStart, rx: &mut mpsc::Receiver<SessionCommand>) -> Result<KubeClient, Ended> {
    let mut trusted_once = None;
    for id in 1..=MAX_PROMPTS + 1 {
        let mut tpl = HttpConfig::new(CertProtocol::Kube, "", s.known_certs.clone());
        tpl.trusted_once = trusted_once;
        let res = race(KubeClient::connect(&s.plan.resolved, &s.plan.options, tpl), rx).await?;
        let e = match res {
            Ok(client) => return Ok(client),
            Err(e) => e,
        };
        match &e {
            KubeError::Http(HttpError::TrustPrompt(d)) if id <= MAX_PROMPTS => {
                trusted_once = prompt(s, rx, id, d).await?;
                continue;
            }
            KubeError::Http(HttpError::TrustMismatch(d)) => {
                let host = mooring_core::known_certs::host_key(&d.host, d.port);
                s.ctrl.audit(cert("kube".to_owned(), host, d.info.display_fingerprint(), "changed", None));
            }
            _ => {}
        }
        tracing::info!(code = e.code(), "kubernetes connect failed");
        return Err((kube_error(&e).message, e.close_code()));
    }
    Err(("the certificate prompt did not settle".to_owned(), CloseCode::TrustRejected))
}

async fn connected(s: &ClusterStart, client: KubeClient, rx: &mut mpsc::Receiver<SessionCommand>, phase: &PhaseCell) -> Result<(), Ended> {
    s.ctrl.set_client(client.clone());
    s.ctrl.drain_audit();
    let namespace = client.default_namespace().unwrap_or("default").to_owned();
    let summary = race(client.preflight(&namespace), rx).await?;
    s.ctrl.drain_audit();
    let (rbac, identity) = match summary {
        Ok(r) => (AccessDto::from(&r), r.identity),
        // `/version` is often anonymous: a rejected token shows up in the pre-flight.
        Err(e @ KubeError::Unauthorized) => return Err((kube_error(&e).message, e.close_code())),
        Err(e) => {
            tracing::info!(code = e.code(), "kubernetes pre-flight failed");
            (AccessDto::default(), None)
        }
    };
    s.ctrl.cache_access(&namespace, rbac);
    phase.set(Phase::Connected);
    s.ctrl.audit(AuditEvent::SessionOpened {
        connection: s.ctrl.connection_id().to_owned(),
        protocol: "kubernetes".to_owned(),
        peer_identity: identity.as_ref().map(|i| i.user.clone()),
    });
    let event = ClusterEvent::Connected {
        server: client.server().to_owned(),
        identity,
        context_namespace: client.default_namespace().map(str::to_owned),
        namespace,
        rbac,
        allowed_namespaces: client.allowed_namespaces().to_vec(),
        exec_command: s.ctrl.exec_command().as_str(),
        token_expires_at: s.plan.token_expires_at.map(crate::dto::ts),
    };
    if (s.sink)(event) { Ok(()) } else { Err(user()) }
}

/// Connected: no terminal; wait for the end.
async fn serve(rx: &mut mpsc::Receiver<SessionCommand>) -> Ended {
    loop {
        match rx.recv().await {
            Some(SessionCommand::Input(_, reply)) => {
                let _ = reply.send(Err(IpcError::invalid("input", "a cluster session has no terminal")));
            }
            Some(SessionCommand::Close(reply)) => {
                let _ = reply.send(());
                return user();
            }
            None => return user(),
        }
    }
}

/// The cluster task.
pub(crate) async fn run(s: ClusterStart, mut rx: mpsc::Receiver<SessionCommand>, phase: PhaseCell) {
    let (mut reason, mut code) = match connect(&s, &mut rx).await {
        Ok(client) => match connected(&s, client, &mut rx, &phase).await {
            Ok(()) => serve(&mut rx).await,
            Err(end) => end,
        },
        Err(end) => end,
    };
    if s.ctrl.locked() {
        "vault locked".clone_into(&mut reason);
        code = CloseCode::VaultLocked;
    }
    phase.set(Phase::Closed);
    s.ctrl.teardown(if code == CloseCode::VaultLocked { "vault_locked" } else { "session_closed" });
    s.ctrl.audit(AuditEvent::KubeClusterClosed { connection: s.ctrl.connection_id().to_owned(), reason: reason.clone() });
    (s.sink)(ClusterEvent::Closed { reason: reason.clone(), code });
    finish(rx, s.ctx, &phase, reason);
}
