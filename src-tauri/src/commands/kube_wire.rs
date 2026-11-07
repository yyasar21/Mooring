//! Wire shapes, error codes and audit mapping of the Kubernetes commands (ADR-0014 K4).
//!
//! Events of the cluster channel use the session-event conventions (`kind` tag, base64
//! never needed); new fields are camelCase like the command results.

use base64::Engine as _;
use mooring_audit::AuditEvent;
use mooring_core::known_certs::CertificateInfo;
use mooring_core::session::{CloseCode, PromptAccount, PromptPurpose};
use mooring_http::HttpError;
use mooring_proto_kube::{Identity, KubeAudit, KubeError, LogChunk, RbacSummary};
use mooring_core::SessionAudit;
use serde::Serialize;

use crate::error::IpcError;

/// `kube_access` result: what the identity may do in one namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // the IPC shape is five flags (ADR-0014 §6)
pub struct AccessDto {
    /// `list pods`.
    pub list_pods: bool,
    /// `get pods/log`.
    pub get_logs: bool,
    /// `create pods/exec`.
    pub exec: bool,
    /// `create pods/portforward`.
    pub port_forward: bool,
    /// `list namespaces` (cluster scope).
    pub list_namespaces: bool,
}

impl From<&RbacSummary> for AccessDto {
    fn from(r: &RbacSummary) -> Self {
        Self {
            list_pods: r.can_list_pods,
            get_logs: r.can_get_logs,
            exec: r.can_exec,
            port_forward: r.can_port_forward,
            list_namespaces: r.can_list_namespaces,
        }
    }
}

/// `kube_open` `onEvent` messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterEvent {
    /// Reached the API server; RBAC pre-flight of `namespace` done.
    #[serde(rename_all = "camelCase")]
    Connected {
        /// API server URL.
        server: String,
        /// `SelfSubjectReview`, `null` when not allowed.
        identity: Option<Identity>,
        /// Options namespace, then the context namespace.
        context_namespace: Option<String>,
        /// The namespace `rbac` is for (`contextNamespace` or `default`).
        namespace: String,
        /// Pre-flight of `namespace`.
        rbac: AccessDto,
        /// Offered when `list namespaces` is denied.
        allowed_namespaces: Vec<String>,
        /// Default exec shell of the connection.
        exec_command: &'static str,
        /// RFC 3339 `exp` of a JWT bearer token, read **unverified**, display only.
        token_expires_at: Option<String>,
    },
    /// The certificate prompt (`purpose: certificate_trust`); answer with `session_send`
    /// `{ kind: "answer", id, text: "yes" | "once" | "no" }`.
    Prompt {
        /// Prompt id.
        id: u32,
        /// Safe text.
        message: String,
        /// Always `false`.
        secret: bool,
        /// `certificate_trust`.
        purpose: PromptPurpose,
        /// Always `null`.
        account: Option<PromptAccount>,
        /// The API server certificate (`null` for a jump host's prompt).
        certificate: Option<CertificateInfo>,
        /// ADR-0025: the jump host asking (host key, keyboard-interactive, sign-in form);
        /// absent for the API server's certificate prompt.
        #[serde(skip_serializing_if = "Option::is_none")]
        hop: Option<u8>,
    },
    /// ADR-0025: progress of one jump host towards the API server (same shape as the
    /// terminal sessions' `hop_status`).
    HopStatus {
        /// 0-based position in the chain.
        hop: u8,
        /// Hops in the chain.
        of: u8,
        /// `connecting` | `authenticating` | `up` | `failed`.
        state: mooring_core::HopState,
        /// `host:port` of the hop.
        host: String,
        /// Host key fingerprint once known.
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_identity: Option<String>,
    },
    /// Ended (always last).
    Closed {
        /// Safe reason.
        reason: String,
        /// Cause (`user`, `vault_locked`, `auth_failed`, `trust_rejected`, `network`, ...).
        code: CloseCode,
    },
}

/// `kube_logs_open` `onChunk` messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogChunkDto {
    /// Sanitised UTF-8 text, base64.
    Data {
        /// Base64.
        data: String,
    },
    /// The stream ended (always last).
    End {
        /// Stopped at `maxLogBytes`.
        truncated: bool,
        /// `kube.stream_limit` at the cap, an error code, or `null`.
        reason: Option<String>,
    },
}

impl From<LogChunk> for LogChunkDto {
    fn from(c: LogChunk) -> Self {
        match c {
            LogChunk::Data(d) => {
                Self::Data { data: base64::engine::general_purpose::STANDARD.encode(d) }
            }
            LogChunk::End { truncated, reason } => {
                Self::End { truncated, reason: reason.map(str::to_owned) }
            }
        }
    }
}

/// `KubeError` → `IpcError` with literal codes (so `ipc-codes.json` lists them).
pub fn kube_error(e: &KubeError) -> IpcError {
    let msg = e.to_string();
    let code = match e {
        KubeError::Forbidden(_) => "kube.refused",
        KubeError::StreamLimit => "kube.stream_limit",
        KubeError::RbacDenied => "kube.rbac_denied",
        KubeError::NotFound => "kube.not_found",
        KubeError::Unauthorized => "kube.auth_failed",
        KubeError::UnsupportedAuth(_) => "kube.unsupported_auth",
        KubeError::Invalid(r) => return IpcError::invalid("kubernetes request", r),
        KubeError::Status(_) => "kube.status",
        KubeError::Protocol(_) => "kube.protocol",
        KubeError::Closed => "kube.closed",
        KubeError::Http(HttpError::TrustMismatch(_)) => "session.trust_mismatch",
        KubeError::Http(HttpError::TrustConflict(_)) => "http.trust_conflict",
        KubeError::Http(HttpError::TrustRejected(_) | HttpError::TrustPrompt(_)) => {
            "session.trust_rejected"
        }
        KubeError::Http(h) => {
            tracing::info!(code = h.code(), "kubernetes transport error");
            "kube.unreachable"
        }
    };
    IpcError::new(code, msg)
}

/// A `kube.logs.closed` entry.
pub fn logs_closed(
    connection: &str,
    stream: &str,
    target: (String, String, Option<String>),
    truncated: bool,
    reason: &str,
) -> AuditEvent {
    let (namespace, pod, container) = target;
    AuditEvent::KubeLogsClosed {
        connection: connection.to_owned(),
        stream: stream.to_owned(),
        namespace,
        pod,
        container,
        truncated,
        reason: reason.to_owned(),
    }
}

/// One drained [`KubeAudit`] as an audit-log entry (`None`: recorded elsewhere).
pub fn audit_event(connection: &str, e: KubeAudit) -> Option<AuditEvent> {
    let connection = connection.to_owned();
    Some(match e {
        KubeAudit::RequestRefused { method, template } => AuditEvent::KubeRequestRefused {
            connection,
            method: method.to_owned(),
            template: template.to_owned(),
        },
        KubeAudit::Connected { server, identity } => {
            AuditEvent::KubeClusterOpened { connection, server, identity }
        }
        KubeAudit::ExecOpened { namespace, pod, container, argv0 } => {
            AuditEvent::KubeExecOpened { connection, namespace, pod, container, argv0: argv0.to_owned() }
        }
        KubeAudit::ExecClosed { namespace, pod, container, code } => {
            AuditEvent::KubeExecClosed { connection, namespace, pod, container, code: code.to_owned() }
        }
        // `kube_logs_open` records `kube.logs.opened` itself, with the stream id.
        KubeAudit::LogsOpened { .. } => return None,
        KubeAudit::Session(SessionAudit::ForwardOpened { id, bind, target, exposure, .. }) => {
            AuditEvent::KubeForwardOpened { connection, id, bind, target, exposure: exposure.to_owned() }
        }
        KubeAudit::Session(SessionAudit::ForwardClosed { id, bind, target, .. }) => {
            AuditEvent::KubeForwardClosed { connection, id, bind, target }
        }
        KubeAudit::Session(other) => {
            tracing::debug!(action = other.action(), "unmapped kubernetes session audit");
            return None;
        }
    })
}

impl ClusterEvent {
    /// A jump host's event of the chain phase (ADR-0025); `None` for anything else.
    pub fn from_hop(e: mooring_core::SessionEvent) -> Option<Self> {
        use mooring_core::SessionEvent as E;
        match e {
            E::HopStatus { hop, of, state, host, peer_identity } => {
                Some(Self::HopStatus { hop, of, state, host, peer_identity })
            }
            E::Prompt { id, message, secret, purpose, account, certificate, hop } => {
                Some(Self::Prompt { id, message, secret, purpose, account, certificate, hop })
            }
            _ => None,
        }
    }
}
