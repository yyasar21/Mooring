//! `mooring-proto-kube`: read-only Kubernetes sessions (ADR-0014, task K3).
//!
//! * [`ReadOnlyGuard`]: a tower layer under `kube::Client` that allow-lists
//!   `(method, path template, query)` before a request leaves the process; anything else is a
//!   local [`Refused`] (`kube.refused`) recorded as `kube.request_refused`.
//! * [`KubeClient`]: `kube::Client::new(service)` over `mooring-http` (our TLS, pins, TOFU,
//!   caps). The kubeconfig CA is an exclusive anchor; without one, the ADR-0011 TOFU prompt.
//!   `kube::Config` and its loaders are never used (`clippy.toml` `disallowed-methods`).
//! * RBAC pre-flight ([`RbacSummary`]), browsing ([`PodSummary`]), [`ExecSession`] (a
//!   `Session`), bounded sanitised [`LogStream`]s and pod port-forwards
//!   ([`PortForwardStream`], loopback [`PodForward`]).

#![forbid(unsafe_code)]

mod audit;
mod auth;
mod browse;
mod client;
mod error;
mod exec;
mod frame;
pub mod fuzz;
mod guard;
mod logs;
mod portforward;
mod query;
mod rbac;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use audit::{AuditSink, KubeAudit, AUDIT_CAPACITY};
pub use auth::http_config;
pub use browse::{clean, ContainerSummary, Listing, PodSummary, MAX_PAGES};
pub use client::{KubeClient, KubeLimits, MAX_JSON_BODY, MAX_LOG_STREAMS, MAX_WS_MESSAGE};
pub use error::KubeError;
pub use exec::{ExecSession, ExecTarget, EXEC_PROTOCOLS, MAX_BYTES, RESIZE_DEBOUNCE};
pub use frame::{decode_exec, parse_status, ExecFrame, ExecStatus, FrameError, PfDecoder, PfEvent};
pub use guard::{
    check, GuardPolicy, ReadOnlyGuard, ReadOnlyGuardLayer, Refused, RequestShape, Route,
    MAX_LIST_LIMIT, MAX_TAIL_LINES,
};
pub use logs::{sanitize_line, LogChunk, LogParams, LogStream, Sanitizer, STREAM_LIMIT};
pub use portforward::{PodForward, PodTarget, PortForwardStream, MAX_CONNECTIONS_PER_FORWARD};
pub use rbac::{Identity, RbacSummary, RuleSummary};
