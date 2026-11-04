//! Kubernetes audit events (ADR-0014 §6). Like the other protocol crates this one does not
//! depend on `mooring-audit`: it records [`KubeAudit`]s into an [`AuditSink`] that the Tauri
//! layer (K4) drains and appends to the hash-chained log. No event carries a token, a path
//! with concrete names of refused requests, a query, a body or terminal/log bytes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use mooring_core::SessionAudit;

/// Events kept before the oldest are dropped (and counted) — K4 drains far more often.
pub const AUDIT_CAPACITY: usize = 1024;

/// One audit-worthy Kubernetes event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubeAudit {
    /// The [`crate::ReadOnlyGuard`] refused a request before it left the process.
    RequestRefused {
        /// Upper-case method or `OTHER`.
        method: &'static str,
        /// Route template or `unlisted`.
        template: &'static str,
    },
    /// The client reached the API server and identified itself.
    Connected {
        /// API server URL (no credentials by construction).
        server: String,
        /// `SelfSubjectReview` user name, when allowed.
        identity: Option<String>,
    },
    /// An exec shell opened.
    ExecOpened {
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container (`None` = the pod's default).
        container: Option<String>,
        /// The shell (closed list).
        argv0: &'static str,
    },
    /// An exec shell ended.
    ExecClosed {
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container.
        container: Option<String>,
        /// `CloseCode` name.
        code: &'static str,
    },
    /// A log stream opened.
    LogsOpened {
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container.
        container: Option<String>,
        /// `follow=true`.
        follow: bool,
    },
    /// A generic session event (`session.forward.open/close` with kind `pod`).
    Session(SessionAudit),
}

impl KubeAudit {
    /// Audit action name.
    pub fn action(&self) -> &'static str {
        match self {
            Self::RequestRefused { .. } => "kube.request_refused",
            Self::Connected { .. } => "kube.connected",
            Self::ExecOpened { .. } => "kube.exec.opened",
            Self::ExecClosed { .. } => "kube.exec.closed",
            Self::LogsOpened { .. } => "kube.logs.opened",
            Self::Session(s) => s.action(),
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    events: VecDeque<KubeAudit>,
    dropped: u64,
}

/// A bounded, shared queue of [`KubeAudit`]s (cheap to clone).
#[derive(Debug, Clone, Default)]
pub struct AuditSink(Arc<Mutex<Inner>>);

impl AuditSink {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record an event (drops the oldest above [`AUDIT_CAPACITY`]).
    pub fn push(&self, event: KubeAudit) {
        let mut g = self.lock();
        if g.events.len() >= AUDIT_CAPACITY {
            g.events.pop_front();
            g.dropped += 1;
        }
        g.events.push_back(event);
    }

    /// Take everything recorded so far.
    pub fn take(&self) -> Vec<KubeAudit> {
        self.lock().events.drain(..).collect()
    }

    /// Events dropped because nobody drained the queue (K4 should log this as a gap).
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}
