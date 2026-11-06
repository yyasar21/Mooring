//! Kubernetes sessions (ADR-0014 K4): no token, body, query or log byte is recorded.
//!
//! `kube_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! kube_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// A cluster session connected (`kube.cluster.opened`).
        KubeClusterOpened {
            /// Connection id.
            connection: String,
            /// API server URL.
            server: String,
            /// `SelfSubjectReview` user, when allowed.
            identity: Option<String>,
        },
        /// A cluster session ended (`kube.cluster.closed`).
        KubeClusterClosed {
            /// Connection id.
            connection: String,
            /// Safe reason.
            reason: String,
        },
        /// The read-only guard refused a request before it left the process (`kube.refused`).
        KubeRequestRefused {
            /// Connection id.
            connection: String,
            /// Upper-case method.
            method: String,
            /// Route template or `unlisted`.
            template: String,
        },
        /// An exec shell opened (`kube.exec.opened`).
        KubeExecOpened {
            /// Connection id.
            connection: String,
            /// Namespace.
            namespace: String,
            /// Pod.
            pod: String,
            /// Container, `None` = the pod's default.
            container: Option<String>,
            /// The shell (closed list).
            argv0: String,
        },
        /// An exec shell ended (`kube.exec.closed`).
        KubeExecClosed {
            /// Connection id.
            connection: String,
            /// Namespace.
            namespace: String,
            /// Pod.
            pod: String,
            /// Container.
            container: Option<String>,
            /// Close code name.
            code: String,
        },
        /// A log stream opened (`kube.logs.opened`).
        KubeLogsOpened {
            /// Connection id.
            connection: String,
            /// Stream id.
            stream: String,
            /// Namespace.
            namespace: String,
            /// Pod.
            pod: String,
            /// Container.
            container: Option<String>,
            /// `follow=true`.
            follow: bool,
        },
        /// A log stream ended (`kube.logs.closed`).
        KubeLogsClosed {
            /// Connection id.
            connection: String,
            /// Stream id.
            stream: String,
            /// Namespace.
            namespace: String,
            /// Pod.
            pod: String,
            /// Container.
            container: Option<String>,
            /// Stopped at the byte cap.
            truncated: bool,
            /// `end`, `user`, `session_closed`, `vault_locked`, or an error code.
            reason: String,
        },
        /// A pod port-forward opened (`kube.forward.opened`, ADR-0010 fields).
        KubeForwardOpened {
            /// Connection id.
            connection: String,
            /// `fwd-<n>`.
            id: String,
            /// Local listener.
            bind: String,
            /// `ns/pod:port`.
            target: String,
            /// Always `loopback` in A3.
            exposure: String,
        },
        /// A pod port-forward closed (`kube.forward.closed`).
        KubeForwardClosed {
            /// Connection id.
            connection: String,
            /// `fwd-<n>`.
            id: String,
            /// Local listener.
            bind: String,
            /// `ns/pod:port`.
            target: String,
        },
        }
    };
}
pub(crate) use kube_variants;
