//! Security-relevant session events for the Tauri layer to append to the audit log
//! (ADR-0011: `TrustEvent` moves to core as [`SessionAudit`]).
//!
//! Protocol crates do not depend on `mooring-audit`; they record [`SessionAudit`]s that the
//! caller drains with [`crate::Session::take_audit_events`]. Events never carry secret
//! material or clipboard text. `mooring_proto_ssh::TrustEvent` is a re-export of this type.

/// Authentication method that succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// SSH `publickey` with the vault key.
    PublicKey,
    /// SSH `publickey` through the ssh-agent.
    Agent,
    /// SSH `password`.
    Password,
    /// SSH `keyboard-interactive`.
    KeyboardInteractive,
    /// RDP `CredSSP` / NLA (`NTLMv2`).
    Nla,
    /// RDP TLS without NLA (`allowTlsWithoutNla`).
    RdpTls,
    /// VNC Authentication (type 2), also inside `VeNCrypt` `X509Vnc`.
    VncAuth,
    /// `VeNCrypt` `X509Plain` (username + password inside TLS).
    VncPlain,
    /// No authentication (VNC None / `X509None`).
    None,
}

impl AuthMethod {
    /// Stable name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicKey => "publickey",
            Self::Agent => "agent",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard-interactive",
            Self::Nla => "nla",
            Self::RdpTls => "tls",
            Self::VncAuth => "vnc-auth",
            Self::VncPlain => "vencrypt-plain",
            Self::None => "none",
        }
    }
}

/// Direction of a clipboard transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardDirection {
    /// Local → remote.
    ToRemote,
    /// Remote → local.
    FromRemote,
}

impl ClipboardDirection {
    /// `to_remote` / `from_remote`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToRemote => "to_remote",
            Self::FromRemote => "from_remote",
        }
    }
}

/// One audit-worthy event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAudit {
    /// The user trusted a new SSH host key (TOFU "yes").
    HostKeyAdded {
        /// Host as given.
        host: String,
        /// Port.
        port: u16,
        /// Key type, e.g. `ssh-ed25519`.
        key_type: String,
        /// `SHA256:<base64>`.
        fingerprint: String,
        /// Whether it was written to `known_hosts`; `false` means trusted for this session
        /// only (full disk, file over the caps; review 2 ruling D4 / N-3).
        stored: bool,
    },
    /// The user declined a new host key.
    HostKeyRejected {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// `SHA256:<base64>` of the declined key.
        fingerprint: String,
    },
    /// The stored key differs from the presented one; the connection was stopped.
    HostKeyMismatch {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// Stored fingerprint (or `revoked`).
        expected: String,
        /// Presented fingerprint.
        presented: String,
    },
    /// Authentication succeeded with this method.
    AuthSucceeded {
        /// Method.
        method: AuthMethod,
    },
    /// Every method failed.
    AuthFailed,
    /// A port forward started listening (ADR-0007 §Channels and flow).
    ForwardOpened {
        /// Session-local id, e.g. `fwd-1`.
        id: String,
        /// `local`, `remote` or `dynamic`.
        kind: &'static str,
        /// Address actually bound (local side for local/dynamic, server side for remote).
        bind: String,
        /// Where connections go (`host:port`, or `socks5` for dynamic).
        target: String,
        /// `loopback` or `external` (security review 2 M-2).
        exposure: &'static str,
    },
    /// A port forward stopped (by the user or because the session ended).
    ForwardClosed {
        /// Session-local id.
        id: String,
        /// `local`, `remote` or `dynamic`.
        kind: &'static str,
        /// Bound address.
        bind: String,
        /// Target.
        target: String,
    },
    /// Privilege escalation (`become`) was refused by the server (review 3, M-6).
    BecomeFailed,
    /// The user trusted a new server certificate (TOFU "yes", ADR-0011).
    CertAdded {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// `SHA256:<hex>`.
        fingerprint: String,
        /// Whether the pin was written to `known_*_certs`.
        stored: bool,
    },
    /// The user declined a new server certificate.
    CertRejected {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// `SHA256:<hex>`.
        fingerprint: String,
    },
    /// A pinned certificate changed (or TLS was stripped after a pin, ADR-0012: then
    /// `presented` is `none`): hard stop.
    CertMismatch {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// Stored pin, `SHA256:<hex>`.
        expected: String,
        /// Presented, `SHA256:<hex>` or `none`.
        presented: String,
    },
    /// No pin and the chain validated against the system roots / `caPem`.
    CertCaValid {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// `SHA256:<hex>`.
        fingerprint: String,
    },
    /// RDP connected with TLS but without NLA (`allowTlsWithoutNla`).
    RdpLegacySecurity,
    /// VNC connected without TLS (`Connected.security` `none` or `vnc-auth`).
    VncPlaintext {
        /// `none` or `vnc-auth`.
        security: &'static str,
    },
    /// VNC took a None-only offer although a password is configured (`allowNoAuth`, L-27).
    VncNoAuthAllowed,
    /// Clipboard text crossed the session (coalesced: at most one per second per direction).
    Clipboard {
        /// Direction.
        direction: ClipboardDirection,
        /// UTF-8 bytes transferred since the previous entry.
        bytes: u64,
    },
}

impl SessionAudit {
    /// Audit action name, e.g. `trust.host_key.added`.
    pub fn action(&self) -> &'static str {
        match self {
            Self::HostKeyAdded { .. } => "trust.host_key.added",
            Self::HostKeyRejected { .. } => "trust.host_key.rejected",
            Self::HostKeyMismatch { .. } => "trust.host_key.mismatch",
            Self::AuthSucceeded { .. } => "session.auth.succeeded",
            Self::AuthFailed => "session.auth.failed",
            Self::ForwardOpened { .. } => "session.forward.open",
            Self::ForwardClosed { .. } => "session.forward.close",
            Self::BecomeFailed => "session.become.failed",
            Self::CertAdded { .. } => "trust.cert.added",
            Self::CertRejected { .. } => "trust.cert.rejected",
            Self::CertMismatch { .. } => "trust.cert.mismatch",
            Self::CertCaValid { .. } => "trust.cert.ca_valid",
            Self::RdpLegacySecurity => "session.rdp.legacy_security",
            Self::VncPlaintext { .. } => "session.vnc.plaintext",
            Self::VncNoAuthAllowed => "session.vnc.no_auth_allowed",
            Self::Clipboard { .. } => "session.clipboard",
        }
    }
}

/// Most audit events an [`AuditBuffer`] keeps before the oldest are dropped (a caller that
/// never drains).
pub const MAX_AUDIT: usize = 4096;

/// Shared, append-only buffer of [`SessionAudit`]s. A graphical session pushes; the Tauri layer
/// drains it through `Session::take_audit_events` or through its own clone (useful while the
/// session is owned by a task). `mooring_proto_rdp::AuditSink` and
/// `mooring_proto_vnc::AuditLog` are this type.
#[derive(Debug, Clone, Default)]
pub struct AuditBuffer(std::sync::Arc<std::sync::Mutex<Vec<SessionAudit>>>);

impl AuditBuffer {
    /// Empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one event (the oldest is dropped beyond [`MAX_AUDIT`]).
    pub fn push(&self, event: SessionAudit) {
        tracing::debug!(action = event.action(), "session audit event");
        let mut v = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if v.len() >= MAX_AUDIT {
            v.remove(0);
        }
        v.push(event);
    }

    /// Drain everything recorded so far.
    pub fn take(&self) -> Vec<SessionAudit> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names_are_stable() {
        let host = || "h.example.test".to_owned();
        let fp = || "SHA256:00".to_owned();
        for (e, want) in [
            (SessionAudit::AuthFailed, "session.auth.failed"),
            (
                SessionAudit::CertAdded { host: host(), port: 1, fingerprint: fp(), stored: true },
                "trust.cert.added",
            ),
            (
                SessionAudit::CertRejected { host: host(), port: 1, fingerprint: fp() },
                "trust.cert.rejected",
            ),
            (
                SessionAudit::CertMismatch {
                    host: host(),
                    port: 1,
                    expected: fp(),
                    presented: fp(),
                },
                "trust.cert.mismatch",
            ),
            (
                SessionAudit::CertCaValid { host: host(), port: 1, fingerprint: fp() },
                "trust.cert.ca_valid",
            ),
            (SessionAudit::RdpLegacySecurity, "session.rdp.legacy_security"),
            (SessionAudit::VncPlaintext { security: "none" }, "session.vnc.plaintext"),
            (SessionAudit::VncNoAuthAllowed, "session.vnc.no_auth_allowed"),
            (
                SessionAudit::Clipboard { direction: ClipboardDirection::FromRemote, bytes: 3 },
                "session.clipboard",
            ),
        ] {
            assert_eq!(e.action(), want);
        }
        assert_eq!(AuthMethod::Nla.as_str(), "nla");
        assert_eq!(AuthMethod::KeyboardInteractive.as_str(), "keyboard-interactive");
        assert_eq!(ClipboardDirection::ToRemote.as_str(), "to_remote");
    }

    #[test]
    fn audit_buffer_is_shared_capped_and_drained() {
        let a = AuditBuffer::new();
        let b = a.clone();
        for _ in 0..MAX_AUDIT + 3 {
            a.push(SessionAudit::AuthFailed);
        }
        b.push(SessionAudit::RdpLegacySecurity);
        let all = a.take();
        assert_eq!(all.len(), MAX_AUDIT);
        assert_eq!(all.last(), Some(&SessionAudit::RdpLegacySecurity));
        assert!(b.take().is_empty());
    }
}
