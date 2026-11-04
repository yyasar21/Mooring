//! [`SessionAudit`] (drained from a protocol session) → audit log entries (ADR-0011: the
//! former SSH `TrustEvent`, now shared by SSH, RDP and VNC).

use std::sync::Mutex;

use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::{Protocol, SessionAudit};

use crate::state::record_audit;

/// Write SSH trust and forward events (`protocol = ssh`); see [`audit_session`].
pub fn audit_trust(audit: &Mutex<AuditLog>, connection: &str, events: Vec<SessionAudit>) {
    audit_session(audit, connection, Protocol::Ssh, events);
}

fn host(host: &str, port: u16) -> String {
    mooring_core::known_certs::host_key(host, port)
}

/// Write the audit events drained from a session of `protocol` into the audit log.
pub fn audit_session(
    audit: &Mutex<AuditLog>,
    connection: &str,
    protocol: Protocol,
    events: Vec<SessionAudit>,
) {
    let conn = || connection.to_owned();
    let proto = || protocol.name().to_owned();
    for e in events {
        let event = match e {
            SessionAudit::HostKeyAdded { host, port, fingerprint, stored, .. } => {
                // N-3: a key that could not be written is trusted for this session only.
                let decision = if stored { "accepted" } else { "accepted_session_only" };
                trust(format!("{host}:{port}"), fingerprint, decision, None)
            }
            SessionAudit::HostKeyRejected { host, port, fingerprint } => {
                trust(format!("{host}:{port}"), fingerprint, "rejected", None)
            }
            SessionAudit::HostKeyMismatch { host, port, presented, expected } => {
                trust(format!("{host}:{port}"), presented, "changed", Some(expected))
            }
            SessionAudit::AuthSucceeded { method } => {
                tracing::info!(method = method.as_str(), protocol = protocol.name(), "authentication succeeded");
                continue;
            }
            SessionAudit::AuthFailed => {
                tracing::info!(protocol = protocol.name(), "authentication failed");
                continue;
            }
            SessionAudit::BecomeFailed => AuditEvent::BecomeFailed { connection: conn() },
            // ADR-0010: every forward open (with its exposure) and close is audited.
            SessionAudit::ForwardOpened { id, kind, bind, target, exposure } => {
                let (kind, exposure) = (kind.to_owned(), exposure.to_owned());
                AuditEvent::ForwardOpened { connection: conn(), id, kind, bind, target, exposure }
            }
            SessionAudit::ForwardClosed { id, kind, bind, target } => {
                AuditEvent::ForwardClosed { connection: conn(), id, kind: kind.to_owned(), bind, target }
            }
            // ADR-0011 trust.cert.*
            SessionAudit::CertAdded { host: h, port, fingerprint, stored } => {
                let decision = if stored { "accepted" } else { "accepted_session_only" };
                cert(proto(), host(&h, port), fingerprint, decision, None)
            }
            SessionAudit::CertRejected { host: h, port, fingerprint } => {
                cert(proto(), host(&h, port), fingerprint, "rejected", None)
            }
            SessionAudit::CertMismatch { host: h, port, expected, presented } => {
                cert(proto(), host(&h, port), presented, "changed", Some(expected))
            }
            SessionAudit::CertCaValid { host: h, port, fingerprint } => {
                cert(proto(), host(&h, port), fingerprint, "ca_valid", None)
            }
            SessionAudit::RdpLegacySecurity => AuditEvent::SessionWeakSecurity {
                connection: conn(),
                protocol: proto(),
                security: "tls".to_owned(),
            },
            SessionAudit::VncPlaintext { security } => AuditEvent::SessionWeakSecurity {
                connection: conn(),
                protocol: proto(),
                security: security.to_owned(),
            },
            // L-27: `allowNoAuth` let a password connection take a None-only offer.
            SessionAudit::VncNoAuthAllowed => AuditEvent::SessionWeakSecurity {
                connection: conn(),
                protocol: proto(),
                security: "none_with_password".to_owned(),
            },
            SessionAudit::Clipboard { direction, bytes } => AuditEvent::SessionClipboard {
                connection: conn(),
                direction: direction.as_str().to_owned(),
                bytes,
            },
        };
        record_audit(audit, event);
    }
}

fn trust(host: String, fingerprint: String, decision: &str, expected: Option<String>) -> AuditEvent {
    AuditEvent::TrustDecision { host, fingerprint, decision: decision.to_owned(), expected }
}

/// A `cert_decision` entry.
pub fn cert(
    protocol: String,
    host: String,
    fingerprint: String,
    decision: &str,
    expected: Option<String>,
) -> AuditEvent {
    AuditEvent::CertDecision { protocol, host, fingerprint, decision: decision.to_owned(), expected }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::ClipboardDirection;

    fn log() -> (tempfile::TempDir, std::path::PathBuf, Mutex<AuditLog>) {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("audit.jsonl");
        let log = Mutex::new(AuditLog::open(&path).expect("open"));
        (dir, path, log)
    }

    #[test]
    fn become_failure_is_audited_with_the_connection() {
        let (_d, path, log) = log();
        audit_trust(&log, "conn-1", vec![SessionAudit::BecomeFailed]);
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains(r#""event":"become_failed""#), "{text}");
        assert!(text.contains(r#""connection":"conn-1""#), "{text}");
    }

    #[test]
    fn forward_events_are_audited_with_exposure() {
        let (_d, path, log) = log();
        let (bind, target) = ("0.0.0.0:8080".to_owned(), "db.example.test:5432".to_owned());
        let opened = SessionAudit::ForwardOpened {
            id: "fwd-1".into(),
            kind: "local",
            bind: bind.clone(),
            target: target.clone(),
            exposure: "external",
        };
        let closed = SessionAudit::ForwardClosed { id: "fwd-1".into(), kind: "local", bind, target };
        audit_trust(&log, "conn-1", vec![opened, closed]);
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].contains(r#""event":"forward_opened""#), "{text}");
        assert!(lines[0].contains(r#""exposure":"external""#), "{text}");
        assert!(lines[1].contains(r#""event":"forward_closed""#), "{text}");
        assert!(AuditLog::verify(&path).expect("verify").ok());
    }

    #[test]
    fn certificate_security_and_clipboard_events_map() {
        let (_d, path, log) = log();
        let (h, fp) = (|| "RDP.example.test".to_owned(), |s: &str| format!("SHA256:{s}"));
        audit_session(
            &log,
            "conn-2",
            Protocol::Rdp,
            vec![
                SessionAudit::CertAdded { host: h(), port: 3389, fingerprint: fp("a"), stored: false },
                SessionAudit::CertRejected { host: h(), port: 3389, fingerprint: fp("b") },
                SessionAudit::CertMismatch {
                    host: h(),
                    port: 3389,
                    expected: fp("old"),
                    presented: fp("new"),
                },
                SessionAudit::CertCaValid { host: h(), port: 3389, fingerprint: fp("c") },
                SessionAudit::RdpLegacySecurity,
                SessionAudit::AuthFailed,
                SessionAudit::Clipboard { direction: ClipboardDirection::FromRemote, bytes: 12 },
            ],
        );
        audit_session(&log, "conn-3", Protocol::Vnc, vec![
            SessionAudit::VncPlaintext { security: "none" },
            SessionAudit::VncNoAuthAllowed,
        ]);
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 8, "auth outcomes are traced, not audited: {text}");
        assert!(lines[0].contains(r#""decision":"accepted_session_only""#), "{text}");
        assert!(lines[0].contains(r#""host":"rdp.example.test:3389""#), "{text}");
        assert!(lines[0].contains(r#""protocol":"rdp""#), "{text}");
        assert!(lines[1].contains(r#""decision":"rejected""#), "{text}");
        assert!(lines[2].contains(r#""expected":"SHA256:old""#), "{text}");
        assert!(lines[2].contains(r#""fingerprint":"SHA256:new""#), "{text}");
        assert!(lines[3].contains(r#""decision":"ca_valid""#), "{text}");
        assert!(lines[4].contains(r#""event":"session_weak_security""#), "{text}");
        assert!(lines[4].contains(r#""security":"tls""#), "{text}");
        assert!(lines[5].contains(r#""direction":"from_remote""#) && lines[5].contains(r#""bytes":12"#));
        assert!(lines[6].contains(r#""protocol":"vnc""#) && lines[6].contains(r#""security":"none""#));
        assert!(lines[7].contains(r#""security":"none_with_password""#), "{text}");
        assert!(AuditLog::verify(&path).expect("verify").ok());
    }
}
