//! Tests of the hash-chained audit log.

use super::*;
use std::fs;

fn three(path: &Path) {
    let mut log = AuditLog::open(path).expect("open");
    log.record(AuditEvent::VaultCreated).expect("1");
    log.record(AuditEvent::VaultUnlocked).expect("2");
    log.record(AuditEvent::VaultLocked { reason: "idle".into() }).expect("3");
}

#[test]
fn trust_decision_expected_is_optional_and_keeps_old_lines_verifiable() {
    let dir = tempfile::tempdir().expect("tmp");
    let p = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&p).expect("open");
    log.record(AuditEvent::TrustDecision {
        host: "h:22".into(),
        fingerprint: "SHA256:new".into(),
        decision: "accepted".into(),
        expected: None,
    })
    .expect("1");
    log.record(AuditEvent::TrustDecision {
        host: "h:22".into(),
        fingerprint: "SHA256:new".into(),
        decision: "changed".into(),
        expected: Some("SHA256:old".into()),
    })
    .expect("2");
    let text = fs::read_to_string(&p).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines[0].contains("expected"), "{}", lines[0]);
    assert!(lines[1].contains(r#""expected":"SHA256:old""#), "{}", lines[1]);
    assert!(AuditLog::verify(&p).expect("verify").ok());
}

#[test]
fn credential_events_have_stable_wire_names() {
    let cases = [
        (
            AuditEvent::CredentialCopied { credential: "c".into(), name: "otp".into() },
            "credential_copied",
        ),
        (AuditEvent::CredentialOtpAttached { credential: "c".into() }, "credential_otp_attached"),
        (
            AuditEvent::CredentialPrompted { connection: "x".into(), username: "u".into() },
            "credential_prompted",
        ),
        (AuditEvent::CredentialResealed { count: 3 }, "credential_resealed"),
        (AuditEvent::BecomeFailed { connection: "x".into() }, "become_failed"),
        (
            AuditEvent::VaultPolicyChanged {
                idle_minutes: Some(15),
                on_screen_lock: true,
                on_sleep: true,
                on_window_hidden: false,
            },
            "vault_policy_changed",
        ),
        (
            AuditEvent::AuditSyslogChanged {
                enabled: true,
                host: "logs.example.test".into(),
                port: 6514,
                transport: "tls".into(),
                facility: 13,
            },
            "audit_syslog_changed",
        ),
        (
            AuditEvent::AuditSyslogStarted {
                enabled: false,
                host: "logs.example.test".into(),
                port: 6514,
                transport: "tls".into(),
            },
            "audit_syslog_started",
        ),
        (AuditEvent::AuditHeartbeat { seq: 3 }, "audit_heartbeat"),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name);
    }
}

#[test]
fn forward_and_sftp_events_have_stable_wire_names() {
    let (c, s) = (|| "x".to_owned(), |v: &str| v.to_owned());
    let cases = [
        (
            AuditEvent::ForwardOpened {
                connection: c(),
                id: s("fwd-1"),
                kind: s("local"),
                bind: s("127.0.0.1:1"),
                target: s("db.example.test:5432"),
                exposure: s("external"),
            },
            "forward_opened",
        ),
        (
            AuditEvent::ForwardClosed {
                connection: c(),
                id: s("fwd-1"),
                kind: s("dynamic"),
                bind: s("127.0.0.1:1"),
                target: s("socks5"),
            },
            "forward_closed",
        ),
        (
            AuditEvent::SftpTransfer {
                connection: c(),
                transfer: s("t"),
                direction: s("upload"),
                bytes: 7,
                outcome: s("done"),
            },
            "sftp_transfer",
        ),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name);
        assert_eq!(serde_json::from_value::<AuditEvent>(v).expect("round trip"), e);
    }
}

#[test]
fn chain_verifies_and_survives_reopen() {
    let dir = tempfile::tempdir().expect("tmp");
    let p = dir.path().join("audit.jsonl");
    three(&p);
    let mut again = AuditLog::open(&p).expect("reopen");
    let e = again.record(AuditEvent::PasswordChanged).expect("4");
    assert_eq!(e.seq, 4);
    let r = AuditLog::verify(&p).expect("verify");
    assert!(r.ok());
    assert_eq!(r.entries, 4);
}

#[test]
fn deleting_or_editing_a_line_breaks_the_chain() {
    let dir = tempfile::tempdir().expect("tmp");
    let p = dir.path().join("audit.jsonl");
    three(&p);
    let text = fs::read_to_string(&p).expect("read");
    let lines: Vec<&str> = text.lines().collect();

    // delete the middle line
    fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).expect("write");
    assert_eq!(AuditLog::verify(&p).expect("v").broken_at, Some(2));

    // edit the first line's event
    let edited = lines[0].replace("vault_created", "vault_unlocked");
    fs::write(&p, format!("{}\n{}\n{}\n", edited, lines[1], lines[2])).expect("write");
    assert_eq!(AuditLog::verify(&p).expect("v").broken_at, Some(2));
}

#[test]
fn graphical_session_events_have_stable_wire_names() {
    let s = |v: &str| v.to_owned();
    let cases = [
        (
            AuditEvent::CertDecision {
                protocol: s("rdp"),
                host: s("h.example.test:3389"),
                fingerprint: s("SHA256:00"),
                decision: s("ca_valid"),
                expected: None,
            },
            "cert_decision",
        ),
        (
            AuditEvent::CertRemoved { protocol: s("vnc"), host: s("h:5900"), removed: 1 },
            "cert_removed",
        ),
        (
            AuditEvent::SessionWeakSecurity {
                connection: s("c"),
                protocol: s("rdp"),
                security: s("tls"),
            },
            "session_weak_security",
        ),
        (
            AuditEvent::SessionClipboard {
                connection: s("c"),
                direction: s("to_remote"),
                bytes: 3,
            },
            "session_clipboard",
        ),
        (
            AuditEvent::SessionScreenshot { connection: s("c"), width: 2, height: 1 },
            "session_screenshot",
        ),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name);
        assert!(v.get("expected").is_none(), "absent when None: {v}");
    }
}

#[cfg(unix)]
#[test]
fn file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tmp");
    let p = dir.path().join("audit.jsonl");
    three(&p);
    let mode = fs::metadata(&p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
