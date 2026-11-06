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
        (
            AuditEvent::WebOpened {
                connection: s("c"),
                origin: s("https://a.test"),
                persistent: false,
            },
            "web_opened",
        ),
        (AuditEvent::WebClosed { connection: s("c") }, "web_closed"),
        (
            AuditEvent::WebNavigationBlocked { connection: s("c"), origin: s("https://b.test") },
            "web_navigation_blocked",
        ),
        (
            AuditEvent::WebDownloadBlocked { connection: s("c"), origin: s("https://a.test") },
            "web_download_blocked",
        ),
        (AuditEvent::WebDataCleared { connection: s("c") }, "web_data_cleared"),
        (AuditEvent::SessionDetached { connection: s("c"), session: s("s") }, "session_detached"),
        (AuditEvent::SessionAttached { connection: s("c"), session: s("s") }, "session_attached"),
        (
            AuditEvent::VsphereSyncStarted { connection: s("c"), trigger: s("manual") },
            "vsphere_sync_started",
        ),
        (
            AuditEvent::VsphereSyncFinished {
                connection: s("c"),
                added: 1,
                changed: 0,
                missing: 0,
                removed: 0,
                ms: 3,
            },
            "vsphere_sync_finished",
        ),
        (
            AuditEvent::VsphereSyncFailed { connection: s("c"), code: s("vsphere.failed") },
            "vsphere_sync_failed",
        ),
        (
            AuditEvent::VspherePower {
                connection: s("c"),
                vm: s("vm-1"),
                action: s("stop"),
                outcome: s("done"),
            },
            "vsphere_power",
        ),
        (
            AuditEvent::VsphereConsole { connection: s("c"), vm: s("vm-1"), kind: s("vmrc") },
            "vsphere_console",
        ),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name);
        assert!(v.get("expected").is_none(), "absent when None: {v}");
    }
}

#[test]
fn confirm_refused_has_a_stable_wire_name() {
    let e = AuditEvent::ConfirmRefused {
        kind: "vsphere_power".to_owned(),
        target: "c/vm-1".to_owned(),
        reason: "busy".to_owned(),
    };
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(v["event"], "confirm_refused");
    assert_eq!(v["reason"], "busy");
    let v = serde_json::to_value(AuditEvent::ConfirmRefusedSuppressed { count: 7 }).expect("json");
    assert_eq!(
        (v["event"].clone(), v["count"].clone()),
        ("confirm_refused_suppressed".into(), 7.into())
    );
    let v = serde_json::to_value(AuditEvent::NetSuppressed { count: 9 }).expect("json");
    assert_eq!((v["event"].clone(), v["count"].clone()), ("net_suppressed".into(), 9.into()));
}

/// ADR-0018 §3: the four updater rows carry versions and codes only.
#[test]
fn update_events_have_stable_wire_names() {
    let s = |x: &str| x.to_owned();
    let cases = [
        (AuditEvent::UpdateCheck { current: s("0.1.0"), available: None }, "update.check"),
        (AuditEvent::UpdateInstall { from: s("0.1.0"), to: s("0.2.0") }, "update.install"),
        (AuditEvent::UpdateRefused { code: s("update.manual_only") }, "update.refused"),
        (AuditEvent::UpdateSettingsChanged { background_check: true }, "update.settings_changed"),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name);
        let back: AuditEvent = serde_json::from_value(v).expect("round trip");
        assert_eq!(back, e);
    }
    let v = serde_json::to_value(AuditEvent::UpdateCheck {
        current: s("0.1.0"),
        available: Some(s("0.2.0")),
    })
    .expect("json");
    assert_eq!(v["available"], "0.2.0");
}

/// ADR-0020 §6: the network-tool rows carry names and counts only.
#[test]
fn net_events_serialize_names_and_counts() {
    let v = serde_json::to_value(AuditEvent::NetTcpCheck {
        host: "h.example.test".into(),
        port: 22,
        outcome: "open".into(),
    })
    .expect("json");
    assert_eq!(v["event"], "net_tcp_check");
    assert_eq!((v["port"].clone(), v["outcome"].clone()), (22.into(), "open".into()));
    let v = serde_json::to_value(AuditEvent::NetPing { host: "h".into(), sent: 4, received: 3 })
        .expect("json");
    assert_eq!((v["event"].clone(), v["received"].clone()), ("net_ping".into(), 3.into()));
    let v = serde_json::to_value(AuditEvent::NetTraceroute { host: "h".into(), hops: 9 })
        .expect("json");
    assert_eq!(v["event"], "net_traceroute");
    let v = serde_json::to_value(AuditEvent::NetWgStatus { interfaces: vec!["wg0".into()] })
        .expect("json");
    assert_eq!(
        (v["event"].clone(), v["interfaces"][0].clone()),
        ("net_wg_status".into(), "wg0".into())
    );
}

#[test]
fn trust_conflict_has_a_stable_wire_name() {
    let e = AuditEvent::TrustConflict {
        file: "known_rdp_certs".to_owned(),
        host: "rdp.example.test:3389".to_owned(),
    };
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(
        (v["event"].clone(), v["file"].clone()),
        ("trust_conflict".into(), "known_rdp_certs".into())
    );
}

#[test]
fn suppressed_refusal_summaries_have_stable_wire_names() {
    let web = AuditEvent::WebNavigationBlockedSuppressed { connection: "c".to_owned(), count: 40 };
    let v = serde_json::to_value(&web).expect("json");
    assert_eq!(
        (v["event"].clone(), v["count"].clone()),
        ("web_navigation_blocked_suppressed".into(), 40.into())
    );
    let oidc = AuditEvent::SecretRefusedSuppressed {
        source: "s".to_owned(),
        action: "oidc_navigation".to_owned(),
        count: 48,
    };
    let v = serde_json::to_value(&oidc).expect("json");
    assert_eq!(
        (v["event"].clone(), v["count"].clone()),
        ("secret_refused_suppressed".into(), 48.into())
    );
}

#[test]
fn secret_events_have_stable_wire_names() {
    let s = |v: &str| v.to_owned();
    let cases = [
        (AuditEvent::SecretLogin { source: s("s"), method: s("approle"), ttl: 60 }, "secret_login"),
        (
            AuditEvent::SecretResolved {
                connection: Some(s("c")),
                credential: s("r"),
                source: s("s"),
                reference: s("secret/servers/web"),
                version: 2,
                target_kind: s("user_password"),
                fields: vec![s("password"), s("username")],
            },
            "secret_resolved",
        ),
        (
            AuditEvent::SecretFailed { connection: None, source: s("s"), category: s("tls") },
            "secret_failed",
        ),
        (AuditEvent::SecretRevoked { source: s("s") }, "secret_revoked"),
        (
            AuditEvent::SecretSourceChanged {
                source: s("s"),
                changed: vec![s("caPem")],
                ca_pem: vec![s("SHA256:00")],
                warning: true,
            },
            "secret_source_changed",
        ),
        (
            AuditEvent::SecretRefused {
                source: None,
                action: s("oidc_navigation"),
                detail: s("https://evil.example.test"),
            },
            "secret_refused",
        ),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name, "{v}");
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
