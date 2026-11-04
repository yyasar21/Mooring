//! Syslog commands against loopback collectors (127.0.0.1 only).

use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

use super::*;
use crate::state::testing::*;

fn udp_collector() -> (UdpSocket, u16) {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let port = s.local_addr().expect("addr").port();
    (s, port)
}

fn recv(s: &UdpSocket) -> String {
    let mut buf = [0u8; 9000];
    let n = s.recv(&mut buf).expect("datagram");
    String::from_utf8(buf[..n].to_vec()).expect("utf8")
}

fn udp(port: u16, enabled: bool) -> SyslogConfig {
    parse("127.0.0.1", i64::from(port), "udp", 13, enabled).expect("valid")
}

#[test]
fn parse_table() {
    assert!(parse("logs.example.test", 6514, "tls", 23, true).is_ok());
    assert!(parse("192.0.2.7", 1, "tcp", 0, false).is_ok());
    assert_eq!(parse("192.0.2.7", 1, "tcp", "local4", false).expect("keyword").facility, 20);
    assert!(parse("192.0.2.7", 1, "tcp", "LOCAL4", false).is_err());
    assert!(parse("192.0.2.7", 1, "tcp", "bogus", false).is_err());
    let cases: &[(&str, i64, &str, i64, &str)] = &[
        ("logs.example.test", 0, "udp", 1, "port"),
        ("logs.example.test", -1, "udp", 1, "port"),
        ("logs.example.test", 65536, "udp", 1, "port"),
        ("logs.example.test", i64::MAX, "udp", 1, "port"),
        ("logs.example.test", 514, "udp", 24, "facility"),
        ("logs.example.test", 514, "udp", -1, "facility"),
        ("logs.example.test", 514, "UDP", 1, "transport"),
        ("logs.example.test", 514, "quic", 1, "transport"),
        ("", 514, "udp", 1, "host"),
        ("https://logs.example.test/", 514, "udp", 1, "host"),
        ("logs.example.test:514", 514, "udp", 1, "host"),
        ("logs\u{0}.example.test", 514, "udp", 1, "host"),
        ("logs.example.test\u{202e}", 514, "udp", 1, "host"),
    ];
    for (host, port, transport, facility, field) in cases {
        let e = parse(host, *port, transport, *facility, true).expect_err("invalid");
        assert_eq!(e.code, "input.invalid");
        assert!(e.message.contains(field), "{host:?} {port} {transport} {facility}: {}", e.message);
        assert!(host.is_empty() || !e.message.contains(host), "value echoed: {}", e.message);
    }
    let huge = "a".repeat(100_000);
    assert_eq!(parse(&huge, 514, "udp", 1, true).expect_err("huge").code, "input.invalid");
}

#[test]
fn set_mirrors_entries_get_reports_counters_and_disable_stops() {
    let f = unlocked();
    let (server, port) = udp_collector();
    let st = set(&f.state, udp(port, true), TlsRoots::System).expect("set");
    assert!(st.running);
    // the change itself is the first mirrored entry
    let first = recv(&server);
    assert!(first.contains(" mooring ") && first.contains(" audit_syslog_changed "), "{first}");
    f.state.audit(AuditEvent::VaultUnlocked);
    assert!(recv(&server).contains(" vault_unlocked "));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while get(&f.state).expect("get").expect("some").sent < 2 {
        assert!(std::time::Instant::now() < deadline, "sent counter");
        std::thread::sleep(Duration::from_millis(10));
    }
    let st = get(&f.state).expect("get").expect("configured");
    assert_eq!(st.dropped, 0);
    assert_eq!(
        serde_json::to_value(&st).expect("json"),
        serde_json::json!({"host":"127.0.0.1","port":port,"transport":"udp","facility":"security",
            "enabled":true,"running":true,"dropped":0,"sent":2})
    );

    // disabling: the old collector still receives the change, then nothing more
    let st = set(&f.state, udp(port, false), TlsRoots::System).expect("disable");
    assert!(!st.running && !st.config.enabled);
    assert!(recv(&server).contains(r#""enabled":false"#));
    f.state.audit(AuditEvent::VaultUnlocked);
    server.set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
    let mut buf = [0u8; 64];
    assert!(server.recv(&mut buf).is_err(), "nothing after disable");

    let audit = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
    let changes: Vec<&str> =
        audit.lines().filter(|l| l.contains(r#""event":"audit_syslog_changed""#)).collect();
    assert_eq!(changes.len(), 2);
    assert!(changes[0].contains(r#""host":"127.0.0.1""#), "host is recorded: {}", changes[0]);
}

#[test]
fn a_redirect_is_seen_by_both_collectors() {
    let f = unlocked();
    let (old, old_port) = udp_collector();
    let (new, new_port) = udp_collector();
    set(&f.state, udp(old_port, true), TlsRoots::System).expect("set");
    assert!(recv(&old).contains(" audit_syslog_changed "));
    set(&f.state, udp(new_port, true), TlsRoots::System).expect("redirect");
    let to_old = recv(&old);
    assert!(to_old.contains(" audit_syslog_changed "), "{to_old}");
    assert!(to_old.contains(&format!(r#""port":{new_port}"#)), "old collector learns the target");
    let to_new = recv(&new);
    assert!(to_new.contains(" audit_syslog_changed ") && to_new.contains(&format!(r#""port":{new_port}"#)));
    f.state.audit(AuditEvent::VaultUnlocked);
    assert!(recv(&new).contains(" vault_unlocked "));
    old.set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
    let mut buf = [0u8; 64];
    assert!(old.recv(&mut buf).is_err(), "nothing more to the old collector");
    let audit = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
    assert_eq!(audit.matches(r#""event":"audit_syslog_changed""#).count(), 3, "{audit}");
}

#[test]
fn stored_config_restarts_with_a_new_process() {
    let f = unlocked();
    let (server, port) = udp_collector();
    set(&f.state, udp(port, true), TlsRoots::System).expect("set");
    recv(&server);
    let again = AppState::new(f.dir.path().to_path_buf(), settings(f.clipboard.clone()))
        .expect("reload");
    start_stored(&again);
    assert!(again.audit.lock().expect("log").mirror().is_some(), "mirror running before unlock");
    let started = recv(&server);
    assert!(started.contains(" audit_syslog_started "), "the collector sees the start: {started}");
    assert!(started.contains(r#""enabled":true"#) && started.contains(r#""transport":"udp""#));
    again.audit(AuditEvent::VaultUnlocked);
    assert!(recv(&server).contains(" vault_unlocked "));
}

#[test]
fn a_config_disabled_at_startup_is_recorded() {
    let f = unlocked();
    let (server, port) = udp_collector();
    set(&f.state, udp(port, true), TlsRoots::System).expect("set");
    recv(&server);
    // A same-user attacker edits the plaintext setting to switch the mirror off.
    set(&f.state, udp(port, false), TlsRoots::System).expect("off");
    let again = AppState::new(f.dir.path().to_path_buf(), settings(f.clipboard.clone()))
        .expect("reload");
    start_stored(&again);
    assert!(again.audit.lock().expect("log").mirror().is_none());
    let audit = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
    let last = audit.lines().last().expect("entry");
    assert!(last.contains(r#""event":"audit_syslog_started""#), "{last}");
    assert!(last.contains(r#""enabled":false"#) && last.contains("127.0.0.1"), "{last}");
}

#[tokio::test]
async fn heartbeats_are_written_only_while_the_mirror_runs() {
    let f = unlocked();
    assert!(!heartbeat(&f.state, 1), "no mirror, no heartbeat");
    let (server, port) = udp_collector();
    set(&f.state, udp(port, true), TlsRoots::System).expect("set");
    recv(&server);
    let looped = tokio::time::timeout(HEARTBEAT * 3 + HEARTBEAT / 2, heartbeat_loop(|seq| {
        heartbeat(&f.state, seq)
    }));
    assert!(looped.await.is_err(), "the loop runs until stopped");
    let first = recv(&server);
    assert!(first.contains(" audit_heartbeat ") && first.contains(r#""seq":1"#), "{first}");
    assert!(recv(&server).contains(r#""seq":2"#));
    let audit = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
    let beats = audit.matches(r#""event":"audit_heartbeat""#).count();
    assert!((2..=3).contains(&beats), "one per period: {beats}");
}

#[test]
fn locked_vault_refuses_all_three() {
    let f = unlocked();
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(get(&f.state).expect_err("get").code, "vault.locked");
    assert_eq!(
        set(&f.state, udp(514, true), TlsRoots::System).expect_err("set").code,
        "vault.locked"
    );
    assert_eq!(test_target(&f.state).expect_err("test").code, "vault.locked");
    assert!(f.state.audit.lock().expect("log").mirror().is_none(), "nothing started");
}

#[test]
fn test_command_reports_reachability() {
    let f = unlocked();
    assert_eq!(get(&f.state).expect("get"), None);
    assert_eq!(test_target(&f.state).expect_err("none").code, "syslog.not_configured");

    let (server, port) = udp_collector();
    set(&f.state, udp(port, false), TlsRoots::System).expect("store, disabled");
    let r = run_test(&test_target(&f.state).expect("target"), &TlsRoots::System);
    assert_eq!(r, TestResult { ok: true, error: None });
    assert!(recv(&server).ends_with(r#"{"event":"syslog_test"}"#), "test works while disabled");

    let closed = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("a").port();
    let cfg = parse("127.0.0.1", i64::from(closed), "tcp", 1, true).expect("cfg");
    let r = run_test(&cfg, &TlsRoots::System);
    assert!(!r.ok);
    assert_eq!(r.error.as_deref(), Some("network error: ConnectionRefused"));
    assert_eq!(
        serde_json::to_string(&r).expect("json"),
        r#"{"ok":false,"error":"network error: ConnectionRefused"}"#
    );
}

#[test]
fn unreachable_collector_never_fails_the_users_action() {
    let f = unlocked();
    let closed = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("a").port();
    let cfg = parse("127.0.0.1", i64::from(closed), "tcp", 1, true).expect("cfg");
    set(&f.state, cfg, TlsRoots::System).expect("set succeeds; delivery is best effort");
    crate::commands::vault::lock(&f.state, Some("idle")).expect("lock still works");
    let n = audit_events(&f.state).len();
    assert!(n >= 3, "local log keeps every entry");
}
