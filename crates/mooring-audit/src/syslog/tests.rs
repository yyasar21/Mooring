//! Loopback collectors (UDP, TCP, TLS with an rcgen self-signed certificate), drop accounting
//! and configuration validation. Only 127.0.0.1 is ever contacted.

use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::{AuditEvent, AuditLog};

const HOST: &str = "ws01.example.test";

fn cfg(transport: Transport, port: u16) -> SyslogConfig {
    SyslogConfig { host: "127.0.0.1".into(), port, transport, facility: 13, enabled: true }
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Read one octet-counted frame.
fn read_frame(r: &mut impl BufRead) -> String {
    let mut len = Vec::new();
    r.read_until(b' ', &mut len).expect("len");
    let n: usize = std::str::from_utf8(&len[..len.len() - 1]).expect("utf8").parse().expect("n");
    let mut buf = vec![0; n];
    r.read_exact(&mut buf).expect("body");
    String::from_utf8(buf).expect("utf8")
}

fn log_with(mirror: SyslogMirror) -> (tempfile::TempDir, AuditLog) {
    let dir = tempfile::tempdir().expect("tmp");
    let mut log = AuditLog::open(dir.path().join("audit.jsonl")).expect("open");
    assert!(log.set_mirror(Some(mirror)).is_none());
    (dir, log)
}

#[test]
fn udp_collector_receives_each_entry() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    server.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let port = server.local_addr().expect("addr").port();
    let mirror =
        SyslogMirror::start(cfg(Transport::Udp, port), HOST, TlsRoots::System).expect("start");
    let (_dir, mut log) = log_with(mirror);
    let entry = log.record(AuditEvent::VaultLocked { reason: "idle".into() }).expect("record");
    let mut buf = [0u8; 9000];
    let n = server.recv(&mut buf).expect("datagram");
    let got = std::str::from_utf8(&buf[..n]).expect("utf8");
    assert_eq!(got, format_entry(&entry, 13, HOST, std::process::id()));
    wait_until("sent counter", || log.mirror().expect("m").sent() == 1);
    assert_eq!(log.mirror().expect("m").dropped(), 0);
}

#[test]
fn tcp_collector_receives_octet_counted_frames_in_order() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (s, _) = listener.accept().expect("accept");
        let mut r = BufReader::new(s);
        (read_frame(&mut r), read_frame(&mut r))
    });
    let mirror =
        SyslogMirror::start(cfg(Transport::Tcp, port), HOST, TlsRoots::System).expect("start");
    let (_dir, mut log) = log_with(mirror);
    let a = log.record(AuditEvent::VaultCreated).expect("1");
    let b = log.record(AuditEvent::VaultUnlocked).expect("2");
    let (fa, fb) = server.join().expect("server");
    assert_eq!(fa, format_entry(&a, 13, HOST, std::process::id()));
    assert_eq!(fb, format_entry(&b, 13, HOST, std::process::id()));
    assert!(fb.contains(&format!("seq=\"2\" hash=\"{}\"", b.digest())));
}

/// A TLS collector on 127.0.0.1 with a fresh self-signed certificate; returns the port, the
/// certificate (to trust it) and the thread yielding the first frame.
fn tls_server(
) -> (u16, rustls::pki_types::CertificateDer<'static>, std::thread::JoinHandle<Option<String>>) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("rcgen");
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("server cert");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        let (s, _) = listener.accept().ok()?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
        let conn = rustls::ServerConnection::new(config).ok()?;
        let mut tls = BufReader::new(rustls::StreamOwned::new(conn, s));
        let mut len = Vec::new();
        tls.read_until(b' ', &mut len).ok()?;
        let n: usize =
            std::str::from_utf8(len.get(..len.len().checked_sub(1)?)?).ok()?.parse().ok()?;
        let mut buf = vec![0; n];
        tls.read_exact(&mut buf).ok()?;
        String::from_utf8(buf).ok()
    });
    (port, cert, handle)
}

#[test]
fn tls_collector_with_trusted_self_signed_cert() {
    let (port, cert, server) = tls_server();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("root");
    let roots = TlsRoots::Custom(Arc::new(roots));
    let mirror = SyslogMirror::start(cfg(Transport::Tls, port), HOST, roots).expect("start");
    let (_dir, mut log) = log_with(mirror);
    let e = log.record(AuditEvent::PasswordChanged).expect("record");
    let got = server.join().expect("server").expect("frame");
    assert_eq!(got, format_entry(&e, 13, HOST, std::process::id()));
}

#[test]
fn tls_refuses_an_untrusted_certificate() {
    let (port, _cert, server) = tls_server();
    let roots = TlsRoots::Custom(Arc::new(rustls::RootCertStore::empty()));
    let err = send_test(&cfg(Transport::Tls, port), HOST, &roots).expect_err("untrusted");
    assert!(matches!(&err, SyslogError::Tls(m) if m.contains("certificate")), "{err:?}");
    assert_eq!(server.join().expect("server"), None, "nothing was delivered");
}

#[test]
fn tls_refuses_a_name_mismatch() {
    let (port, cert, server) = tls_server();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("root");
    // `localhost` resolves to loopback but the certificate only names 127.0.0.1.
    let mut c = cfg(Transport::Tls, port);
    c.host = "localhost".into();
    let err = send_test(&c, HOST, &TlsRoots::Custom(Arc::new(roots))).expect_err("name");
    assert!(matches!(err, SyslogError::Tls(_) | SyslogError::Io(_)), "{err:?}");
    drop(server); // the server thread ends on its own when the client hangs up
}

fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

#[test]
fn closed_collector_counts_drops_and_never_blocks_the_writer() {
    const N: u64 = 2000; // more than the queue holds
    let mirror = SyslogMirror::start(cfg(Transport::Tcp, closed_port()), HOST, TlsRoots::System)
        .expect("start");
    let (_dir, mut log) = log_with(mirror);
    let started = Instant::now();
    for _ in 0..N {
        log.record(AuditEvent::VaultUnlocked).expect("local write never fails");
    }
    // 2000 fsyncs dominate; the mirror adds nothing that waits on the network.
    assert!(started.elapsed() < Duration::from_secs(60));
    wait_until("all drops counted", || log.mirror().expect("m").dropped() == N);
    assert_eq!(log.mirror().expect("m").sent(), 0);
    assert!(AuditLog::verify(log.path()).expect("verify").ok(), "local chain intact");
}

#[test]
fn send_test_reports_success_and_refusal() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    server.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let port = server.local_addr().expect("addr").port();
    send_test(&cfg(Transport::Udp, port), HOST, &TlsRoots::System).expect("udp");
    let mut buf = [0u8; 2048];
    let n = server.recv(&mut buf).expect("recv");
    let got = std::str::from_utf8(&buf[..n]).expect("utf8");
    assert!(got.starts_with("<109>1 ") && got.ends_with(r#"{"event":"syslog_test"}"#), "{got}");
    let err = send_test(&cfg(Transport::Tcp, closed_port()), HOST, &TlsRoots::System)
        .expect_err("refused");
    assert_eq!(err, SyslogError::Io(std::io::ErrorKind::ConnectionRefused));
    assert_eq!(err.to_string(), "network error: ConnectionRefused");
}

#[test]
fn dropping_the_mirror_detaches_it() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = server.local_addr().expect("addr").port();
    let mirror =
        SyslogMirror::start(cfg(Transport::Udp, port), HOST, TlsRoots::System).expect("start");
    let (_dir, mut log) = log_with(mirror);
    assert!(log.set_mirror(None).is_some());
    assert!(log.mirror().is_none());
    log.record(AuditEvent::VaultCreated).expect("write without mirror");
}

#[test]
fn config_validation_table() {
    let ok =
        |host: &str| SyslogConfig { host: host.into(), ..cfg(Transport::Udp, 514) }.validated();
    for good in ["127.0.0.1", "2001:db8::1", "logs.example.test", " LOGS.Example.Test ", "a-b.c1"] {
        assert!(ok(good).is_ok(), "{good:?}");
    }
    assert_eq!(ok(" LOGS.Example.Test ").expect("ok").host, "logs.example.test");
    let bad_hosts = [
        "",
        "   ",
        "udp://logs.example.test",
        "logs.example.test:514",
        "[2001:db8::1]",
        "logs example.test",
        "logs.exa\nmple.test",
        "-bad.example.test",
        "bad-.example.test",
        "a..b",
        "logs.example.test.",
        "ünicode.example.test",
        "x\0y",
    ];
    for bad in bad_hosts {
        assert!(matches!(ok(bad), Err(SyslogError::Invalid { field: "host", .. })), "{bad:?}");
    }
    assert!(ok(&"a".repeat(64)).is_err(), "label > 63");
    assert!(ok(&["a"; 127].join(".")).is_ok(), "253 bytes");
    assert!(ok(&format!("{}.ab", ["a"; 126].join("."))).is_err(), "254 bytes");
    let port0 = SyslogConfig { port: 0, ..cfg(Transport::Udp, 514) }.validated();
    assert!(matches!(port0, Err(SyslogError::Invalid { field: "port", .. })));
    let fac = SyslogConfig { facility: 24, ..cfg(Transport::Udp, 514) }.validated();
    assert!(matches!(fac, Err(SyslogError::Invalid { field: "facility", .. })));
    assert!(SyslogConfig { facility: 23, ..cfg(Transport::Udp, 514) }.validated().is_ok());
}

#[test]
fn config_wire_shape() {
    let c = cfg(Transport::Tls, 6514);
    assert_eq!(
        serde_json::to_string(&c).expect("json"),
        r#"{"host":"127.0.0.1","port":6514,"transport":"tls","facility":"security","enabled":true}"#
    );
    // numeric codes are still accepted on input; keywords round-trip
    let back: SyslogConfig = serde_json::from_str(
        r#"{"host":"127.0.0.1","port":6514,"transport":"tls","facility":13,"enabled":true}"#,
    )
    .expect("numeric facility");
    assert_eq!(back, c);
    assert!(serde_json::from_str::<SyslogConfig>(
        r#"{"host":"h","port":1,"transport":"udp","facility":"nope","enabled":true}"#
    )
    .is_err());
    let unknown = r#"{"host":"h","port":1,"transport":"udp","facility":1,"enabled":true,"x":1}"#;
    assert!(serde_json::from_str::<SyslogConfig>(unknown).is_err());
    assert!(serde_json::from_str::<SyslogConfig>(
        r#"{"host":"h","port":1,"transport":"quic","facility":1,"enabled":true}"#
    )
    .is_err());
}

#[test]
fn debug_output_has_no_host() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = server.local_addr().expect("addr").port();
    let m = SyslogMirror::start(cfg(Transport::Udp, port), HOST, TlsRoots::System).expect("start");
    let dbg = format!("{m:?}");
    assert!(dbg.contains("Udp") && !dbg.contains("127.0.0.1"), "{dbg}");
}
