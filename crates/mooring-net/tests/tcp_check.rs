//! ADR-0020 §2 integration: the port check against a loopback listener (open), a port nobody
//! listens on (closed) and an RFC 5737 address (timeout / unreachable, depending on the
//! sandbox's routing). No bytes are ever written to the listener.

use std::time::Duration;

use mooring_net::{tcp_check, Target, TcpResult};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

fn t(s: &str) -> Target {
    Target::parse(s).expect("target")
}

#[tokio::test]
async fn loopback_listener_is_open_and_receives_no_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 16];
        // The checker drops the stream at once: EOF, zero bytes.
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .expect("eof in time");
        n.unwrap_or(0)
    });
    let r = tcp_check(&t("127.0.0.1"), port, Duration::from_secs(3)).await;
    let TcpResult::Open { addr, rtt_ms } = r else { panic!("{r:?}") };
    assert_eq!(addr, format!("127.0.0.1:{port}"));
    assert!((0.0..3000.0).contains(&rtt_ms));
    assert_eq!(server.await.expect("server"), 0, "no bytes were sent");
}

#[tokio::test]
async fn closed_port_is_closed() {
    // Bind then drop: the port is free again and nobody listens (a RST follows).
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let r = tcp_check(&t("127.0.0.1"), port, Duration::from_secs(3)).await;
    assert_eq!(r, TcpResult::Closed);
}

#[tokio::test]
async fn hostname_localhost_resolves() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let r = tcp_check(&t("localhost"), port, Duration::from_secs(3)).await;
    assert!(matches!(r, TcpResult::Open { .. } | TcpResult::Closed), "{r:?}");
}

#[tokio::test]
async fn unresolvable_name_is_dns_failed() {
    let r = tcp_check(&t("no-such-host.invalid"), 22, Duration::from_secs(3)).await;
    assert_eq!(r, TcpResult::DnsFailed);
}

/// RFC 5737 TEST-NET-1 is unrouted on a plain host (timeout), but a sandbox proxy or firewall
/// may answer with an RST or an ICMP error instead; what is pinned is that the check never
/// reports `open` and returns within its deadline.
#[tokio::test]
async fn test_net_address_is_never_open_and_respects_the_deadline() {
    let started = std::time::Instant::now();
    let r = tcp_check(&t("192.0.2.1"), 22, Duration::from_millis(400)).await;
    assert!(!matches!(r, TcpResult::Open { .. }), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}
