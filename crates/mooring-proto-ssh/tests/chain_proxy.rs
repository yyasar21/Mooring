//! ADR-0025 §3: the web window's SOCKS5 forward over a jump-host chain. Loopback only, each
//! CONNECT a `direct-tcpip` of the last hop (names resolved there), closed with the proxy.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::forwarding::echo_server;
use common::*;
use mooring_core::session::ConnectSecret;
use mooring_proto_ssh::{ChainProxy, Hop, HopChain, HopEvents, ProxyAllow};
use russh::MethodKind;
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const T: Duration = Duration::from_secs(10);

fn hop(port: u16, kh: &std::path::Path) -> Hop {
    Hop {
        params: params(port, ConnectSecret::Password(SecretString::from(PASSWORD))),
        options: options(kh),
        index: 0,
        connection: "hop-0".into(),
    }
}

/// SOCKS5 CONNECT to `localhost:<port>` (a domain request); returns the stream and the reply.
async fn connect_domain(proxy: SocketAddr, port: u16) -> (TcpStream, u8) {
    let mut c = TcpStream::connect(proxy).await.expect("connect proxy");
    c.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.expect("method");
    assert_eq!(m, [5, 0], "no-auth method");
    let mut req = vec![5, 1, 0, 3, 9];
    req.extend_from_slice(b"localhost");
    req.extend_from_slice(&port.to_be_bytes());
    c.write_all(&req).await.expect("request");
    let mut rep = [0u8; 10];
    tokio::time::timeout(T, c.read_exact(&mut rep)).await.expect("in time").expect("reply");
    (c, rep[1])
}

#[tokio::test]
async fn socks_through_the_last_hop_round_trips_and_dies_with_the_proxy() {
    let a = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    let echo = echo_server().await;
    let (ev, _rx) = HopEvents::new(16);
    let chain = HopChain::open_hops(vec![hop(a.port, &kh)], ("app.example.test", 443), &ev)
        .await
        .expect("chain up");

    let mut allow = ProxyAllow::new();
    allow.allow("LOCALHOST.", echo.port());
    let proxy = ChainProxy::open(&chain, allow).await.expect("proxy");
    assert!(proxy.addr().ip().is_loopback(), "{}", proxy.addr());
    assert_ne!(proxy.addr().port(), 0);
    assert_eq!(proxy.url(), format!("socks5://127.0.0.1:{}", proxy.addr().port()));

    let (mut c, rep) = connect_domain(proxy.addr(), echo.port()).await;
    assert_eq!(rep, 0, "CONNECT succeeds");
    c.write_all(b"via the bastion").await.expect("write");
    let mut buf = [0u8; 15];
    tokio::time::timeout(T, c.read_exact(&mut buf)).await.expect("in time").expect("read");
    assert_eq!(&buf, b"via the bastion");
    assert_eq!(proxy.connections(), 1);
    // The host name went to the hop unresolved.
    assert!(a
        .seen
        .lock()
        .expect("lock")
        .direct
        .contains(&("localhost".to_owned(), u32::from(echo.port()))));

    proxy.close();
    assert!(proxy.is_closed());
    let mut b = [0u8; 1];
    let ended = tokio::time::timeout(T, c.read(&mut b)).await.expect("in time");
    assert!(matches!(ended, Ok(0) | Err(_)), "open connection ends with the proxy");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpStream::connect(proxy.addr()).await.is_err(), "listener gone");

    chain.close().await;
}

#[tokio::test]
async fn no_proxy_over_a_closed_chain() {
    let a = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    let (ev, _rx) = HopEvents::new(16);
    let chain = HopChain::open_hops(vec![hop(a.port, &kh)], ("app.example.test", 443), &ev)
        .await
        .expect("chain up");
    chain.close_with("closed").await;
    // `disconnect` is asynchronous inside russh; wait for the handle to notice.
    for _ in 0..100 {
        if chain.lost_hop().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let e = ChainProxy::open(&chain, ProxyAllow::new()).await.expect_err("no live hop");
    assert_eq!(e.kind(), std::io::ErrorKind::NotConnected);
}

/// Review 9 L-48: a CONNECT outside the allow-list gets reply `0x02` and never reaches the
/// hop; it is counted and kept for the audit log.
#[tokio::test]
async fn connect_outside_the_allow_list_is_refused_before_the_hop() {
    let a = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    let echo = echo_server().await;
    let (ev, _rx) = HopEvents::new(16);
    let chain = HopChain::open_hops(vec![hop(a.port, &kh)], ("app.example.test", 443), &ev)
        .await
        .expect("chain up");
    let mut allow = ProxyAllow::new();
    allow.allow("app.example.test", 443);
    let proxy = ChainProxy::open(&chain, allow).await.expect("proxy");

    let (_c, rep) = connect_domain(proxy.addr(), echo.port()).await;
    assert_eq!(rep, 2, "connection not allowed by ruleset");
    assert_eq!(proxy.refused(), 1);
    assert_eq!(proxy.take_refused(), [format!("localhost:{}", echo.port())]);
    assert!(proxy.take_refused().is_empty(), "taken once");
    assert!(a.seen.lock().expect("lock").direct.is_empty(), "no direct-tcpip for a refusal");
    chain.close().await;
}
