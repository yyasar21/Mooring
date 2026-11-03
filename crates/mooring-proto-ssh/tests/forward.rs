//! Port forwarding: local, remote, dynamic (SOCKS5), close, and cleanup with the session.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::forwarding::echo_server;
use common::*;
use mooring_core::session::Session;
use mooring_core::MooringError;
use mooring_proto_ssh::{Exposure, ForwardKind, SshSession, TrustEvent};
use russh::MethodKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const T: Duration = Duration::from_secs(10);

async fn session() -> (SshSession, TestServer, tempfile::TempDir) {
    connected(ServerSpec::new(&[MethodKind::Password])).await
}

fn loopback0() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Write `msg`, read the same number of bytes back, return them.
async fn round_trip(stream: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
    stream.write_all(msg).await.expect("write");
    let mut buf = vec![0u8; msg.len()];
    tokio::time::timeout(T, stream.read_exact(&mut buf)).await.expect("in time").expect("read");
    buf
}

/// The connection was closed (EOF or reset) or refused.
async fn is_dead(addr: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect(addr).await else {
        return true;
    };
    let _ = s.write_all(b"x").await;
    let mut b = [0u8; 1];
    matches!(tokio::time::timeout(T, s.read(&mut b)).await, Ok(Ok(0) | Err(_)))
}

fn actions(events: &[TrustEvent]) -> Vec<&'static str> {
    events.iter().map(TrustEvent::action).collect()
}

#[tokio::test]
async fn local_forward_echo_round_trip() {
    let (mut s, srv, _d) = session().await;
    let echo = echo_server().await;
    let id = s
        .forward_local(loopback0(), ("127.0.0.1".into(), echo.port()), Exposure::Loopback)
        .await
        .expect("fwd");
    let info = s.forwards().into_iter().find(|f| f.id == id).expect("listed");
    assert_eq!(info.kind, ForwardKind::Local);
    assert_eq!(info.target, format!("127.0.0.1:{}", echo.port()));

    let addr = SocketAddr::from(([127, 0, 0, 1], info.port));
    let mut c = TcpStream::connect(addr).await.expect("connect");
    assert_eq!(round_trip(&mut c, b"hello through -L").await, b"hello through -L");
    let big: Vec<u8> = (0..300_000u32).map(|i| u8::try_from(i % 251).expect("< 251")).collect();
    assert_eq!(round_trip(&mut c, &big).await, big);
    assert_eq!(
        srv.seen.lock().expect("lock").direct,
        vec![("127.0.0.1".into(), u32::from(echo.port()))]
    );

    let events = s.take_audit_events();
    let open =
        events.iter().find(|e| matches!(e, TrustEvent::ForwardOpened { .. })).expect("audit");
    let TrustEvent::ForwardOpened { kind, bind, target, .. } = open else { unreachable!() };
    assert_eq!(
        (*kind, bind.as_str(), target.as_str()),
        ("local", addr.to_string().as_str(), info.target.as_str())
    );

    s.forward_close(id).await.expect("close");
    assert!(s.forwards().is_empty());
    assert!(actions(&s.take_audit_events()).contains(&"session.forward.close"));
    assert!(is_dead(addr).await, "listener stopped");
    assert!(matches!(s.forward_close(id).await, Err(MooringError::NotFound { .. })));
    s.close().await.expect("close");
}

#[tokio::test]
async fn local_forward_validates_target() {
    let (mut s, _srv, _d) = session().await;
    assert!(s
        .forward_local(loopback0(), ("bad host".into(), 80), Exposure::Loopback)
        .await
        .is_err());
    assert!(s
        .forward_local(loopback0(), ("127.0.0.1".into(), 0), Exposure::Loopback)
        .await
        .is_err());
    assert!(s.forwards().is_empty());
    assert!(s.take_audit_events().iter().all(|e| !matches!(e, TrustEvent::ForwardOpened { .. })));
    s.close().await.expect("close");
}

#[tokio::test]
async fn remote_forward_round_trip() {
    let (mut s, srv, _d) = session().await;
    let echo = echo_server().await;
    let id =
        s.forward_remote(("127.0.0.1".into(), 0), echo, Exposure::Loopback).await.expect("fwd");
    let info = s.forwards().into_iter().find(|f| f.id == id).expect("listed");
    assert_eq!(info.kind, ForwardKind::Remote);
    assert_ne!(info.port, 0, "server-allocated port reported");
    assert_eq!(info.bind, format!("127.0.0.1:{}", info.port));

    let server_side = SocketAddr::from(([127, 0, 0, 1], info.port));
    let mut c = TcpStream::connect(server_side).await.expect("connect server listener");
    assert_eq!(round_trip(&mut c, b"hello through -R").await, b"hello through -R");

    s.forward_close(id).await.expect("close");
    let cancelled = srv.seen.lock().expect("lock").cancelled_forwards.clone();
    assert_eq!(cancelled, vec![("127.0.0.1".into(), u32::from(info.port))]);
    assert!(is_dead(server_side).await);
    s.close().await.expect("close");
}

async fn socks_connect(proxy: SocketAddr, req_addr: &[u8]) -> (TcpStream, u8) {
    let mut c = TcpStream::connect(proxy).await.expect("connect proxy");
    c.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.expect("method");
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0];
    req.extend_from_slice(req_addr);
    c.write_all(&req).await.expect("request");
    let mut rep = [0u8; 10];
    tokio::time::timeout(T, c.read_exact(&mut rep)).await.expect("in time").expect("reply");
    (c, rep[1])
}

#[tokio::test]
async fn socks5_connect_round_trip() {
    let (mut s, srv, _d) = session().await;
    let echo = echo_server().await;
    let id = s.forward_dynamic(loopback0(), Exposure::Loopback).await.expect("fwd");
    let info = s.forwards().into_iter().find(|f| f.id == id).expect("listed");
    assert_eq!((info.kind, info.target.as_str()), (ForwardKind::Dynamic, "socks5"));
    let proxy = SocketAddr::from(([127, 0, 0, 1], info.port));
    let port = echo.port().to_be_bytes();

    let (mut c, rep) = socks_connect(proxy, &[1, 127, 0, 0, 1, port[0], port[1]]).await;
    assert_eq!(rep, 0, "IPv4 CONNECT succeeds");
    assert_eq!(round_trip(&mut c, b"socks v4").await, b"socks v4");

    let mut dn = vec![3, 9];
    dn.extend_from_slice(b"localhost");
    dn.extend_from_slice(&port);
    let (mut c, rep) = socks_connect(proxy, &dn).await;
    assert_eq!(rep, 0, "domain CONNECT succeeds");
    assert_eq!(round_trip(&mut c, b"socks dn").await, b"socks dn");

    // Target refused on the server side → host unreachable reply.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let dead = closed.local_addr().expect("addr").port().to_be_bytes();
    drop(closed);
    let (_c, rep) = socks_connect(proxy, &[1, 127, 0, 0, 1, dead[0], dead[1]]).await;
    assert_eq!(rep, 4);

    let direct = srv.seen.lock().expect("lock").direct.clone();
    assert!(direct.contains(&("localhost".into(), u32::from(echo.port()))));
    s.close().await.expect("close");
}

#[tokio::test]
async fn socks5_refuses_non_loopback_bind() {
    let (mut s, _srv, _d) = session().await;
    let any = SocketAddr::from(([0, 0, 0, 0], 0));
    let err = s.forward_dynamic(any, Exposure::Loopback).await.expect_err("refused");
    assert!(matches!(err, MooringError::Invalid { field: "bind", .. }));
    assert!(s.forwards().is_empty());
    let id = s.forward_dynamic(any, Exposure::External).await.expect("explicitly allowed");
    assert_eq!(s.forwards()[0].id, id);
    s.close().await.expect("close");
}

fn exposure_of(events: &[TrustEvent]) -> Vec<&'static str> {
    events
        .iter()
        .filter_map(|e| match e {
            TrustEvent::ForwardOpened { exposure, .. } => Some(*exposure),
            _ => None,
        })
        .collect()
}

/// Security review 2 M-2: a local forward on a non-loopback address needs `External`.
#[tokio::test]
async fn local_forward_refuses_non_loopback_bind_unless_external() {
    let (mut s, _srv, _d) = session().await;
    let echo = echo_server().await;
    let any = SocketAddr::from(([0, 0, 0, 0], 0));
    let target = || ("127.0.0.1".to_owned(), echo.port());
    let err = s.forward_local(any, target(), Exposure::Loopback).await.expect_err("refused");
    assert!(matches!(err, MooringError::Invalid { field: "bind", .. }));
    assert!(s.forwards().is_empty());
    assert!(exposure_of(&s.take_audit_events()).is_empty());

    s.forward_local(loopback0(), target(), Exposure::Loopback).await.expect("loopback");
    let id = s.forward_local(any, target(), Exposure::External).await.expect("external");
    assert_eq!(
        s.forwards().iter().find(|f| f.id == id).expect("listed").exposure,
        Exposure::External
    );
    assert_eq!(exposure_of(&s.take_audit_events()), vec!["loopback", "external"]);
    s.close().await.expect("close");
}

/// Security review 2 M-2: a remote bind of `0.0.0.0` / `*` / `::` needs `External`.
#[tokio::test]
async fn remote_forward_refuses_non_loopback_bind_unless_external() {
    let (mut s, srv, _d) = session().await;
    let echo = echo_server().await;
    for host in ["0.0.0.0", "*", "::", "10.10.0.1"] {
        let err = s
            .forward_remote((host.into(), 0), echo, Exposure::Loopback)
            .await
            .expect_err("refused");
        assert!(matches!(err, MooringError::Invalid { field: "bind", .. }), "{host}");
    }
    assert!(srv.seen.lock().expect("lock").cancelled_forwards.is_empty());
    assert!(s.forwards().is_empty());
    s.forward_remote(("localhost".into(), 0), echo, Exposure::Loopback).await.expect("localhost");
    s.forward_remote(("0.0.0.0".into(), 0), echo, Exposure::External).await.expect("external");
    assert_eq!(exposure_of(&s.take_audit_events()), vec!["loopback", "external"]);
    s.close().await.expect("close");
}

#[tokio::test]
async fn forwards_close_with_the_session() {
    let (mut s, _srv, _d) = session().await;
    let echo = echo_server().await;
    s.forward_local(loopback0(), ("127.0.0.1".into(), echo.port()), Exposure::Loopback)
        .await
        .expect("L");
    s.forward_dynamic(loopback0(), Exposure::Loopback).await.expect("D");
    s.forward_remote(("127.0.0.1".into(), 0), echo, Exposure::Loopback).await.expect("R");
    let listed = s.forwards();
    assert_eq!(listed.len(), 3);
    let local = SocketAddr::from(([127, 0, 0, 1], listed[0].port));
    let mut live = TcpStream::connect(local).await.expect("connect");
    assert_eq!(round_trip(&mut live, b"before").await, b"before");

    s.close().await.expect("close");
    assert!(s.forwards().is_empty());
    let events = s.take_audit_events();
    let closes = events.iter().filter(|e| e.action() == "session.forward.close").count();
    assert_eq!(closes, 3);
    for f in &listed {
        assert!(is_dead(SocketAddr::from(([127, 0, 0, 1], f.port))).await, "{} still open", f.id);
    }
    let mut b = [0u8; 1];
    let read = tokio::time::timeout(T, live.read(&mut b)).await.expect("in time");
    assert!(matches!(read, Ok(0) | Err(_)), "live connection closed");
    assert!(matches!(
        s.forward_local(loopback0(), ("127.0.0.1".into(), 1), Exposure::Loopback).await,
        Err(MooringError::Closed)
    ));
}

#[tokio::test]
async fn forwards_close_when_the_remote_ends() {
    let (mut s, _srv, _d) = session().await;
    let echo = echo_server().await;
    s.forward_local(loopback0(), ("127.0.0.1".into(), echo.port()), Exposure::Loopback)
        .await
        .expect("L");
    let port = s.forwards()[0].port;
    s.send(mooring_core::session::SessionInput::Bytes { data: b"exit\r".to_vec() })
        .await
        .expect("send");
    expect_closed(&mut s).await;
    assert!(s.forwards().is_empty());
    assert!(is_dead(SocketAddr::from(([127, 0, 0, 1], port))).await);
}

#[tokio::test]
async fn forwards_need_a_connected_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    // Unknown host key: the session waits at the TOFU prompt, not connected yet.
    let s =
        connect(server.port, mooring_core::session::ConnectSecret::None, &dir.path().join("kh"))
            .await;
    let err = s.forward_dynamic(loopback0(), Exposure::Loopback).await.expect_err("not connected");
    assert!(matches!(err, MooringError::Protocol { .. }));
}
