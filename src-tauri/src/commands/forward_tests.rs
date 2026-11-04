//! `forward_*` tests against the in-process russh server (loopback only).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::commands::test_session::{audit_text, close as close_session, connect};
use crate::test_ssh_server as server;

/// Loopback TCP echo service.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn ep(host: &str, port: u32) -> WireEndpoint {
    WireEndpoint { host: host.into(), port }
}

fn local(bind: WireEndpoint, target: WireEndpoint) -> ForwardRequest {
    ForwardRequest { kind: "local".into(), bind, target: Some(target), exposure: None }
}

async fn round_trip(port: u16, msg: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    s.write_all(msg).await.expect("write");
    let mut buf = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("echo within 10 s")
        .expect("read");
    buf
}

#[tokio::test]
async fn local_forward_echoes_lists_closes_and_audits() {
    let srv = server::start(61).await;
    let echo = echo_server().await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());

    let req = local(ep("127.0.0.1", 0), ep("127.0.0.1", u32::from(echo.port())));
    let fwd = open(st, sid, req).await.expect("open");
    assert_eq!((fwd.id.as_str(), fwd.kind, fwd.exposure), ("fwd-1", "local", "loopback"));
    assert_eq!(fwd.bind.host, "127.0.0.1");
    assert_ne!(fwd.bind.port, 0, "allocated port is reported");
    let target = fwd.target.clone().expect("target");
    assert_eq!((target.host.as_str(), target.port), ("127.0.0.1", echo.port()));
    assert!(fwd.opened_at.ends_with('Z'), "{}", fwd.opened_at);

    assert_eq!(round_trip(fwd.bind.port, b"ping through the forward").await, b"ping through the forward");
    let json = serde_json::to_value(list(st, sid).expect("list")).expect("json");
    assert_eq!(json[0]["id"], "fwd-1");
    assert_eq!(json[0]["bind"]["port"], fwd.bind.port);
    assert!(json[0]["openedAt"].is_string() && json[0]["connections"].is_number(), "{json}");

    close(st, sid, "fwd-1").await.expect("close");
    assert!(list(st, sid).expect("list").is_empty());
    assert_eq!(close(st, sid, "fwd-1").await.expect_err("gone").code, "forward.not_found");
    let log = audit_text(&live);
    assert!(log.contains(r#""event":"forward_opened""#), "{log}");
    assert!(log.contains(r#""exposure":"loopback""#), "{log}");
    assert!(log.contains(r#""event":"forward_closed""#), "{log}");
    close_session(&live).await;
}

#[tokio::test]
async fn dynamic_and_external_forwards_are_audited_and_die_with_the_session() {
    let srv = server::start(62).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let dynamic = ForwardRequest {
        kind: "dynamic".into(),
        bind: ep("localhost", 0),
        target: None,
        exposure: Some("loopback".into()),
    };
    let d = open(st, sid, dynamic).await.expect("dynamic");
    assert_eq!((d.kind, d.target.clone()), ("dynamic", None));

    let mut any = local(ep("0.0.0.0", 0), ep("db.example.test", 5432));
    let e = open(st, sid, any.clone()).await.expect_err("loopback policy");
    assert_eq!(e.code, "input.invalid", "{e:?}");
    any.exposure = Some("external".into());
    let x = open(st, sid, any).await.expect("external on explicit opt-in");
    assert_eq!(x.exposure, "external");
    assert_eq!(list(st, sid).expect("list").len(), 2);
    assert!(audit_text(&live).contains(r#""exposure":"external""#));

    close_session(&live).await;
    assert_eq!(list(st, sid).expect_err("gone").code, "session.not_found");
    let log = audit_text(&live);
    assert_eq!(log.matches(r#""event":"forward_closed""#).count(), 2, "{log}");
}

#[tokio::test]
async fn lock_closes_external_forwards_and_keeps_loopback_ones() {
    let srv = server::start(66).await;
    let echo = echo_server().await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let to_echo = ep("127.0.0.1", u32::from(echo.port()));
    let lo = open(st, sid, local(ep("127.0.0.1", 0), to_echo.clone())).await.expect("loopback");
    let mut ext = local(ep("0.0.0.0", 0), to_echo);
    ext.exposure = Some("external".into());
    let x = open(st, sid, ext).await.expect("external");
    assert_eq!(round_trip(x.bind.port, b"before").await, b"before");

    crate::commands::vault::lock(st, None).expect("lock");
    let left = list(st, sid).expect("session survives the lock");
    assert_eq!(left.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), [lo.id.as_str()]);
    // The external listener is gone; the loopback forward still works.
    let refused = TcpStream::connect(("127.0.0.1", x.bind.port)).await;
    assert!(refused.is_err(), "external listener closed");
    assert_eq!(round_trip(lo.bind.port, b"after").await, b"after");
    let log = audit_text(&live);
    assert_eq!(log.matches(r#""event":"forward_closed""#).count(), 1, "{log}");
    let closed_at = log.find(r#""event":"forward_closed""#).expect("closed");
    assert!(closed_at < log.find(r#""event":"vault_locked""#).expect("locked"), "{log}");
    close_session(&live).await;
}

#[tokio::test]
async fn bind_conflict_and_forward_limit() {
    let srv = server::start(63).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let taken = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = u32::from(taken.local_addr().expect("addr").port());
    let e = open(st, sid, local(ep("127.0.0.1", port), ep("127.0.0.1", 9))).await;
    assert_eq!(e.expect_err("in use").code, "forward.bind");

    for _ in 0..mooring_proto_ssh::forward::MAX_FORWARDS {
        open(st, sid, local(ep("127.0.0.1", 0), ep("127.0.0.1", 9))).await.expect("open");
    }
    let e = open(st, sid, local(ep("127.0.0.1", 0), ep("127.0.0.1", 9))).await;
    assert_eq!(e.expect_err("65th").code, "forward.limit");
    close_session(&live).await;
}

#[tokio::test]
async fn hostile_inputs_are_refused() {
    let srv = server::start(64).await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let t = || Some(ep("127.0.0.1", 22));
    let req = |kind: &str, bind: WireEndpoint, target: Option<WireEndpoint>, exp: Option<&str>| {
        ForwardRequest { kind: kind.into(), bind, target, exposure: exp.map(str::to_owned) }
    };
    let cases = [
        req("LOCAL", ep("127.0.0.1", 0), t(), None),
        req("socks", ep("127.0.0.1", 0), None, None),
        req("local", ep("127.0.0.1", 70_000), t(), None),
        req("local", ep("127.0.0.1", 0), Some(ep("127.0.0.1", 0)), None),
        req("local", ep("127.0.0.1", 0), Some(ep("127.0.0.1", 65_536)), None),
        req("local", ep("127.0.0.1", 0), None, None),
        req("local", ep("example.test", 0), t(), None),
        req("local", ep("", 0), t(), None),
        req("local", ep("127.0.0.1\n", 0), t(), None),
        req("local", ep("127.0.0.1", 0), Some(ep("bad host", 22)), None),
        req("local", ep("127.0.0.1", 0), Some(ep(&"a".repeat(300), 22)), None),
        req("local", ep("127.0.0.1", 0), t(), Some("public")),
        req("dynamic", ep("127.0.0.1", 0), t(), None),
        req("remote", ep("127.0.0.1", 0), Some(ep("example.test", 80)), None),
        req("remote", ep("127.0.0.1", 0), Some(ep("127.0.0.1", 0)), None),
        req("remote", ep("0.0.0.0", 0), Some(ep("127.0.0.1", 80)), None),
        // N-16: format characters that spoof the displayed target
        req("local", ep("127.0.0.1", 0), Some(ep("db\u{202e}tset.elpmaxe", 22)), None),
        req("local", ep("127.0.0.1", 0), Some(ep("db\u{200b}.example.test", 22)), None),
        req("local", ep("127.0.0.1", 0), Some(ep("db.example.test\u{e0001}", 22)), None),
        req("local", ep("127.0.0.1", 0), Some(ep("db\u{2066}.example.test", 22)), None),
        req("local", ep("127.0.0.1", 0), Some(ep(" db.example.test", 22)), None),
        req("local", ep("127.0.0.1", 0), Some(ep("db.example.test\t", 22)), None),
        req("remote", ep("db\u{00ad}.example.test", 0), Some(ep("127.0.0.1", 80)), None),
    ];
    for (i, c) in cases.into_iter().enumerate() {
        let e = open(st, sid, c).await.expect_err("refused");
        assert_eq!(e.code, "input.invalid", "case {i}: {e:?}");
        assert!(!e.message.contains("example.test"), "values are not echoed: {e:?}");
    }
    for bad in ["", "1", "fwd-", "fwd-x", "fwd--1", &"9".repeat(40), "fwd-1\0"] {
        assert_eq!(close(st, sid, bad).await.expect_err("bad id").code, "input.invalid", "{bad:?}");
    }
    let ok = local(ep("127.0.0.1", 0), ep("127.0.0.1", 22));
    assert_eq!(open(st, "nope", ok.clone()).await.expect_err("x").code, "session.not_found");
    assert_eq!(open(st, &"s".repeat(65), ok).await.expect_err("x").code, "input.invalid");
    assert_eq!(list(st, "").expect_err("x").code, "input.invalid");
    assert_eq!(close(st, "nope", "fwd-1").await.expect_err("x").code, "session.not_found");
    assert!(list(st, sid).expect("list").is_empty(), "nothing was opened");

    let unknown = r#"{"kind":"local","bind":{"host":"127.0.0.1","port":0},"evil":1}"#;
    assert!(serde_json::from_str::<ForwardRequest>(unknown).is_err(), "unknown fields refused");
    let negative = r#"{"kind":"local","bind":{"host":"127.0.0.1","port":-1}}"#;
    assert!(serde_json::from_str::<ForwardRequest>(negative).is_err());
    close_session(&live).await;
}

#[tokio::test]
async fn remote_forward_through_the_command() {
    let srv = server::start(65).await;
    let echo = echo_server().await;
    let live = connect(&srv).await;
    let (st, sid) = (&live.f.state, live.session_id.as_str());
    let req = ForwardRequest {
        kind: "remote".into(),
        bind: ep("127.0.0.1", 0),
        target: Some(ep("127.0.0.1", u32::from(echo.port()))),
        exposure: None,
    };
    // The minimal test server does not implement `tcpip-forward`: the refusal maps cleanly.
    let e = open(st, sid, req).await.expect_err("server refuses");
    assert_eq!(e.code, "forward.bind", "{e:?}");
    assert!(list(st, sid).expect("list").is_empty());
    close_session(&live).await;
}
