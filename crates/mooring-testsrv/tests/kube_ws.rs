//! Self-tests of the kube mock's WebSocket side: `pods/exec` (v5 / v4 channel protocol, echo
//! shell, resize, status channel) and `pods/portforward` (native v4 framing, echo backend).

mod common;

use bytes::Bytes;
use common::http_client::{request, send, ws_connect, Ws};
use common::{eventually, within};
use http::Method;
use mooring_testsrv::kube::{self, AccessRule, KubeConfig, KubeKnobs};

const AUTH: (&str, &str) = ("authorization", "Bearer test-token");
const V5: &str = "v5.channel.k8s.io";
const V4: &str = "v4.channel.k8s.io";
const EXEC: &str = "/api/v1/namespaces/default/pods/web-0/exec?container=app&command=%2Fbin%2Fsh&stdin=true&stdout=true";

async fn srv() -> kube::KubeServer {
    kube::start(KubeConfig::default(), 0).await.expect("start")
}

async fn open(s: &kube::KubeServer, path: &str, protos: &[&str]) -> Ws {
    ws_connect(s.addr(), path, protos, &[AUTH]).await.expect("upgrade")
}

/// Reads stdout until `needle` shows up; returns everything read.
async fn read_until(ws: &mut Ws, needle: &str) -> String {
    let mut out = String::new();
    while !out.contains(needle) {
        let (ch, p) = ws.recv_channel().await.expect("open");
        assert_eq!(ch, 1, "stdout expected, got channel {ch}");
        out.push_str(&String::from_utf8_lossy(&p));
    }
    out
}

fn chan(ch: u8, data: &[u8]) -> Vec<u8> {
    [&[ch], data].concat()
}

#[tokio::test]
async fn exec_v5_tty_echo_resize_and_exit_code() {
    let s = srv().await;
    within(async {
        let mut ws = open(&s, &format!("{EXEC}&tty=true"), &[V5, V4]).await;
        assert_eq!(ws.protocol, V5);
        read_until(&mut ws, "$ ").await;
        ws.send(&chan(4, br#"{"Width":120,"Height":40}"#)).await;
        ws.send(&chan(0, b"stty size\r")).await;
        let out = read_until(&mut ws, "40 120").await;
        assert!(out.starts_with("stty size\r"), "tty echo: {out:?}");
        ws.send(&chan(0, b"exit 3\r")).await;
        let status = loop {
            let (ch, p) = ws.recv_channel().await.expect("status");
            if ch == 3 {
                break serde_json::from_slice::<serde_json::Value>(&p).expect("status json");
            }
        };
        assert_eq!(status["reason"], "NonZeroExitCode");
        assert_eq!(status["details"]["causes"][0]["message"], "3");
        assert!(ws.recv_channel().await.is_none(), "closed after the status");
    })
    .await;
    let rec = s.exec_sessions().remove(0);
    assert_eq!(
        (rec.container.as_str(), rec.command.clone(), rec.tty),
        ("app", vec!["/bin/sh".to_owned()], true)
    );
    assert_eq!((rec.resizes.clone(), rec.exit_code), (vec![(120, 40)], Some(3)));
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn exec_v4_fallback_stderr_and_success_status() {
    let s = srv().await;
    s.set_knobs(KubeKnobs { ws_protocols: vec![V4.to_owned()], ..KubeKnobs::default() });
    within(async {
        let mut ws = open(&s, &format!("{EXEC}&stderr=true&tty=false"), &[V5, V4]).await;
        assert_eq!(ws.protocol, V4, "server without v5: the client must fall back");
        ws.send(&chan(0, b"stderr boom\n")).await;
        let mut got = Vec::new();
        while !got.iter().any(|(c, _)| *c == 2) {
            got.push(ws.recv_channel().await.expect("frames"));
        }
        assert!(got.contains(&(2, b"boom\r\n".to_vec())));
        ws.send(&chan(0, b"exit\n")).await;
        loop {
            let (ch, p) = ws.recv_channel().await.expect("status");
            if ch == 3 {
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&p).expect("json")["status"],
                    "Success"
                );
                break;
            }
        }
    })
    .await;
    assert_eq!(s.exec_sessions()[0].exit_code, Some(0));
}

#[tokio::test]
async fn exec_v5_close_stdin_ends_the_shell() {
    let s = srv().await;
    within(async {
        let mut ws = open(&s, EXEC, &[V5]).await;
        ws.send(&chan(0, b"hello")).await;
        assert_eq!(ws.recv_channel().await, Some((1, b"hello".to_vec())));
        ws.send(&[255, 0]).await;
        assert_eq!(ws.recv_channel().await.map(|(c, _)| c), Some(3));
    })
    .await;
    let rec = &s.exec_sessions()[0];
    assert_eq!((rec.stdin_bytes, rec.exit_code), (5, Some(0)));
}

#[tokio::test]
async fn exec_refusals() {
    let s = srv().await;
    within(async {
        let base = "/api/v1/namespaces/default/pods/web-0/exec";
        let no_cmd = ws_connect(s.addr(), &format!("{base}?container=app"), &[V5], &[AUTH]).await;
        assert!(matches!(no_cmd, Err((400, ref b)) if b.contains("at least 1 command")));
        let no_container =
            ws_connect(s.addr(), &format!("{base}?command=sh"), &[V5], &[AUTH]).await;
        assert!(matches!(no_container, Err((400, _))));
        let spdy = ws_connect(s.addr(), EXEC, &["SPDY/3.1+portforward.k8s.io"], &[AUTH]).await;
        assert!(matches!(spdy, Err((400, ref b)) if b.contains("no supported subprotocol")));
        let plain = send(s.addr(), request(Method::GET, EXEC, &[AUTH], Bytes::new()), None).await;
        assert_eq!(plain.status, 400, "exec without Upgrade");
        assert!(matches!(ws_connect(s.addr(), EXEC, &[V5], &[]).await, Err((401, _))));
        s.set_rules(vec![AccessRule::new(&["get", "list"], &["pods"])]);
        assert!(matches!(ws_connect(s.addr(), EXEC, &[V5], &[AUTH]).await, Err((403, _))));
    })
    .await;
    assert!(s.exec_sessions().is_empty());
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn websocket_protocol_violations_end_the_session() {
    let s = srv().await;
    s.set_knobs(KubeKnobs { max_ws_message: 1024, ..KubeKnobs::default() });
    within(async {
        let mut ws = open(&s, EXEC, &[V5]).await;
        ws.send_unmasked(&[0, b'x']).await;
        assert!(ws.recv_channel().await.is_none(), "unmasked client frame");
        let mut ws = open(&s, EXEC, &[V5]).await;
        ws.send(&chan(0, &[b'a'; 2048])).await;
        assert!(ws.recv_channel().await.is_none(), "message over the cap");
    })
    .await;
    eventually(|| s.exec_sessions().len() == 2).await;
    assert!(s.exec_sessions().iter().all(|r| r.exit_code.is_none()));
}

#[tokio::test]
async fn port_forward_prefixes_and_echo() {
    let s = srv().await;
    within(async {
        let path = "/api/v1/namespaces/default/pods/web-0/portforward?ports=8080,9090";
        let mut ws = open(&s, path, &[V4]).await;
        assert_eq!(ws.protocol, V4);
        let mut init = Vec::new();
        for _ in 0..4 {
            init.push(ws.recv_channel().await.expect("prefix"));
        }
        let p = |port: u16| port.to_le_bytes().to_vec();
        assert_eq!(init, vec![(0, p(8080)), (1, p(8080)), (2, p(9090)), (3, p(9090))]);
        ws.send(&chan(0, b"hello")).await;
        assert_eq!(ws.recv_channel().await, Some((0, b"hello".to_vec())));
        ws.send(&chan(2, b"x")).await;
        assert_eq!(ws.recv_channel().await, Some((2, b"x".to_vec())));
        ws.close().await;
    })
    .await;
    eventually(|| s.port_forwards().first().is_some_and(|f| f.bytes_echoed == 6)).await;
    assert_eq!(s.port_forwards()[0].ports, vec![8080, 9090]);
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn port_forward_refusals_and_error_knob() {
    let s = srv().await;
    within(async {
        let base = "/api/v1/namespaces/default/pods/web-0/portforward";
        assert!(
            matches!(ws_connect(s.addr(), base, &[V4], &[AUTH]).await, Err((400, _))),
            "no ports"
        );
        let tunnel = ws_connect(
            s.addr(),
            &format!("{base}?ports=80"),
            &["SPDY/3.1+portforward.k8s.io"],
            &[AUTH],
        )
        .await;
        assert!(matches!(tunnel, Err((400, _))), "KEP-4006 SPDY tunnelling is not implemented");
        s.set_knobs(KubeKnobs {
            portforward_error: Some("connection refused".to_owned()),
            ..KubeKnobs::default()
        });
        let mut ws = open(&s, &format!("{base}?ports=5432"), &["portforward.k8s.io"]).await;
        ws.recv_channel().await.expect("data prefix");
        ws.recv_channel().await.expect("error prefix");
        assert_eq!(ws.recv_channel().await, Some((1, b"connection refused".to_vec())));
        assert!(ws.recv_channel().await.is_none());
    })
    .await;
}
