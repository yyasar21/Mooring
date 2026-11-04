//! PTY shell: echo round trip, resize, remote exit, close, input validation.

mod common;

use common::*;
use mooring_core::session::{ConnectSecret, Session, SessionEvent, SessionInput, Size};
use mooring_proto_ssh::SshSession;
use russh::MethodKind;
use secrecy::SecretString;

async fn shell() -> (SshSession, TestServer, tempfile::TempDir) {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let secret = ConnectSecret::Password(SecretString::from(PASSWORD));
    let mut s = connect(server.port, secret, &kh).await;
    expect_connected(&mut s).await;
    read_until(&mut s, "welcome").await;
    (s, server, dir)
}

#[tokio::test]
async fn pty_is_xterm_256color_with_initial_size() {
    let (mut s, srv, _d) = shell().await;
    let pty = srv.seen.lock().expect("lock").pty.clone();
    assert_eq!(pty, Some(("xterm-256color".to_owned(), 80, 24)));
    assert!(s.handle().is_some(), "handle exposed after Connected");
    s.close().await.expect("close");
}

#[tokio::test]
async fn echo_round_trip() {
    let (mut s, _srv, _d) = shell().await;
    s.send(SessionInput::Bytes { data: b"hello mooring".to_vec() }).await.expect("send");
    let out = read_until(&mut s, "hello mooring").await;
    assert!(out.contains("hello mooring"));

    let big = vec![b'x'; 200 * 1024];
    s.send(SessionInput::Bytes { data: big.clone() }).await.expect("send big");
    let mut got = 0usize;
    while got < big.len() {
        match next(&mut s).await {
            SessionEvent::Bytes { data } => {
                assert!(data.len() <= mooring_proto_ssh::MAX_CHUNK);
                got += data.len();
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got, big.len());
    s.close().await.expect("close");
}

#[tokio::test]
async fn resize_sends_window_change() {
    let (mut s, srv, _d) = shell().await;
    s.send(SessionInput::Resize { size: Size { width: 132, height: 43 } }).await.expect("resize");
    read_until(&mut s, "RESIZE 132x43").await;
    assert_eq!(srv.seen.lock().expect("lock").resizes, vec![(132, 43)]);
    s.close().await.expect("close");
}

#[tokio::test]
async fn remote_exit_reports_status() {
    let (mut s, _srv, _d) = shell().await;
    s.send(SessionInput::Bytes { data: b"exit\r".to_vec() }).await.expect("send");
    assert_eq!(expect_closed(&mut s).await, "session ended (exit status 0)");
    assert!(s.next_event().await.expect("ok").is_none());
}

#[tokio::test]
async fn close_is_idempotent_and_final() {
    let (mut s, _srv, _d) = shell().await;
    s.close().await.expect("close");
    s.close().await.expect("close again");
    match next(&mut s).await {
        SessionEvent::Closed { reason, code } => {
            assert_eq!(reason, "closed by user");
            assert_eq!(code, mooring_core::CloseCode::User);
        }
        other => panic!("expected Closed, got {other:?}"),
    }
    assert!(s.next_event().await.expect("ok").is_none());
    assert!(s.next_event().await.expect("ok").is_none());
    assert!(s.send(SessionInput::Bytes { data: b"x".to_vec() }).await.is_err());
    s.close().await.expect("close after end");
}

#[tokio::test]
async fn graphical_input_is_refused() {
    let (mut s, _srv, _d) = shell().await;
    let key = SessionInput::Key { code: "KeyA".into(), key: "a".into(), pressed: true };
    assert!(s.send(key).await.is_err());
    assert!(s.send(SessionInput::Wheel { dx: 0, dy: 120 }).await.is_err());
    assert!(s.send(SessionInput::ReleaseAll).await.is_err());
    assert!(s.send(SessionInput::ClipboardOffer).await.is_err());
    s.close().await.expect("close");
}

#[tokio::test]
async fn connect_validates_params() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    let mut p = params(22, ConnectSecret::None);
    p.username = None;
    assert!(SshSession::connect(p, options(&kh)).await.is_err());
    let p = params(0, ConnectSecret::None);
    assert!(SshSession::connect(p, options(&kh)).await.is_err());
    let mut p = params(22, ConnectSecret::None);
    p.host = "bad host".into();
    assert!(SshSession::connect(p, options(&kh)).await.is_err());
}

#[tokio::test]
async fn refused_tcp_is_a_transport_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let dir = tempfile::tempdir().expect("tempdir");
    let err =
        SshSession::connect(params(port, ConnectSecret::None), options(&dir.path().join("kh")))
            .await
            .expect_err("refused");
    assert!(matches!(err, mooring_core::MooringError::Transport(_)));
}

/// Security review 2 L-1: channels the server opens toward the client that we never asked
/// for (`session`, `x11`, `auth-agent@openssh.com`, `direct-tcpip`, `direct-streamlocal`,
/// `forwarded-streamlocal`) are refused; the shell keeps working.
#[tokio::test]
async fn server_opened_channels_are_rejected() {
    let (mut s, srv, _d) = shell().await;
    let h = srv.seen.lock().expect("lock").handle.clone().expect("server handle");
    let t = std::time::Duration::from_secs(10);
    let x11 = tokio::time::timeout(t, h.channel_open_x11("127.0.0.1", 6010)).await;
    assert!(x11.expect("in time").is_err(), "x11");
    let agent = tokio::time::timeout(t, h.channel_open_agent()).await;
    assert!(agent.expect("in time").is_err(), "agent");
    let session = tokio::time::timeout(t, h.channel_open_session()).await;
    assert!(session.expect("in time").is_err(), "session");
    let direct = h.channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1);
    assert!(tokio::time::timeout(t, direct).await.expect("in time").is_err(), "direct-tcpip");
    let sl = h.channel_open_direct_streamlocal("/tmp/agent.sock");
    assert!(tokio::time::timeout(t, sl).await.expect("in time").is_err(), "direct-streamlocal");
    let fsl = h.channel_open_forwarded_streamlocal("/tmp/agent.sock");
    assert!(tokio::time::timeout(t, fsl).await.expect("in time").is_err(), "fwd-streamlocal");

    s.send(SessionInput::Bytes { data: b"still-alive\r".to_vec() }).await.expect("send");
    read_until(&mut s, "still-alive").await;
    s.close().await.expect("close");
}
