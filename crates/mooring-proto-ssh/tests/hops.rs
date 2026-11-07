//! ADR-0025 jump hosts against in-process russh servers: chains of 1 and 2 hops, hop TOFU,
//! hop host-key change (hard stop, target never tried), hop auth failure (target never
//! tried), hop loss (`hop_lost`), depth 4 refused, and `ViaSession` around a target session.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use mooring_core::session::{CloseCode, ConnectSecret, HopState, Session, SessionEvent};
use mooring_core::{PromptPurpose, SessionAudit};
use mooring_proto_ssh::{Hop, SshSession, TargetFuture, ViaSession};
use russh::MethodKind;
use secrecy::SecretString;
use tokio::net::TcpListener;

fn password() -> ConnectSecret {
    ConnectSecret::Password(SecretString::from(PASSWORD))
}

fn hop(index: u8, port: u16, secret: ConnectSecret, kh: &std::path::Path) -> Hop {
    Hop {
        params: params(port, secret),
        options: options(kh),
        index,
        connection: format!("hop-{index}"),
    }
}

async fn server() -> TestServer {
    start(ServerSpec::new(&[MethodKind::Password])).await
}

/// Collect `HopStatus` events until something else arrives; returns (statuses, that event).
async fn statuses(s: &mut dyn Session) -> (Vec<(u8, HopState)>, SessionEvent) {
    let mut out = Vec::new();
    loop {
        let e = tokio::time::timeout(Duration::from_secs(20), s.next_event())
            .await
            .expect("event in time")
            .expect("no error")
            .expect("not ended");
        match e {
            SessionEvent::HopStatus { hop, state, .. } => out.push((hop, state)),
            other => return (out, other),
        }
    }
}

fn up_sequence(hops: u8) -> Vec<(u8, HopState)> {
    (0..hops)
        .flat_map(|h| [(h, HopState::Connecting), (h, HopState::Authenticating), (h, HopState::Up)])
        .collect()
}

#[tokio::test]
async fn ssh_through_one_hop_reaches_the_target_via_direct_tcpip() {
    let (a, target) = (server().await, server().await);
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    trust_more(&kh, target.port, &target.host_public);
    let mut s = SshSession::connect_chain(
        params(target.port, password()),
        options(&kh),
        vec![hop(0, a.port, password(), &kh)],
    )
    .expect("chain accepted");
    let (seen, next) = statuses(&mut s).await;
    assert_eq!(seen, up_sequence(1));
    assert!(matches!(next, SessionEvent::Connected { hop: None, .. }), "{next:?}");
    read_until(&mut s, "welcome").await;
    assert_eq!(
        a.seen.lock().expect("lock").direct,
        vec![("127.0.0.1".to_owned(), u32::from(target.port))]
    );
    let audit = s.take_audit_events();
    assert!(audit.iter().any(
        |e| matches!(e, SessionAudit::HopOpened { hop: 0, connection, .. } if connection == "hop-0")
    ));
    s.close().await.expect("close");
    let audit = s.take_audit_events();
    assert!(
        audit.iter().any(|e| matches!(e, SessionAudit::HopClosed { hop: 0, code: "closed", .. })),
        "{audit:?}"
    );
}

#[tokio::test]
async fn ssh_through_two_hops_and_hop_tofu_names_the_hop() {
    let (a, b, target) = (server().await, server().await, server().await);
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    trust_more(&kh, target.port, &target.host_public);
    // Hop 2 (b) is unknown: TOFU prompt tagged with its hop.
    let hops = vec![hop(0, a.port, password(), &kh), hop(1, b.port, password(), &kh)];
    let mut s = SshSession::connect_chain(params(target.port, password()), options(&kh), hops)
        .expect("chain accepted");
    let (seen, next) = statuses(&mut s).await;
    let mut want = up_sequence(1);
    want.push((1, HopState::Connecting));
    assert_eq!(seen, want);
    let SessionEvent::Prompt { id, message, purpose, hop: Some(1), .. } = next else {
        panic!("{next:?}")
    };
    assert_eq!(purpose, PromptPurpose::HostKeyTrust);
    assert!(message.starts_with("Hop 2"), "{message}");
    answer(&mut s, id, "yes").await;
    let (seen, next) = statuses(&mut s).await;
    assert_eq!(seen, vec![(1, HopState::Authenticating), (1, HopState::Up)]);
    assert!(matches!(next, SessionEvent::Connected { .. }), "{next:?}");
    read_until(&mut s, "welcome").await;
    assert_eq!(
        a.seen.lock().expect("lock").direct,
        vec![("127.0.0.1".to_owned(), u32::from(b.port))]
    );
    assert_eq!(
        b.seen.lock().expect("lock").direct,
        vec![("127.0.0.1".to_owned(), u32::from(target.port))]
    );
    // The hop's key is now pinned, like any TOFU.
    assert!(std::fs::read_to_string(&kh).expect("kh").lines().count() >= 3);
    s.close().await.expect("close");
}

#[tokio::test]
async fn hop_host_key_change_is_a_hard_stop_and_the_target_is_never_tried() {
    let (a, target) = (server().await, server().await);
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    // Pin a different key for the hop.
    trust(&kh, a.port, ed25519(99).public_key());
    trust_more(&kh, target.port, &target.host_public);
    let mut s = SshSession::connect_chain(
        params(target.port, password()),
        options(&kh),
        vec![hop(0, a.port, password(), &kh)],
    )
    .expect("chain accepted");
    let (seen, next) = statuses(&mut s).await;
    assert_eq!(seen, vec![(0, HopState::Connecting), (0, HopState::Failed)]);
    let SessionEvent::Closed { code, reason } = next else { panic!("{next:?}") };
    assert_eq!(code, CloseCode::HopFailed);
    assert!(reason.starts_with("hop 1 failed"), "{reason}");
    assert!(a.seen.lock().expect("lock").direct.is_empty(), "no direct-tcpip");
    let audit = s.take_audit_events();
    assert!(audit.iter().any(|e| matches!(e, SessionAudit::HostKeyMismatch { .. })), "{audit:?}");
    assert!(!audit.iter().any(|e| matches!(e, SessionAudit::HopOpened { .. })));
}

#[tokio::test]
async fn hop_auth_failure_never_attempts_the_target() {
    let (a, target) = (server().await, server().await);
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    trust_more(&kh, target.port, &target.host_public);
    let wrong = ConnectSecret::Password(SecretString::from("wrong horse"));
    let mut s = SshSession::connect_chain(
        params(target.port, password()),
        options(&kh),
        vec![hop(0, a.port, wrong, &kh)],
    )
    .expect("chain accepted");
    let (seen, next) = statuses(&mut s).await;
    assert_eq!(
        seen,
        vec![(0, HopState::Connecting), (0, HopState::Authenticating), (0, HopState::Failed)]
    );
    let SessionEvent::Closed { code, reason } = next else { panic!("{next:?}") };
    assert_eq!(code, CloseCode::HopFailed);
    assert!(!reason.contains("wrong horse"));
    assert!(a.seen.lock().expect("lock").direct.is_empty(), "target never dialed");
    assert!(target.seen.lock().expect("lock").pty.is_none());
}

#[tokio::test]
async fn depth_four_and_empty_chains_are_refused_before_any_io() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    let four = (0..4).map(|i| hop(i, 1, password(), &kh)).collect();
    assert!(SshSession::connect_chain(params(22, password()), options(&kh), four).is_err());
    assert!(SshSession::connect_chain(params(22, password()), options(&kh), vec![]).is_err());
}

/// A TCP relay in front of a server, so a test can cut a hop's connection.
async fn relay(to: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.expect("accept");
        let mut out = tokio::net::TcpStream::connect(("127.0.0.1", to)).await.expect("connect");
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
    });
    (port, task)
}

#[tokio::test]
async fn a_lost_hop_closes_the_target_with_hop_lost() {
    let (a, target) = (server().await, server().await);
    let (relay_port, relay) = relay(a.port).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, relay_port, &a.host_public);
    trust_more(&kh, target.port, &target.host_public);
    let mut s = SshSession::connect_chain(
        params(target.port, password()),
        options(&kh),
        vec![hop(0, relay_port, password(), &kh)],
    )
    .expect("chain accepted");
    let (_, first) = statuses(&mut s).await;
    assert!(matches!(first, SessionEvent::Connected { .. }), "{first:?}");
    read_until(&mut s, "welcome").await;
    relay.abort();
    let code = loop {
        match next(&mut s).await {
            SessionEvent::Closed { code, .. } => break code,
            SessionEvent::Bytes { .. } => {}
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(code, CloseCode::HopLost);
    let audit = s.take_audit_events();
    assert!(
        audit.iter().any(|e| matches!(e, SessionAudit::HopClosed { code: "hop_lost", .. })),
        "{audit:?}"
    );
}

#[tokio::test]
async fn via_session_wraps_a_target_and_routes_hop_answers() {
    let (a, target) = (server().await, server().await);
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    // The hop is unknown: its prompt (id above the hop base) is answered through the wrapper.
    trust(&kh, target.port, &target.host_public);
    let kh2 = kh.clone();
    let port = target.port;
    let make = move |dialer| -> TargetFuture {
        Box::pin(async move {
            let s =
                SshSession::connect_via(params(port, password()), options(&kh2), dialer).await?;
            Ok(Box::new(s) as Box<dyn Session>)
        })
    };
    let mut s = ViaSession::start(
        mooring_core::Protocol::Ssh,
        vec![hop(0, a.port, password(), &kh)],
        ("127.0.0.1".to_owned(), target.port),
        make,
    );
    let (seen, next) = statuses(&mut s).await;
    assert_eq!(seen, vec![(0, HopState::Connecting)]);
    let SessionEvent::Prompt { id, hop: Some(0), .. } = next else { panic!("{next:?}") };
    assert!(id > mooring_proto_ssh::HOP_PROMPT_ID_BASE);
    s.send(mooring_core::SessionInput::Answer { id, text: SecretString::from("yes") })
        .await
        .expect("hop answer");
    let (seen, next) = statuses(&mut s).await;
    assert_eq!(seen, vec![(0, HopState::Authenticating), (0, HopState::Up)]);
    assert!(matches!(next, SessionEvent::Connected { .. }), "{next:?}");
    // Target input goes through the wrapper.
    s.send(mooring_core::SessionInput::Bytes { data: b"ping\r".to_vec() }).await.expect("bytes");
    let mut out = String::new();
    while !out.contains("ping") {
        match statuses(&mut s).await.1 {
            SessionEvent::Bytes { data } => out.push_str(&String::from_utf8_lossy(&data)),
            other => panic!("{other:?}"),
        }
    }
    let wrong = s.send(mooring_core::SessionInput::Answer {
        id: mooring_proto_ssh::HOP_PROMPT_ID_BASE + 999,
        text: SecretString::from("yes"),
    });
    assert!(wrong.await.is_err(), "no open hop prompt");
    s.close().await.expect("close");
    let last = s.next_event().await.expect("ok");
    assert!(matches!(last, Some(SessionEvent::Closed { .. })), "{last:?}");
    let audit = s.take_audit_events();
    assert!(audit.iter().any(|e| matches!(e, SessionAudit::HopOpened { .. })));
    assert!(
        audit.iter().any(|e| matches!(e, SessionAudit::HopClosed { code: "closed", .. })),
        "{audit:?}"
    );
    assert_eq!(a.seen.lock().expect("lock").direct.len(), 1, "exactly one target dial");
}

#[tokio::test]
async fn via_session_hop_failure_never_builds_the_target() {
    let a = server().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, a.port, &a.host_public);
    let built = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&built);
    let make = move |_dialer| -> TargetFuture {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(mooring_core::MooringError::Closed) })
    };
    let wrong = ConnectSecret::Password(SecretString::from("nope"));
    let mut s = ViaSession::start(
        mooring_core::Protocol::Rdp,
        vec![hop(0, a.port, wrong, &kh)],
        ("127.0.0.1".to_owned(), 3389),
        make,
    );
    let (_, next) = statuses(&mut s).await;
    let SessionEvent::Closed { code, .. } = next else { panic!("{next:?}") };
    assert_eq!(code, CloseCode::HopFailed);
    assert!(!built.load(std::sync::atomic::Ordering::SeqCst));
}

/// `trust` replaces the file; this adds to it.
fn trust_more(kh: &std::path::Path, port: u16, key: &russh::keys::PublicKey) {
    let mut store = mooring_proto_ssh::KnownHosts::load(kh).unwrap_or_default();
    store.add_hashed("127.0.0.1", port, key).expect("add");
    store.save(kh).expect("save");
}
