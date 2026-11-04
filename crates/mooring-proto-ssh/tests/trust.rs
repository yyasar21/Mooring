//! Host-key TOFU / known-host / mismatch scenarios against the in-process server.

mod common;

use common::*;
use mooring_core::session::{ConnectSecret, Session, SessionEvent};
use mooring_proto_ssh::known_hosts::{fingerprint, KnownHosts};
use mooring_proto_ssh::{TrustDecision, TrustEvent};
use russh::MethodKind;
use secrecy::SecretString;

fn password() -> ConnectSecret {
    ConnectSecret::Password(SecretString::from(PASSWORD))
}

#[tokio::test]
async fn tofu_accept_stores_hashed_entry_and_connects() {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");

    let mut s = connect(server.port, password(), &kh).await;
    let message = accept_tofu(&mut s).await;
    let fp = fingerprint(&server.host_public);
    assert!(message.contains(&format!("127.0.0.1:{}", server.port)), "{message}");
    assert!(message.contains(&format!("ssh-ed25519 {fp}")), "{message}");
    assert!(message.ends_with("trust this host?"), "{message}");

    let peer = expect_connected(&mut s).await;
    assert_eq!(peer, Some(format!("ssh-ed25519 {fp}")));

    let text = std::fs::read_to_string(&kh).expect("known_hosts written");
    assert!(text.starts_with("|1|"), "entry is hashed: {text}");
    assert!(!text.contains("127.0.0.1"), "host name not in clear");
    let store = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(store.check("127.0.0.1", server.port, &server.host_public), TrustDecision::Known);

    let events = s.take_audit_events();
    assert!(events.iter().any(|e| matches!(e,
        TrustEvent::HostKeyAdded { fingerprint, key_type, .. }
            if *fingerprint == fp && key_type == "ssh-ed25519")));
    s.close().await.expect("close");
}

#[tokio::test]
async fn tofu_decline_closes_and_writes_nothing() {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");

    let mut s = connect(server.port, password(), &kh).await;
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else {
        panic!("expected prompt");
    };
    answer(&mut s, id, "no").await;
    assert_eq!(expect_closed(&mut s).await, "host key not trusted");
    assert!(!kh.exists(), "nothing written on decline");
    assert!(s.take_audit_events().iter().any(|e| matches!(e, TrustEvent::HostKeyRejected { .. })));
    assert!(s.next_event().await.expect("ok").is_none(), "stream ends");
}

#[tokio::test]
async fn known_host_connects_without_prompt() {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let before = std::fs::read(&kh).expect("read");

    let mut s = connect(server.port, password(), &kh).await;
    let peer = expect_connected(&mut s).await;
    assert!(peer.expect("peer").starts_with("ssh-ed25519 SHA256:"));
    assert_eq!(std::fs::read(&kh).expect("read"), before, "file untouched");
    assert!(!s.take_audit_events().iter().any(|e| matches!(e, TrustEvent::HostKeyAdded { .. })));
    s.close().await.expect("close");
}

#[tokio::test]
async fn mismatch_is_a_hard_stop_and_changes_nothing() {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    let old = ed25519(77).public_key().clone();
    trust(&kh, server.port, &old);
    let before = std::fs::read(&kh).expect("read");

    let mut s = connect(server.port, password(), &kh).await;
    // No prompt: the first event is Closed.
    let reason = match next(&mut s).await {
        SessionEvent::Closed { reason, code } => {
            assert_eq!(code, mooring_core::CloseCode::TrustMismatch);
            reason
        }
        other => panic!("expected hard stop, got {other:?}"),
    };
    let expected = format!(
        "HOST KEY CHANGED for 127.0.0.1: expected {}, got {}",
        fingerprint(&old),
        fingerprint(&server.host_public)
    );
    assert_eq!(reason, expected);
    assert_eq!(std::fs::read(&kh).expect("read"), before, "store unchanged");
    let events = s.take_audit_events();
    assert!(events.iter().any(|e| matches!(e, TrustEvent::HostKeyMismatch { .. })));
    assert!(!events.iter().any(|e| matches!(e, TrustEvent::AuthSucceeded { .. })));
}

/// Review 6b L-35: two distinct ed25519 keys for the host (what a sync merge leaves behind)
/// fail closed with `trust_conflict`, even though one of them is the server's; removing the
/// stray entry restores the connection.
#[tokio::test]
async fn conflicting_host_keys_fail_closed_until_one_is_removed() {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let stray = ed25519(78).public_key().clone();
    KnownHosts::add_and_save(&kh, "127.0.0.1", server.port, &stray).expect("second pin");
    let before = std::fs::read(&kh).expect("read");

    let mut s = connect(server.port, password(), &kh).await;
    match next(&mut s).await {
        SessionEvent::Closed { reason, code } => {
            assert_eq!(code, mooring_core::CloseCode::TrustConflict);
            assert!(
                reason.starts_with("CONFLICTING HOST KEYS (ssh-ed25519) for 127.0.0.1"),
                "{reason}"
            );
            assert!(!reason.contains("SHA256:"), "no fingerprint in the reason");
        }
        other => panic!("expected hard stop, got {other:?}"),
    }
    assert_eq!(std::fs::read(&kh).expect("read"), before, "store unchanged");
    let events = s.take_audit_events();
    assert!(!events.iter().any(|e| matches!(e, TrustEvent::AuthSucceeded { .. })));

    // The user keeps the server's key only.
    std::fs::write(&kh, b"").expect("truncate");
    trust(&kh, server.port, &server.host_public);
    let mut s = connect(server.port, password(), &kh).await;
    expect_connected(&mut s).await;
    s.close().await.expect("close");
}

#[tokio::test]
async fn close_while_tofu_prompt_is_open() {
    let server = start(ServerSpec::new(&[MethodKind::Password])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    let mut s = connect(server.port, password(), &kh).await;
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else {
        panic!("expected prompt");
    };
    s.close().await.expect("close");
    assert!(matches!(next(&mut s).await, SessionEvent::Closed { .. }));
    assert!(s.next_event().await.expect("ok").is_none());
    assert!(s
        .send(mooring_core::session::SessionInput::Answer { id, text: SecretString::from("yes") })
        .await
        .is_err());
    assert!(!kh.exists());
}
