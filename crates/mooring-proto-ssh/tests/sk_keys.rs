//! ADR-0024: FIDO2 `ssh_sk_key` sign-in through a fake agent against the in-process server.
//! Unix only (the fake agent is a Unix socket; Windows uses the OpenSSH pipe, same code path
//! above the transport).
#![cfg(unix)]

mod common;
#[path = "sk_support/fake_agent.rs"]
mod fake_agent;

use std::time::Duration;

use common::*;
use fake_agent::{Behaviour, FakeAgent};
use mooring_core::credential::testdata::{public_line, sk_ed25519_public};
use mooring_core::credential::SkBackend;
use mooring_core::session::{CloseCode, ConnectSecret, SessionEvent, SkLogin};
use mooring_proto_ssh::{AuthMethod, SshSession, TrustEvent};
use russh::keys::PublicKey;
use russh::MethodKind;

const APP: &str = "ssh:";

fn sk_of(seed: u8) -> PublicKey {
    let point = ed25519(seed).public_key().key_data().ed25519().expect("ed25519").0;
    sk_ed25519_public(point, APP)
}

fn behaviour(seed: u8, listed: &[PublicKey]) -> Behaviour {
    Behaviour {
        listed: listed.iter().map(|k| k.to_bytes().expect("blob")).collect(),
        signer: ed25519(seed),
        application: APP.to_owned(),
        flags: 0x01,
        delay: Duration::ZERO,
        refuse: false,
    }
}

fn login(key: &PublicKey, certificate: Option<String>) -> ConnectSecret {
    ConnectSecret::SecurityKey(SkLogin {
        public_key: public_line(key),
        fingerprint: key.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
        certificate,
        backend: SkBackend::Agent,
        key_handle: None,
        passphrase: None,
    })
}

struct Run {
    session: SshSession,
    events: Vec<SessionEvent>,
    _server: TestServer,
    _dir: tempfile::TempDir,
}

/// Connect with `secret` through `agent`; collect events up to `Connected` or `Closed`.
async fn run(
    spec: ServerSpec,
    secret: ConnectSecret,
    agent: Option<&FakeAgent>,
    timeout: Duration,
) -> Run {
    let server = start(spec).await;
    let dir = tempfile::tempdir().expect("dir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let mut o = options(&kh);
    o.agent_path =
        Some(agent.map_or_else(|| dir.path().join("no-agent.sock"), |a| a.path().to_owned()));
    o.sk_touch_timeout = timeout;
    let mut session = SshSession::connect(params(server.port, secret), o).await.expect("tcp");
    let mut events = Vec::new();
    loop {
        let e = next(&mut session).await;
        let end = matches!(e, SessionEvent::Connected { .. } | SessionEvent::Closed { .. });
        events.push(e);
        if end {
            break;
        }
    }
    Run { session, events, _server: server, _dir: dir }
}

fn spec_for(key: &PublicKey) -> ServerSpec {
    let mut spec = ServerSpec::new(&[
        MethodKind::PublicKey,
        MethodKind::Password,
        MethodKind::KeyboardInteractive,
    ]);
    spec.authorized_key = Some(key.clone());
    spec
}

fn closed(r: &Run) -> (CloseCode, String) {
    match r.events.last() {
        Some(SessionEvent::Closed { code, reason }) => (*code, reason.clone()),
        other => panic!("expected Closed, got {other:?}"),
    }
}

fn sk_outcome(r: &mut Run) -> Option<&'static str> {
    r.session.take_audit_events().into_iter().find_map(|e| match e {
        TrustEvent::SecurityKeyAuth { outcome, fingerprint, backend } => {
            assert!(fingerprint.starts_with("SHA256:") && backend == "agent");
            Some(outcome)
        }
        _ => None,
    })
}

#[tokio::test]
async fn sk_key_signs_through_the_agent_with_the_touch_banner() {
    let key = sk_of(1);
    let agent = fake_agent::start(behaviour(1, &[sk_of(9), key.clone()]));
    let mut r = run(spec_for(&key), login(&key, None), Some(&agent), Duration::from_secs(5)).await;
    assert!(matches!(r.events.last(), Some(SessionEvent::Connected { .. })), "{:?}", r.events);
    let fp = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
    let touch = r.events.iter().find_map(|e| match e {
        SessionEvent::TouchRequired { id, fingerprint, timeout_seconds, hop } => {
            assert_eq!((fingerprint.as_str(), *timeout_seconds, *hop), (fp.as_str(), 5, None));
            Some(*id)
        }
        _ => None,
    });
    let id = touch.expect("touch_required before the signature");
    assert!(r
        .events
        .iter()
        .any(|e| matches!(e, SessionEvent::TouchCleared { id: i, .. } if *i == id)));
    assert_eq!(agent.signed.lock().expect("lock").as_slice(), &[key.to_bytes().expect("blob")]);
    let audit = r.session.take_audit_events();
    assert!(audit.contains(&TrustEvent::AuthSucceeded { method: AuthMethod::SecurityKey }));
    assert!(audit.iter().any(|e| matches!(e, TrustEvent::SecurityKeyAuth { outcome: "ok", .. })));
}

#[tokio::test]
async fn key_not_in_agent_is_refused_without_a_password_or_prompt() {
    let key = sk_of(1);
    let agent = fake_agent::start(behaviour(2, &[sk_of(2)]));
    let mut r = run(spec_for(&key), login(&key, None), Some(&agent), Duration::from_secs(5)).await;
    let (code, reason) = closed(&r);
    assert_eq!(code, CloseCode::AuthFailed);
    assert!(reason.contains("not in ssh-agent") && reason.contains("ssh-add"), "{reason}");
    assert!(!r.events.iter().any(|e| matches!(e, SessionEvent::Prompt { .. })), "no kbd fallback");
    assert!(agent.signed.lock().expect("lock").is_empty(), "the other key never signs");
    assert_eq!(sk_outcome(&mut r), Some("not_in_agent"));
}

#[tokio::test]
async fn no_agent_is_refused() {
    let key = sk_of(1);
    let mut r = run(spec_for(&key), login(&key, None), None, Duration::from_secs(5)).await;
    let (code, reason) = closed(&r);
    assert_eq!(code, CloseCode::AuthFailed);
    assert!(reason.contains("no ssh-agent"), "{reason}");
    assert_eq!(sk_outcome(&mut r), Some("no_agent"));
}

#[tokio::test]
async fn agent_signing_with_another_key_is_refused_before_the_server() {
    let key = sk_of(1);
    // Lists the right blob but signs with another Ed25519 key.
    let agent = fake_agent::start(behaviour(3, std::slice::from_ref(&key)));
    let mut r = run(spec_for(&key), login(&key, None), Some(&agent), Duration::from_secs(5)).await;
    assert_eq!(closed(&r).0, CloseCode::AuthFailed);
    assert_eq!(sk_outcome(&mut r), Some("bad_signature"));
}

#[tokio::test]
async fn signature_without_user_presence_is_refused() {
    let key = sk_of(1);
    let mut b = behaviour(1, std::slice::from_ref(&key));
    b.flags = 0x04; // UV only, UP unset
    let agent = fake_agent::start(b);
    let mut r = run(spec_for(&key), login(&key, None), Some(&agent), Duration::from_secs(5)).await;
    let (code, reason) = closed(&r);
    assert_eq!(code, CloseCode::AuthFailed);
    assert!(reason.contains("user presence"), "{reason}");
    assert_eq!(sk_outcome(&mut r), Some("no_presence"));
}

#[tokio::test]
async fn touch_timeout_ends_the_attempt() {
    let key = sk_of(1);
    let mut b = behaviour(1, std::slice::from_ref(&key));
    b.delay = Duration::from_secs(5);
    let agent = fake_agent::start(b);
    let mut r =
        run(spec_for(&key), login(&key, None), Some(&agent), Duration::from_millis(300)).await;
    assert!(
        r.events.iter().any(|e| matches!(e, SessionEvent::TouchTimeout { .. })),
        "{:?}",
        r.events
    );
    let (code, reason) = closed(&r);
    assert_eq!(code, CloseCode::AuthFailed);
    assert!(reason.contains("not touched in time"), "{reason}");
    assert_eq!(sk_outcome(&mut r), Some("touch_timeout"));
}

#[tokio::test]
async fn agent_refusal_is_a_generic_failure() {
    let key = sk_of(1);
    let mut b = behaviour(1, std::slice::from_ref(&key));
    b.refuse = true;
    let agent = fake_agent::start(b);
    let mut r = run(spec_for(&key), login(&key, None), Some(&agent), Duration::from_secs(5)).await;
    assert_eq!(closed(&r), (CloseCode::AuthFailed, "authentication failed".to_owned()));
    assert_eq!(sk_outcome(&mut r), Some("refused"));
}

fn sk_cert(key: &PublicKey, ca: &russh::keys::PrivateKey) -> String {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut b =
        Builder::new([4u8; 16], key.key_data().clone(), now - 60, now + 600).expect("builder");
    b.cert_type(CertType::User).expect("type");
    b.valid_principal(USER).expect("principal");
    b.sign(ca).expect("sign").to_openssh().expect("line")
}

/// The R3 `certificate` role for an sk key: `sk-ssh-ed25519-cert-v01@openssh.com`, the key
/// itself not authorized.
#[tokio::test]
async fn sk_certificate_signs_in_through_the_agent() {
    let (key, ca) = (sk_of(1), ed25519(6));
    let mut spec = ServerSpec::new(&[MethodKind::PublicKey]);
    spec.trusted_ca = Some(ca.public_key().clone());
    let cert = sk_cert(&key, &ca);
    assert!(cert.starts_with("sk-ssh-ed25519-cert-v01@openssh.com "));
    let agent = fake_agent::start(behaviour(1, std::slice::from_ref(&key)));
    let mut r = run(spec, login(&key, Some(cert)), Some(&agent), Duration::from_secs(5)).await;
    assert!(matches!(r.events.last(), Some(SessionEvent::Connected { .. })), "{:?}", r.events);
    assert_eq!(sk_outcome(&mut r), Some("ok"));
}

/// A certificate identity held by the agent (no stored certificate) is used too.
#[tokio::test]
async fn agent_held_sk_certificate_is_used() {
    let (key, ca) = (sk_of(1), ed25519(6));
    let mut spec = ServerSpec::new(&[MethodKind::PublicKey]);
    spec.trusted_ca = Some(ca.public_key().clone());
    let cert = russh::keys::Certificate::from_openssh(&sk_cert(&key, &ca)).expect("cert");
    let mut b = behaviour(1, std::slice::from_ref(&key));
    b.listed.push(cert.to_bytes().expect("blob"));
    let agent = fake_agent::start(b);
    let mut r = run(spec, login(&key, None), Some(&agent), Duration::from_secs(5)).await;
    assert!(matches!(r.events.last(), Some(SessionEvent::Connected { .. })), "{:?}", r.events);
    assert_eq!(sk_outcome(&mut r), Some("ok"));
}

#[tokio::test]
async fn agent_holds_reports_presence() {
    let key = sk_of(1);
    let agent = fake_agent::start(behaviour(1, std::slice::from_ref(&key)));
    let line = public_line(&key);
    assert_eq!(mooring_proto_ssh::agent_holds(&line, Some(agent.path())).await, Some(true));
    assert_eq!(
        mooring_proto_ssh::agent_holds(&public_line(&sk_of(2)), Some(agent.path())).await,
        Some(false)
    );
    let dir = tempfile::tempdir().expect("dir");
    assert_eq!(mooring_proto_ssh::agent_holds(&line, Some(&dir.path().join("x"))).await, None);
}
