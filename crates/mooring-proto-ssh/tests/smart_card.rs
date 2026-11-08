//! ADR-0027 §2: `smart_card` sign-in through the ssh-agent against the in-process server. A
//! fake agent holds (or, after `SSH_AGENTC_ADD_SMARTCARD_KEY` with the right PIN, loads) one
//! Ed25519 "card" key. Unix only (the fake agent is a Unix socket).
#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use mooring_core::credential::Pkcs11Module;
use mooring_core::session::{
    CloseCode, ConnectSecret, PivLogin, PromptPurpose, Session as _, SessionEvent, SessionInput,
};
use mooring_proto_ssh::{SshSession, TrustEvent};
use russh::keys::signature::Signer;
use russh::keys::{HashAlg, PrivateKey};
use russh::MethodKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const PIN: &str = "123456";

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).expect("len").to_be_bytes());
    out.extend_from_slice(b);
}

fn take<'a>(buf: &mut &'a [u8]) -> &'a [u8] {
    let len = usize::try_from(u32::from_be_bytes(buf[..4].try_into().expect("4"))).expect("len");
    let (s, rest) = buf[4..].split_at(len);
    *buf = rest;
    s
}

/// `(provider, pin, constraints)` of one constrained add.
type Add = (String, String, Vec<u8>);

struct Agent {
    path: PathBuf,
    /// `(provider, pin, constraints)` of every `ADD_SMARTCARD_KEY_CONSTRAINED` received.
    adds: Arc<Mutex<Vec<Add>>>,
    _dir: tempfile::TempDir,
}

/// A fake agent holding `key` when `loaded`, or after `ADD_SMARTCARD_KEY_CONSTRAINED` with
/// [`PIN`]. The unconstrained `ADD_SMARTCARD_KEY` (20) is answered with failure.
fn agent(key: PrivateKey, loaded: bool) -> Agent {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let adds = Arc::new(Mutex::new(Vec::new()));
    let (a2, held) = (Arc::clone(&adds), Arc::new(Mutex::new(loaded)));
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let (key, adds, held) = (key.clone(), Arc::clone(&a2), Arc::clone(&held));
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let n = usize::try_from(u32::from_be_bytes(len)).expect("len");
                    let mut body = vec![0u8; n];
                    if s.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let blob = key.public_key().to_bytes().expect("blob");
                    let reply = match body[0] {
                        11 => {
                            let has = *held.lock().expect("held");
                            let mut r = vec![12u8];
                            r.extend_from_slice(&u32::from(has).to_be_bytes());
                            if has {
                                put(&mut r, &blob);
                                put(&mut r, b"PIV AUTH key");
                            }
                            r
                        }
                        13 if *held.lock().expect("held") => {
                            let mut rest = &body[1..];
                            let _ = take(&mut rest);
                            let data = take(&mut rest).to_vec();
                            let sig: russh::keys::ssh_key::Signature =
                                key.try_sign(&data).expect("sign");
                            let mut enc = Vec::new();
                            put(&mut enc, b"ssh-ed25519");
                            put(&mut enc, sig.as_bytes());
                            let mut r = vec![14u8];
                            put(&mut r, &enc);
                            r
                        }
                        26 => {
                            let mut rest = &body[1..];
                            let provider = String::from_utf8(take(&mut rest).to_vec()).expect("p");
                            let pin = String::from_utf8(take(&mut rest).to_vec()).expect("pin");
                            let ok = pin == PIN;
                            adds.lock().expect("adds").push((provider, pin, rest.to_vec()));
                            *held.lock().expect("held") |= ok;
                            vec![if ok { 6 } else { 5 }]
                        }
                        _ => vec![5u8],
                    };
                    let mut frame = Vec::new();
                    put(&mut frame, &reply);
                    if s.write_all(&frame).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Agent { path, adds, _dir: dir }
}

fn login(key: &PrivateKey, module: Option<Pkcs11Module>) -> ConnectSecret {
    let public = key.public_key();
    ConnectSecret::SmartCard(PivLogin {
        public_key: public.to_openssh().expect("line"),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        module,
        reader_hint: Some("Test reader".into()),
    })
}

/// Connect; answer a smart-card PIN prompt with `pin`; return the events and the audit.
async fn run(
    key: &PrivateKey,
    a: &Agent,
    module: Option<Pkcs11Module>,
    pin: &str,
) -> (Vec<SessionEvent>, Vec<TrustEvent>) {
    let mut spec = ServerSpec::new(&[MethodKind::PublicKey, MethodKind::Password]);
    spec.authorized_key = Some(key.public_key().clone());
    let server = start(spec).await;
    let dir = tempfile::tempdir().expect("dir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let mut o = options(&kh);
    o.agent_path = Some(a.path.clone());
    o.pkcs11_module_path = Some(PathBuf::from("/usr/lib/test-pkcs11.so"));
    let mut s = SshSession::connect(params(server.port, login(key, module)), o).await.expect("tcp");
    let mut events = Vec::new();
    loop {
        let e = tokio::time::timeout(Duration::from_secs(20), next(&mut s)).await.expect("in time");
        if let SessionEvent::Prompt { id, purpose, secret, .. } = &e {
            assert_eq!((*purpose, *secret), (PromptPurpose::SmartCardPin, true));
            let text = pin.to_owned().into();
            s.send(SessionInput::Answer { id: *id, text }).await.expect("answer");
        }
        let end = matches!(e, SessionEvent::Connected { .. } | SessionEvent::Closed { .. });
        events.push(e);
        if end {
            break;
        }
    }
    let audit = s.take_audit_events();
    (events, audit)
}

fn closed(events: &[SessionEvent]) -> (CloseCode, String) {
    match events.last() {
        Some(SessionEvent::Closed { code, reason }) => (*code, reason.clone()),
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[tokio::test]
async fn key_already_in_the_agent_signs_without_a_pin() {
    let key = ed25519(3);
    let a = agent(key.clone(), true);
    let (events, audit) = run(&key, &a, Some(Pkcs11Module::Opensc), "unused").await;
    assert!(matches!(events.last(), Some(SessionEvent::Connected { .. })), "{events:?}");
    assert!(!events.iter().any(|e| matches!(e, SessionEvent::Prompt { .. })));
    assert!(a.adds.lock().expect("adds").is_empty());
    assert!(audit
        .iter()
        .any(|e| matches!(e, TrustEvent::SecurityKeyAuth { backend: "piv", outcome: "ok", .. })));
}

#[tokio::test]
async fn pin_loads_the_card_into_the_agent_then_signs() {
    let key = ed25519(4);
    let a = agent(key.clone(), false);
    let (events, audit) = run(&key, &a, Some(Pkcs11Module::Ykcs11), PIN).await;
    assert!(matches!(events.last(), Some(SessionEvent::Connected { .. })), "{events:?}");
    let adds = a.adds.lock().expect("adds").clone();
    // Review 9 L-49: SSH_AGENT_CONSTRAIN_LIFETIME (1) with 3600 s, nothing else.
    let lifetime = [1, 0, 0, 0x0e, 0x10];
    assert_eq!(adds, [("/usr/lib/test-pkcs11.so".to_owned(), PIN.to_owned(), lifetime.to_vec())]);
    assert_eq!(mooring_proto_ssh::CARD_LIFETIME_SECS, 3600);
    assert!(audit.iter().any(|e| matches!(e, TrustEvent::PinPrompted { outcome: "entered", .. })));
    let shown = format!("{audit:?}");
    assert!(!shown.contains(PIN), "the PIN never reaches the audit");
}

#[tokio::test]
async fn wrong_pin_cancel_and_no_module_are_refused_without_a_password() {
    let key = ed25519(5);
    let a = agent(key.clone(), false);
    let (events, _) = run(&key, &a, Some(Pkcs11Module::Opensc), "0000").await;
    let (code, reason) = closed(&events);
    assert_eq!(code, CloseCode::AuthFailed);
    assert!(reason.contains("could not load the smart card"), "{reason}");
    let (events, audit) = run(&key, &a, Some(Pkcs11Module::Opensc), "").await;
    assert_eq!(closed(&events).0, CloseCode::User);
    assert!(audit
        .iter()
        .any(|e| matches!(e, TrustEvent::PinPrompted { outcome: "cancelled", .. })));
    let (events, _) = run(&key, &a, None, PIN).await;
    let (code, reason) = closed(&events);
    assert_eq!(code, CloseCode::AuthFailed);
    assert!(reason.contains("ssh-add -s"), "{reason}");
    assert!(!events.iter().any(|e| matches!(e, SessionEvent::Prompt { .. })));
}

#[tokio::test]
async fn agent_holds_key_reports_the_card() {
    let key = ed25519(6);
    let a = agent(key.clone(), true);
    let line = key.public_key().to_openssh().expect("line");
    assert_eq!(mooring_proto_ssh::agent_holds_key(&line, Some(&a.path)).await, Some(true));
    let other = ed25519(7).public_key().to_openssh().expect("line");
    assert_eq!(mooring_proto_ssh::agent_holds_key(&other, Some(&a.path)).await, Some(false));
}
