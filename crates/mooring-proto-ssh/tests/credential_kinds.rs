//! ADR-0009 secrets on SSH: `prompt` (connect-time form), `domain_user` (user@domain over
//! password auth), `sudo_become` after login, FIDO2 refusal.

mod common;

use common::*;
use mooring_core::credential::BecomeMethod;
use mooring_core::session::{Become, ConnectSecret, PromptAccount, SessionEvent, SessionInput};
use mooring_core::{PromptPurpose, Session};
use mooring_proto_ssh::{SshSession, TrustEvent};
use russh::MethodKind;
use secrecy::SecretString;

async fn trusted_with(
    spec: ServerSpec,
    p: mooring_core::session::ConnectParams,
) -> (SshSession, TestServer, tempfile::TempDir) {
    let mut p = p;
    let server = start(spec).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    p.port = server.port;
    let s = SshSession::connect(p, options(&kh)).await.expect("tcp");
    (s, server, dir)
}

fn answer_form(id: u32, user: &str, domain: Option<&str>, pw: &str) -> SessionInput {
    SessionInput::CredentialAnswer {
        id,
        username: user.to_owned(),
        domain: domain.map(str::to_owned),
        password: SecretString::from(pw.to_owned()),
    }
}

#[tokio::test]
async fn prompt_kind_asks_one_form_and_signs_in() {
    let account =
        PromptAccount { username: Some(USER.into()), needs_username: false, ..Default::default() };
    let mut p = params(0, ConnectSecret::Prompt(account));
    p.username = None;
    let (mut s, _srv, _d) = trusted_with(ServerSpec::new(&[MethodKind::Password]), p).await;
    let SessionEvent::Prompt { id, purpose, account, secret, .. } = next(&mut s).await else {
        panic!("expected the sign-in form");
    };
    assert_eq!(purpose, PromptPurpose::Credential);
    assert!(secret);
    assert_eq!(account.and_then(|a| a.username).as_deref(), Some(USER));
    // a text answer is the wrong shape for this prompt
    let wrong = SessionInput::Answer { id, text: SecretString::from(PASSWORD) };
    assert!(s.send(wrong).await.is_err());
    s.send(answer_form(id, USER, None, PASSWORD)).await.expect("answer");
    expect_connected(&mut s).await;
}

#[tokio::test]
async fn prompt_cancel_closes_with_a_clear_reason() {
    let p = params(0, ConnectSecret::Prompt(PromptAccount::default()));
    let (mut s, _srv, _d) = trusted_with(ServerSpec::new(&[MethodKind::Password]), p).await;
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else { panic!("form") };
    s.send(answer_form(id, "", None, "")).await.expect("cancel answer");
    assert_eq!(expect_closed(&mut s).await, "authentication cancelled");
}

#[tokio::test]
async fn domain_password_logs_in_as_user_at_domain() {
    let mut spec = ServerSpec::new(&[MethodKind::Password]);
    spec.password_user = "alice@CORP".to_owned();
    let secret = ConnectSecret::DomainPassword {
        user: "alice".into(),
        domain: "CORP".into(),
        password: SecretString::from(PASSWORD),
    };
    let (mut s, _srv, _d) = trusted_with(spec, params(0, secret)).await;
    expect_connected(&mut s).await;
    assert!(s.take_audit_events().iter().any(|e| matches!(e, TrustEvent::AuthSucceeded { .. })));
}

#[tokio::test]
async fn prompt_domain_answer_becomes_user_at_domain() {
    let mut spec = ServerSpec::new(&[MethodKind::Password]);
    spec.password_user = "bob@corp.example".to_owned();
    let p = params(
        0,
        ConnectSecret::Prompt(PromptAccount { needs_domain: true, ..Default::default() }),
    );
    let (mut s, _srv, _d) = trusted_with(spec, p).await;
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else { panic!("form") };
    s.send(answer_form(id, "bob", Some("corp.example"), PASSWORD)).await.expect("answer");
    expect_connected(&mut s).await;
}

#[tokio::test]
async fn become_types_sudo_and_answers_the_prompt_once() {
    let mut spec = ServerSpec::new(&[MethodKind::Password]);
    spec.become_prompt = true;
    let mut p = params(0, ConnectSecret::Password(SecretString::from(PASSWORD)));
    p.r#become = Some(Become {
        method: BecomeMethod::Sudo,
        user: "root".into(),
        password: Some(SecretString::from("test-become-pw")),
    });
    let (mut s, srv, _d) = trusted_with(spec, p).await;
    expect_connected(&mut s).await;
    let out = read_until(&mut s, "root# ").await;
    assert!(!out.contains("test-become-pw"), "password never reaches the UI stream: {out:?}");
    let lines = srv.seen.lock().expect("lock").shell_lines.clone();
    assert!(
        lines[0].starts_with("sudo -p '[mooring]%% become password: ' -i -u root"),
        "{lines:?}"
    );
    assert_eq!(lines.iter().filter(|l| l.as_str() == "test-become-pw\n").count(), 1, "{lines:?}");
    assert!(!s.take_audit_events().iter().any(|e| matches!(e, TrustEvent::BecomeFailed)));
}

#[tokio::test]
async fn become_failure_interrupts_once_notifies_and_keeps_the_login_user() {
    let mut spec = ServerSpec::new(&[MethodKind::Password]);
    spec.become_prompt = true;
    spec.become_wrong = true;
    let mut p = params(0, ConnectSecret::Password(SecretString::from(PASSWORD)));
    p.r#become = Some(Become {
        method: BecomeMethod::Sudo,
        user: "root".into(),
        password: Some(SecretString::from("test-wrong-become-pw")),
    });
    let (mut s, srv, _d) = trusted_with(spec, p).await;
    expect_connected(&mut s).await;
    let out = read_until(&mut s, "alice$ ").await;
    assert!(out.contains("Sorry, try again."), "{out:?}");
    assert!(out.contains("[mooring] become failed"), "notice line in the stream: {out:?}");
    assert!(!out.contains("test-wrong-become-pw"), "password never reaches the UI stream");
    let lines = srv.seen.lock().expect("lock").shell_lines.clone();
    assert_eq!(lines.iter().filter(|l| l.contains("test-wrong-become-pw")).count(), 1, "{lines:?}");
    assert_eq!(lines.iter().filter(|l| l.as_str() == "\x03").count(), 1, "one ^C: {lines:?}");
    assert_eq!(lines.last().map(String::as_str), Some("\x03"), "nothing after ^C: {lines:?}");
    assert!(s.take_audit_events().iter().any(|e| matches!(e, TrustEvent::BecomeFailed)));
    // the session is still open, as the login user
    s.send(SessionInput::Bytes { data: b"id\n".to_vec() }).await.expect("still usable");
}

#[tokio::test]
async fn become_user_that_could_inject_is_refused_before_connecting() {
    let mut p = params(22, ConnectSecret::None);
    p.r#become = Some(Become { method: BecomeMethod::Su, user: "root; id".into(), password: None });
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(SshSession::connect(p, options(&dir.path().join("kh"))).await.is_err());
}

#[tokio::test]
async fn fido_security_keys_are_refused_with_a_clear_reason() {
    use russh::keys::ssh_key::private::{KeypairData, SkEd25519};
    use russh::keys::ssh_key::public::SkEd25519 as SkPub;
    let pk = SkPub::new(ed25519(9).public_key().key_data().ed25519().copied().expect("ed"), "ssh:");
    let sk = SkEd25519::new(pk, 0, vec![1, 2, 3]).expect("sk");
    let key = russh::keys::PrivateKey::new(KeypairData::SkEd25519(sk), "").expect("sk key");
    let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).expect("pem").to_string();
    let secret = ConnectSecret::PrivateKey { pem: SecretString::from(pem), passphrase: None };
    let (mut s, _srv, _d) =
        trusted_with(ServerSpec::new(&[MethodKind::PublicKey]), params(0, secret)).await;
    assert_eq!(
        expect_closed(&mut s).await,
        "this credential is not supported for ssh in this version"
    );
}
