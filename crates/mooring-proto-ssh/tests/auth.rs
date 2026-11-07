//! Authentication methods: success and generic failure for each.

mod common;

use common::*;
use mooring_core::session::{ConnectSecret, PromptPurpose, SessionEvent};
use mooring_proto_ssh::{AuthMethod, SshSession, TrustEvent};
use russh::MethodKind;
use secrecy::SecretString;

async fn trusted(
    spec: ServerSpec,
    secret: ConnectSecret,
) -> (SshSession, TestServer, tempfile::TempDir) {
    let server = start(spec).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let s = connect(server.port, secret, &kh).await;
    (s, server, dir)
}

fn succeeded_with(s: &mut SshSession) -> Option<AuthMethod> {
    s.take_audit_events().into_iter().find_map(|e| match e {
        TrustEvent::AuthSucceeded { method } => Some(method),
        _ => None,
    })
}

async fn assert_generic_failure(s: &mut SshSession, secret_text: &str) {
    let reason = expect_closed(s).await;
    assert_eq!(reason, "authentication failed");
    assert!(!reason.contains(secret_text));
    assert!(s.take_audit_events().contains(&TrustEvent::AuthFailed));
}

#[tokio::test]
async fn password_success() {
    let secret = ConnectSecret::Password(SecretString::from(PASSWORD));
    let (mut s, _srv, _d) = trusted(ServerSpec::new(&[MethodKind::Password]), secret).await;
    expect_connected(&mut s).await;
    assert_eq!(succeeded_with(&mut s), Some(AuthMethod::Password));
}

#[tokio::test]
async fn password_failure_is_generic() {
    let secret = ConnectSecret::Password(SecretString::from("wrong-pass-123"));
    let (mut s, _srv, _d) = trusted(ServerSpec::new(&[MethodKind::Password]), secret).await;
    assert_generic_failure(&mut s, "wrong-pass-123").await;
}

#[tokio::test]
async fn publickey_success() {
    let client_key = ed25519(1);
    let mut spec = ServerSpec::new(&[MethodKind::PublicKey]);
    spec.authorized_key = Some(client_key.public_key().clone());
    let secret =
        ConnectSecret::PrivateKey { pem: pem(&client_key), passphrase: None, certificate: None };
    let (mut s, _srv, _d) = trusted(spec, secret).await;
    expect_connected(&mut s).await;
    assert_eq!(succeeded_with(&mut s), Some(AuthMethod::PublicKey));
}

fn user_cert(key: &russh::keys::PrivateKey, ca: &russh::keys::PrivateKey) -> String {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut b = Builder::new([3u8; 16], key.public_key().key_data().clone(), now - 60, now + 600)
        .expect("builder");
    b.cert_type(CertType::User).expect("type");
    b.valid_principal(USER).expect("principal");
    b.sign(ca).expect("sign").to_openssh().expect("line")
}

/// ADR-0026 §1: a CA-signed certificate logs in although the key itself is not authorized.
#[tokio::test]
async fn certificate_success_without_an_authorized_key() {
    let (key, ca) = (ed25519(5), ed25519(6));
    let mut spec = ServerSpec::new(&[MethodKind::PublicKey]);
    spec.trusted_ca = Some(ca.public_key().clone());
    let secret = ConnectSecret::PrivateKey {
        pem: pem(&key),
        passphrase: None,
        certificate: Some(user_cert(&key, &ca)),
    };
    let (mut s, _srv, _d) = trusted(spec, secret).await;
    expect_connected(&mut s).await;
    assert_eq!(succeeded_with(&mut s), Some(AuthMethod::PublicKey));
}

/// An untrusted CA, or a certificate of another key, falls back to the plain key.
#[tokio::test]
async fn certificate_refused_falls_back_to_the_key() {
    let (key, ca) = (ed25519(5), ed25519(6));
    for cert in [user_cert(&key, &ca), user_cert(&ed25519(7), &ca), "garbage".to_owned()] {
        let mut spec = ServerSpec::new(&[MethodKind::PublicKey]);
        spec.trusted_ca = Some(ed25519(8).public_key().clone());
        spec.authorized_key = Some(key.public_key().clone());
        let secret =
            ConnectSecret::PrivateKey { pem: pem(&key), passphrase: None, certificate: Some(cert) };
        let (mut s, _srv, _d) = trusted(spec, secret).await;
        expect_connected(&mut s).await;
        assert_eq!(succeeded_with(&mut s), Some(AuthMethod::PublicKey));
    }
}

#[tokio::test]
async fn publickey_failure_is_generic() {
    let mut spec = ServerSpec::new(&[MethodKind::PublicKey]);
    spec.authorized_key = Some(ed25519(1).public_key().clone());
    let secret =
        ConnectSecret::PrivateKey { pem: pem(&ed25519(2)), passphrase: None, certificate: None };
    let (mut s, _srv, _d) = trusted(spec, secret).await;
    assert_generic_failure(&mut s, "PRIVATE KEY").await;
}

#[tokio::test]
async fn undecodable_key_falls_through_to_failure() {
    let spec = ServerSpec::new(&[MethodKind::PublicKey]);
    let secret = ConnectSecret::PrivateKey {
        pem: SecretString::from("not a key"),
        passphrase: None,
        certificate: None,
    };
    let (mut s, _srv, _d) = trusted(spec, secret).await;
    assert_generic_failure(&mut s, "not a key").await;
}

#[tokio::test]
async fn keyboard_interactive_autofills_password_and_prompts_for_otp() {
    let secret = ConnectSecret::Password(SecretString::from(PASSWORD));
    let (mut s, srv, _d) =
        trusted(ServerSpec::new(&[MethodKind::KeyboardInteractive]), secret).await;
    let SessionEvent::Prompt { id, message, secret, purpose, .. } = next(&mut s).await else {
        panic!("expected the OTP prompt");
    };
    assert_eq!(purpose, PromptPurpose::KeyboardInteractive);
    assert!(message.contains("Verification code"), "{message}");
    assert!(!message.contains("Password"), "password prompt was auto-filled");
    assert!(!secret, "server asked for echo");
    answer(&mut s, id, OTP).await;
    expect_connected(&mut s).await;
    assert_eq!(succeeded_with(&mut s), Some(AuthMethod::KeyboardInteractive));
    let seen = srv.seen.lock().expect("lock");
    assert_eq!(seen.kbd_responses, vec![PASSWORD.to_owned(), OTP.to_owned()]);
}

#[tokio::test]
async fn keyboard_interactive_without_vault_password_prompts_secretly() {
    let mut spec = ServerSpec::new(&[MethodKind::KeyboardInteractive]);
    spec.kbd_two_step = false;
    let (mut s, _srv, _d) = trusted(spec, ConnectSecret::None).await;
    let SessionEvent::Prompt { id, message, secret, purpose, .. } = next(&mut s).await else {
        panic!("expected password prompt");
    };
    assert_eq!(purpose, PromptPurpose::KeyboardInteractive, "server text never sets purpose");
    assert!(message.contains("Password"), "{message}");
    assert!(message.starts_with("Mooring test"), "{message}");
    assert!(secret, "no-echo prompt must be secret");
    answer(&mut s, id, PASSWORD).await;
    expect_connected(&mut s).await;
}

#[tokio::test]
async fn keyboard_interactive_failure_is_generic() {
    let secret = ConnectSecret::Password(SecretString::from(PASSWORD));
    let (mut s, _srv, _d) =
        trusted(ServerSpec::new(&[MethodKind::KeyboardInteractive]), secret).await;
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else {
        panic!("expected OTP prompt");
    };
    answer(&mut s, id, "000000").await;
    assert_generic_failure(&mut s, "000000").await;
}

#[tokio::test]
async fn wrong_prompt_id_is_refused() {
    let secret = ConnectSecret::Password(SecretString::from(PASSWORD));
    let (mut s, _srv, _d) =
        trusted(ServerSpec::new(&[MethodKind::KeyboardInteractive]), secret).await;
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else {
        panic!("expected OTP prompt");
    };
    let wrong = mooring_core::session::SessionInput::Answer {
        id: id.wrapping_add(9),
        text: SecretString::from(OTP),
    };
    assert!(mooring_core::session::Session::send(&mut s, wrong).await.is_err());
    answer(&mut s, id, OTP).await;
    expect_connected(&mut s).await;
}
