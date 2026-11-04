//! Session-level tests against a minimal in-process server: X.224 negotiation answered with
//! a chosen protocol, then TLS with an rcgen certificate. That is enough to drive input
//! validation, NLA enforcement and the whole certificate TOFU flow (prompt → yes → pin →
//! reconnect; mismatch hard stop; reject). The full acceptor (`CredSSP`, active stage) is QA's
//! `mooring-testsrv` (Q2).

use std::sync::Arc;
use std::time::Duration;

use ironrdp_pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use mooring_core::known_certs::{fingerprint, KnownCerts};
use mooring_core::options::RdpConnOptions;
use mooring_core::session::{
    CloseCode, ConnectParams, ConnectSecret, PromptAccount, PromptPurpose, Session, SessionEvent,
    SessionInput, Size,
};
use mooring_core::{FrameSink, SessionAudit};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::test_certs::self_signed;

fn params(port: u16, secret: ConnectSecret) -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".into(),
        port,
        username: Some("alice".into()),
        secret,
        r#become: None,
        size: Size { width: 1024, height: 768 },
    }
}

fn pw() -> ConnectSecret {
    ConnectSecret::Password("not-a-real-password".to_owned().into())
}

fn options(dir: &tempfile::TempDir) -> RdpOptions {
    let mut o = RdpOptions::new(dir.path().join("known_rdp_certs"), RdpConnOptions::default());
    o.connect_timeout = Duration::from_secs(5);
    o.handshake_timeout = Duration::from_secs(10);
    o
}

async fn next(s: &mut RdpSession) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(20), s.next_event())
        .await
        .expect("event in time")
        .expect("ok")
        .expect("an event")
}

async fn read_tpkt(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.ok()?;
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut rest = vec![0; len.checked_sub(4)?];
    s.read_exact(&mut rest).await.ok()?;
    Some(rest)
}

/// Serves `connections` connections: answers the X.224 request with `protocol`, then
/// (unless it is a failure) runs TLS with `cert`/`key` and drops the connection.
async fn fake_server(
    protocol: SecurityProtocol,
    der: Vec<u8>,
    key: rcgen::KeyPair,
    connections: usize,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der)], key)
        .expect("server cert");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        for _ in 0..connections {
            let Ok((mut s, _)) = listener.accept().await else { return };
            if read_tpkt(&mut s).await.is_none() {
                continue;
            }
            let confirm = ConnectionConfirm::Response { flags: ResponseFlags::empty(), protocol };
            let bytes = ironrdp_core::encode_vec(&X224(confirm)).expect("encode");
            let _ = s.write_all(&bytes).await;
            if let Ok(mut tls) = acceptor.accept(s).await {
                // Read whatever CredSSP sends, then hang up.
                let mut buf = [0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
            }
        }
    });
    port
}

#[tokio::test]
async fn connect_validates_inputs() {
    let dir = tempfile::tempdir().expect("dir");
    let sink = FrameSink::new();
    let err = |p, o| async {
        RdpSession::connect(p, o, FrameSink::new(), AuditSink::new()).await.expect_err("refused")
    };
    assert!(matches!(err(params(0, pw()), options(&dir)).await, MooringError::Invalid { .. }));
    let key = ConnectSecret::PrivateKey { pem: "k".to_owned().into(), passphrase: None };
    assert!(err(params(3389, key), options(&dir)).await.to_string().contains("private-key"));
    let mut bad = options(&dir);
    bad.conn.keyboard_layout = 0x0411;
    assert!(err(params(3389, pw()), bad).await.to_string().contains("keyboardLayout"));
    let mut p = params(3389, pw());
    p.host = "bad host".into();
    assert!(RdpSession::connect(p, options(&dir), sink, AuditSink::new()).await.is_err());
}

#[tokio::test]
async fn refused_tcp_closes_with_network() {
    let dir = tempfile::tempdir().expect("dir");
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        l.local_addr().expect("addr").port()
    };
    let mut s =
        RdpSession::connect(params(port, pw()), options(&dir), FrameSink::new(), AuditSink::new())
            .await
            .expect("starts");
    let SessionEvent::Closed { code, .. } = next(&mut s).await else { panic!("expected closed") };
    assert_eq!(code, CloseCode::Network);
    assert!(s.next_event().await.expect("ok").is_none());
}

#[tokio::test]
async fn tls_only_server_is_refused_without_the_option() {
    let dir = tempfile::tempdir().expect("dir");
    let (der, key) = self_signed(&["127.0.0.1"]);
    let port = fake_server(SecurityProtocol::SSL, der, key, 1).await;
    let mut s =
        RdpSession::connect(params(port, pw()), options(&dir), FrameSink::new(), AuditSink::new())
            .await
            .expect("starts");
    let SessionEvent::Closed { code, .. } = next(&mut s).await else { panic!("expected closed") };
    assert_eq!(code, CloseCode::ProtocolError);
}

#[tokio::test]
async fn unknown_certificate_prompts_and_reconnects_without_writing_the_pin() {
    let dir = tempfile::tempdir().expect("dir");
    let (der, key) = self_signed(&["127.0.0.1"]);
    let fp = fingerprint(&der);
    let port = fake_server(SecurityProtocol::HYBRID, der, key, 2).await;
    let audit = AuditSink::new();
    let mut s =
        RdpSession::connect(params(port, pw()), options(&dir), FrameSink::new(), audit.clone())
            .await
            .expect("starts");
    // Input before Connected is dropped, not queued.
    s.send(SessionInput::Pointer { x: 1, y: 1, buttons: 0 }).await.expect("dropped");
    let SessionEvent::Prompt { id, purpose, certificate, .. } = next(&mut s).await else {
        panic!("prompt")
    };
    assert_eq!(purpose, PromptPurpose::CertificateTrust);
    let cert = certificate.expect("certificate info");
    assert!(cert.is_self_signed());
    s.send(SessionInput::Answer { id, text: "yes".to_owned().into() }).await.expect("answer");
    // The reconnect hits the pin and reaches CredSSP; the fake server then hangs up.
    let SessionEvent::Closed { code, .. } = next(&mut s).await else { panic!("closed") };
    assert_ne!(code, CloseCode::TrustRejected);
    assert_ne!(code, CloseCode::TrustMismatch);
    // The pin file and the decision audit belong to the Tauri layer (R2 contract).
    let known = KnownCerts::load(&dir.path().join("known_rdp_certs")).expect("load");
    assert_eq!(known.check("127.0.0.1", port, &fp), mooring_core::known_certs::CertTrust::Unknown);
    let actions: Vec<_> = audit.take().iter().map(SessionAudit::action).collect();
    assert!(!actions.contains(&"trust.cert.added"), "{actions:?}");
}

#[tokio::test]
async fn declined_certificate_closes_with_trust_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let (der, key) = self_signed(&["127.0.0.1"]);
    let port = fake_server(SecurityProtocol::HYBRID, der, key, 1).await;
    let mut s =
        RdpSession::connect(params(port, pw()), options(&dir), FrameSink::new(), AuditSink::new())
            .await
            .expect("starts");
    let SessionEvent::Prompt { id, .. } = next(&mut s).await else { panic!("prompt") };
    s.send(SessionInput::Answer { id, text: "no".to_owned().into() }).await.expect("answer");
    let SessionEvent::Closed { code, .. } = next(&mut s).await else { panic!("closed") };
    assert_eq!(code, CloseCode::TrustRejected);
    assert!(s.take_audit_events().is_empty(), "the Tauri layer audits the answer");
}

#[tokio::test]
async fn trusted_once_skips_the_prompt_without_writing_a_pin() {
    let dir = tempfile::tempdir().expect("dir");
    let (der, key) = self_signed(&["127.0.0.1"]);
    let fp = fingerprint(&der);
    let port = fake_server(SecurityProtocol::HYBRID, der, key, 1).await;
    let mut o = options(&dir);
    o.trusted_once = Some(fp);
    let mut s = RdpSession::connect(params(port, pw()), o, FrameSink::new(), AuditSink::new())
        .await
        .expect("starts");
    // No prompt: the TLS step accepts the leaf and CredSSP starts; the fake server hangs up.
    let ev = next(&mut s).await;
    let SessionEvent::Closed { code, .. } = ev else { panic!("closed, got {ev:?}") };
    assert!(!matches!(code, CloseCode::TrustRejected | CloseCode::TrustMismatch));
    let known = KnownCerts::load(&dir.path().join("known_rdp_certs")).expect("load");
    assert_eq!(known.check("127.0.0.1", port, &fp), mooring_core::known_certs::CertTrust::Unknown);
}

#[tokio::test]
async fn changed_certificate_is_a_hard_stop() {
    let dir = tempfile::tempdir().expect("dir");
    let (old, _) = self_signed(&["127.0.0.1"]);
    let (der, key) = self_signed(&["127.0.0.1"]);
    let port = fake_server(SecurityProtocol::HYBRID, der, key, 1).await;
    let path = dir.path().join("known_rdp_certs");
    KnownCerts::add_and_save(
        &path,
        "127.0.0.1",
        port,
        &fingerprint(&old),
        time::OffsetDateTime::now_utc(),
    )
    .expect("pin");
    let mut s =
        RdpSession::connect(params(port, pw()), options(&dir), FrameSink::new(), AuditSink::new())
            .await
            .expect("starts");
    let SessionEvent::Closed { code, reason } = next(&mut s).await else {
        panic!("closed, no prompt")
    };
    assert_eq!(code, CloseCode::TrustMismatch);
    assert!(reason.starts_with("CERTIFICATE CHANGED for 127.0.0.1:"), "{reason}");
    let actions: Vec<_> = s.take_audit_events().iter().map(SessionAudit::action).collect();
    assert_eq!(actions, vec!["trust.cert.mismatch"]);
}

#[tokio::test]
async fn credential_prompt_comes_first_and_cancel_closes() {
    let dir = tempfile::tempdir().expect("dir");
    let mut s = RdpSession::connect(
        params(9, ConnectSecret::Prompt(PromptAccount::default())),
        options(&dir),
        FrameSink::new(),
        AuditSink::new(),
    )
    .await
    .expect("starts");
    let SessionEvent::Prompt { id, purpose, account, .. } = next(&mut s).await else {
        panic!("prompt")
    };
    assert_eq!(purpose, PromptPurpose::Credential);
    assert!(account.expect("account").needs_domain);
    assert!(
        s.send(SessionInput::Answer { id, text: "yes".to_owned().into() }).await.is_err(),
        "wrong shape"
    );
    let cancel = SessionInput::CredentialAnswer {
        id,
        username: String::new(),
        domain: None,
        password: String::new().into(),
    };
    s.send(cancel).await.expect("answer");
    let SessionEvent::Closed { code, .. } = next(&mut s).await else { panic!("closed") };
    assert_eq!(code, CloseCode::User);
}

#[tokio::test]
async fn close_during_a_prompt_is_quick_and_final() {
    let dir = tempfile::tempdir().expect("dir");
    let (der, key) = self_signed(&["127.0.0.1"]);
    let port = fake_server(SecurityProtocol::HYBRID, der, key, 1).await;
    let mut s =
        RdpSession::connect(params(port, pw()), options(&dir), FrameSink::new(), AuditSink::new())
            .await
            .expect("starts");
    let SessionEvent::Prompt { .. } = next(&mut s).await else { panic!("prompt") };
    tokio::time::timeout(Duration::from_secs(3), s.close()).await.expect("fast").expect("ok");
    let SessionEvent::Closed { code, .. } = next(&mut s).await else { panic!("closed") };
    assert_eq!(code, CloseCode::User);
    assert!(s.next_event().await.expect("ok").is_none());
    assert!(matches!(s.send(SessionInput::ReleaseAll).await, Err(MooringError::Closed)));
    assert_eq!(s.protocol(), mooring_core::Protocol::Rdp);
}
