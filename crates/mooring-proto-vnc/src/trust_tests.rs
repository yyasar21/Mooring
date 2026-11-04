//! Review-5 trust tests against QA's RFB server: the "TLS seen" downgrade guard (M-13), an
//! unreadable trust store (L-20) and None-only offers with a password configured (L-27).

use std::time::Duration;

use mooring_core::frame::FrameSink;
use mooring_core::known_certs::KnownCerts;
use mooring_core::options::{VncConnOptions, VncSecurity};
use mooring_core::session::{CloseCode, ConnectParams, ConnectSecret, SessionEvent, Size};
use mooring_core::{Session, SessionAudit};
use mooring_testsrv::rfb::VeNCryptSub as Sub;
use mooring_testsrv::rfb::{self, Knobs, RfbConfig, RfbHandle, SecurityOffer as Sec};
use mooring_testsrv::tls::TestCert;
use secrecy::SecretString;

use crate::{AuditLog, VncOptions, VncSession};

fn pw(p: &str) -> ConnectSecret {
    ConnectSecret::Password(SecretString::from(p.to_owned()))
}

async fn server(security: Vec<Sec>, cert: Option<TestCert>) -> RfbHandle {
    let cfg = RfbConfig {
        width: 64,
        height: 48,
        security,
        cert,
        password: Some("pw".into()),
        ..RfbConfig::default()
    };
    rfb::start(cfg, 0).await.expect("rfb test server")
}

async fn session(
    port: u16,
    secret: ConnectSecret,
    conn: VncConnOptions,
    known: &std::path::Path,
) -> VncSession {
    let mut o = VncOptions::new(known.to_path_buf(), conn);
    o.handshake_timeout = Duration::from_secs(5);
    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port,
        username: None,
        secret,
        r#become: None,
        size: Size { width: 800, height: 600 },
    };
    VncSession::connect(params, o, FrameSink::new(), AuditLog::default()).await.expect("connect")
}

/// Events until `Connected` (its security label) or `Closed` (its code).
async fn outcome(s: &mut VncSession) -> Result<Option<String>, CloseCode> {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(10), s.next_event())
            .await
            .expect("event in time")
            .expect("ok")
            .expect("some");
        match ev {
            SessionEvent::Connected { security, .. } => return Ok(security),
            SessionEvent::Closed { code, .. } => return Err(code),
            _ => {}
        }
    }
}

#[tokio::test]
async fn tls_seen_marker_turns_a_stripped_vencrypt_into_a_hard_stop() {
    let (cert, ca_pem) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("ca cert");
    let srv = server(vec![Sec::VeNCrypt(vec![Sub::X509Vnc]), Sec::VncAuth], Some(cert)).await;
    let port = srv.addr().port();
    let dir = tempfile::tempdir().expect("tmp");
    let known = dir.path().join("known_vnc_certs");
    let conn = VncConnOptions { ca_pem: Some(ca_pem), ..VncConnOptions::default() };
    assert_eq!(conn.security, VncSecurity::PreferTls, "the default");

    // A CA-valid connect: no prompt, no pin.
    let mut s = session(port, pw("pw"), conn.clone(), &known).await;
    assert_eq!(outcome(&mut s).await, Ok(Some("vencrypt-x509".to_owned())));
    assert!(s.take_audit_events().iter().any(|a| matches!(a, SessionAudit::CertCaValid { .. })));
    drop(s);
    assert!(!KnownCerts::load(&known).expect("load").has_pin("127.0.0.1", port));

    // Without a marker a stripped VeNCrypt silently falls back to VNC auth (R-VNC-PLAIN).
    srv.set_knobs(Knobs { strip_tls_after: Some(0), ..Knobs::default() });
    let mut s = session(port, pw("pw"), conn.clone(), &known).await;
    assert_eq!(outcome(&mut s).await, Ok(Some("vnc-auth".to_owned())));
    drop(s);

    // The Tauri layer records "TLS seen"; the same strip is now a hard stop before any DES.
    KnownCerts::mark_tls_and_save(&known, "127.0.0.1", port, time::OffsetDateTime::now_utc())
        .expect("mark");
    let chosen = srv.stats().chosen_security.len();
    let mut s = session(port, pw("pw"), conn, &known).await;
    assert_eq!(outcome(&mut s).await, Err(CloseCode::TrustMismatch));
    let audit = s.take_audit_events();
    assert!(
        audit.iter().any(|a| matches!(a, SessionAudit::CertMismatch { expected, presented, .. }
            if expected == "tls-required" && presented == "none")),
        "{audit:?}"
    );
    assert_eq!(srv.stats().chosen_security.len(), chosen, "no security type chosen, no DES sent");
}

#[tokio::test]
async fn unreadable_trust_store_fails_closed() {
    let srv = server(vec![Sec::VncAuth], None).await;
    let dir = tempfile::tempdir().expect("tmp");
    // A directory where the file should be: every read fails with an I/O error.
    let known = dir.path().join("known_vnc_certs");
    std::fs::create_dir(&known).expect("dir");
    let mut s = session(srv.addr().port(), pw("pw"), VncConnOptions::default(), &known).await;
    assert_eq!(outcome(&mut s).await, Err(CloseCode::ProtocolError));
    assert_eq!(srv.stats().connections, 0, "nothing sent before the store is read");
}
