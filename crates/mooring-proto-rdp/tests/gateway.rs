//! RD Gateway end to end (ADR-0027 test plan): the mock gateway (`rdg_mock`) in front of
//! QA's `IronRDP` acceptor. NTLM + TOFU → reconnect → RDP over the tunnel (`nla+rdg`),
//! Basic refused without the option and accepted with it, wrong password, `404` (RPC-only
//! gateway), channel refused, gateway certificate change (hard stop before any HTTP), an
//! oversized packet and a packet out of order.

mod rdg_mock;

use std::sync::Arc;
use std::time::Duration;

use mooring_core::known_certs::{fingerprint, KnownCerts};
use mooring_core::options::{RdGatewayOptions, RdpConnOptions};
use mooring_core::session::{
    CloseCode, ConnectParams, ConnectSecret, HopState, PromptPurpose, Session, SessionEvent,
    SessionInput, Size,
};
use mooring_core::{FrameSink, SessionAudit};
use mooring_proto_rdp::{
    AuditSink, GatewayAccount, GatewayConfig, GatewayCredential, RdpOptions, RdpSession,
};
use mooring_testsrv::rdp::{self, RdpConfig, RdpHandle};
use rdg_mock::{Gateway, Mode, GW_PASS, GW_USER};

struct Run {
    s: RdpSession,
    audit: AuditSink,
    _dir: tempfile::TempDir,
}

fn rdp_server() -> RdpHandle {
    rdp::start(RdpConfig { width: 320, height: 240, ..RdpConfig::default() }, 0).expect("rdp")
}

fn pin(path: &std::path::Path, port: u16, der: &[u8]) {
    let mut k = KnownCerts::load(path).unwrap_or_else(|_| KnownCerts::new());
    k.add("127.0.0.1", port, &fingerprint(der), time::OffsetDateTime::now_utc());
    k.save(path).expect("save");
}

async fn connect(
    srv: &RdpHandle,
    gw: &Gateway,
    allow_basic: bool,
    password: &str,
    pin_gateway: Option<&[u8]>,
) -> Run {
    let dir = tempfile::tempdir().expect("tmp");
    let rdp_known = dir.path().join("known_rdp_certs");
    let gw_known = dir.path().join("known_rdg_certs");
    pin(&rdp_known, srv.addr().port(), srv.cert().cert_der());
    if let Some(der) = pin_gateway {
        pin(&gw_known, gw.addr.port(), der);
    }
    let gateway = RdGatewayOptions {
        host: "127.0.0.1".into(),
        port: gw.addr.port(),
        usage: mooring_core::options::GatewayUsage::Always,
        allow_basic_gateway: allow_basic,
        ca_pem: None,
    };
    let conn = RdpConnOptions { gateway: Some(gateway), ..RdpConnOptions::default() };
    let mut o = RdpOptions::new(&rdp_known, conn);
    o.connect_timeout = Duration::from_secs(5);
    o.handshake_timeout = Duration::from_secs(30);
    o.keepalive = None;
    o.gateway = Some(GatewayConfig {
        known_certs: gw_known,
        credential: Arc::new(GatewayCredential::Account(GatewayAccount {
            username: GW_USER.into(),
            domain: None,
            password: password.to_owned().into(),
        })),
        trusted_once: None,
    });
    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port: srv.addr().port(),
        username: Some("alice".into()),
        secret: ConnectSecret::Password("correct horse".to_owned().into()),
        r#become: None,
        size: Size { width: 320, height: 240 },
    };
    let audit = AuditSink::new();
    let s = RdpSession::connect(params, o, FrameSink::new(), audit.clone()).await.expect("start");
    Run { s, audit, _dir: dir }
}

async fn next(s: &mut RdpSession) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(30), s.next_event())
        .await
        .expect("event in time")
        .expect("ok")
        .expect("an event")
}

/// Events until `Closed` or `Connected` (answering the gateway prompt with `answer`).
async fn until_end(r: &mut Run, answer: &str) -> SessionEvent {
    loop {
        let ev = next(&mut r.s).await;
        match &ev {
            SessionEvent::Prompt { id, purpose, certificate, .. } => {
                assert_eq!(*purpose, PromptPurpose::GatewayCertificateTrust);
                assert!(certificate.is_some());
                let text = answer.to_owned().into();
                r.s.send(SessionInput::Answer { id: *id, text }).await.expect("answer");
            }
            SessionEvent::Connected { .. } | SessionEvent::Closed { .. } => return ev,
            _ => {}
        }
    }
}

fn gateway_rows(a: &AuditSink) -> Vec<(&'static str, &'static str, u32)> {
    a.take()
        .into_iter()
        .filter_map(|e| match e {
            SessionAudit::Gateway { auth, outcome, tunnel_id, .. } => {
                Some((auth, outcome, tunnel_id))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn ntlm_tofu_then_rdp_runs_over_the_tunnel() {
    let srv = rdp_server();
    let gw = rdg_mock::start(Mode::Ntlm, srv.addr()).await;
    let mut r = connect(&srv, &gw, false, GW_PASS, None).await;
    let mut states = Vec::new();
    let ev = loop {
        let ev = next(&mut r.s).await;
        match &ev {
            SessionEvent::GatewayStatus { state, host, .. } => {
                assert_eq!(host, &format!("127.0.0.1:{}", gw.addr.port()));
                states.push(*state);
            }
            SessionEvent::Prompt { id, purpose, .. } => {
                assert_eq!(*purpose, PromptPurpose::GatewayCertificateTrust);
                assert_eq!(gw.log.lock().expect("log").requests, 0, "no HTTP before trust");
                let text = "yes".to_owned().into();
                r.s.send(SessionInput::Answer { id: *id, text }).await.expect("answer");
            }
            _ => break ev,
        }
    };
    let SessionEvent::Connected { security, .. } = ev else { panic!("{ev:?}") };
    assert_eq!(security.as_deref(), Some("nla+rdg"));
    assert!(matches!(next(&mut r.s).await, SessionEvent::DesktopResized { .. }));
    assert_eq!(
        states,
        [HopState::Connecting, HopState::Connecting, HopState::Authenticating, HopState::Up]
    );
    {
        let log = gw.log.lock().expect("log");
        assert!(log.auth_ok && log.requests == 2, "NTLM negotiate + authenticate");
        assert_eq!(log.channels, [("127.0.0.1".to_owned(), srv.addr().port())]);
    }
    assert_eq!(gateway_rows(&r.audit), [("ntlm", "ok", 7)]);
    r.s.close().await.expect("close");
}

#[tokio::test]
async fn wrong_password_is_gateway_auth_and_the_target_is_never_asked() {
    let srv = rdp_server();
    let gw = rdg_mock::start(Mode::Ntlm, srv.addr()).await;
    let mut r = connect(&srv, &gw, false, "wrong", Some(gw.cert.cert_der())).await;
    let SessionEvent::Closed { code, .. } = until_end(&mut r, "no").await else { panic!("closed") };
    assert_eq!(code, CloseCode::GatewayAuth);
    assert!(gw.log.lock().expect("log").channels.is_empty());
    assert_eq!(gateway_rows(&r.audit), [("ntlm", "auth_failed", 0)]);
}

#[tokio::test]
async fn basic_needs_the_option_and_is_audited() {
    let srv = rdp_server();
    let gw = rdg_mock::start(Mode::BasicOnly, srv.addr()).await;
    let mut r = connect(&srv, &gw, false, GW_PASS, Some(gw.cert.cert_der())).await;
    let SessionEvent::Closed { code, reason } = until_end(&mut r, "no").await else { panic!() };
    assert_eq!(code, CloseCode::GatewayAuth);
    assert!(reason.contains("allowBasicGateway"), "{reason}");
    let mut r = connect(&srv, &gw, true, GW_PASS, Some(gw.cert.cert_der())).await;
    let ev = until_end(&mut r, "no").await;
    assert!(matches!(ev, SessionEvent::Connected { .. }), "{ev:?}");
    let rows = r.audit.take();
    assert!(rows.iter().any(|e| matches!(e, SessionAudit::GatewayBasic { .. })));
    assert!(rows
        .iter()
        .any(|e| matches!(e, SessionAudit::Gateway { auth: "basic", outcome: "ok", .. })));
}

#[tokio::test]
async fn refusals_map_to_gateway_codes() {
    let srv = rdp_server();
    for (mode, want) in [
        (Mode::NotFound, CloseCode::GatewayUnsupported),
        (Mode::ChannelRefused, CloseCode::GatewayRefused),
        (Mode::Oversized, CloseCode::ProtocolError),
        (Mode::OutOfOrder, CloseCode::ProtocolError),
        (Mode::BadAccept, CloseCode::ProtocolError),
        (Mode::NoAccept, CloseCode::ProtocolError),
    ] {
        let gw = rdg_mock::start(mode, srv.addr()).await;
        let mut r = connect(&srv, &gw, false, GW_PASS, Some(gw.cert.cert_der())).await;
        let SessionEvent::Closed { code, reason } = until_end(&mut r, "no").await else {
            panic!("{mode:?}")
        };
        assert_eq!(code, want, "{mode:?}: {reason}");
        if mode == Mode::ChannelRefused {
            assert!(reason.contains("0x800759DD"), "{reason}");
        }
        if matches!(mode, Mode::BadAccept | Mode::NoAccept) {
            assert!(reason.contains("did not upgrade to WebSocket"), "{mode:?}: {reason}");
            assert!(
                gw.log.lock().expect("log").channels.is_empty(),
                "no tunnel after a bad accept"
            );
        }
    }
}

#[tokio::test]
async fn changed_gateway_certificate_is_a_hard_stop_before_http() {
    let srv = rdp_server();
    let gw = rdg_mock::start(Mode::Ntlm, srv.addr()).await;
    let other = mooring_testsrv::tls::TestCert::generate(&["127.0.0.1"]).expect("cert");
    let mut r = connect(&srv, &gw, false, GW_PASS, Some(other.cert_der())).await;
    let SessionEvent::Closed { code, reason } = until_end(&mut r, "yes").await else { panic!() };
    assert_eq!(code, CloseCode::TrustMismatch);
    assert!(reason.starts_with("RD GATEWAY CERTIFICATE CHANGED"), "{reason}");
    assert_eq!(gw.log.lock().expect("log").requests, 0);
    let rows = r.audit.take();
    assert!(rows.iter().any(|e| matches!(e, SessionAudit::CertMismatch { .. })));
    assert!(rows.iter().any(|e| matches!(e, SessionAudit::Gateway { outcome: "trust", .. })));
}

#[tokio::test]
async fn rejected_gateway_certificate_closes_with_trust_rejected() {
    let srv = rdp_server();
    let gw = rdg_mock::start(Mode::Ntlm, srv.addr()).await;
    let mut r = connect(&srv, &gw, false, GW_PASS, None).await;
    let SessionEvent::Closed { code, .. } = until_end(&mut r, "no").await else { panic!() };
    assert_eq!(code, CloseCode::TrustRejected);
    assert_eq!(gw.log.lock().expect("log").requests, 0);
}
