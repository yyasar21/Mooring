//! Read-only lab check (ADR-0011 test plan): connect to `MOORING_LAB_RDP_HOST` with NLA, wait
//! for `Connected`, the first `DesktopResized` and the first pixels in the `FrameSink`, close.
//!
//! Skipped by default. Run against an RDP host you control with:
//! `MOORING_LAB_RDP_HOST=<host> MOORING_LAB_RDP_USER=<user> MOORING_LAB_RDP_PASSWORD=<pw>
//! cargo test -p mooring-proto-rdp --test lab -- --ignored` (`MOORING_LAB_RDP_PORT` defaults to
//! 3389, `MOORING_LAB_RDP_DOMAIN` is optional; see `.env.example`). The certificate TOFU prompt
//! is answered `yes` into a temporary `known_rdp_certs`, so nothing outside the test changes.
//! The password is never printed. Real hosts never go in the repository.

use std::time::Duration;

use mooring_core::options::RdpConnOptions;
use mooring_core::session::{
    ConnectParams, ConnectSecret, Session, SessionEvent, SessionInput, Size,
};
use mooring_core::FrameSink;
use mooring_proto_rdp::{AuditSink, RdpOptions, RdpSession};

fn lab_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "needs a lab RDP host: set MOORING_LAB_RDP_HOST / _USER / _PASSWORD"]
async fn lab_rdp_connects_and_draws() {
    let (Some(host), Some(user), Some(password)) = (
        lab_var("MOORING_LAB_RDP_HOST"),
        lab_var("MOORING_LAB_RDP_USER"),
        lab_var("MOORING_LAB_RDP_PASSWORD"),
    ) else {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("skipping lab test: MOORING_LAB_RDP_HOST, _USER and _PASSWORD must be set");
        }
        return;
    };
    let port = lab_var("MOORING_LAB_RDP_PORT")
        .map_or(3389, |p| p.parse::<u16>().expect("MOORING_LAB_RDP_PORT must be a port number"));
    let secret = match lab_var("MOORING_LAB_RDP_DOMAIN") {
        Some(domain) => {
            ConnectSecret::DomainPassword { user: user.clone(), domain, password: password.into() }
        }
        None => ConnectSecret::Password(password.into()),
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let options = RdpOptions::new(dir.path().join("known_rdp_certs"), RdpConnOptions::default());
    let params = ConnectParams {
        host,
        port,
        username: Some(user),
        secret,
        r#become: None,
        size: Size { width: 1280, height: 800 },
    };
    let sink = FrameSink::new();
    let mut s =
        RdpSession::connect(params, options, sink.clone(), AuditSink::new()).await.expect("starts");
    let step = Duration::from_secs(30);
    let (mut connected, mut resized) = (false, false);
    while !(connected && resized) {
        match tokio::time::timeout(step, s.next_event()).await {
            Ok(Ok(Some(SessionEvent::Prompt { id, certificate: Some(_), .. }))) => {
                s.send(SessionInput::Answer { id, text: "yes".to_owned().into() })
                    .await
                    .expect("answer");
            }
            Ok(Ok(Some(SessionEvent::Connected { security, .. }))) => {
                assert_eq!(security.as_deref(), Some("nla"));
                connected = true;
            }
            Ok(Ok(Some(SessionEvent::DesktopResized { width, height }))) => {
                assert!(width >= 200 && height >= 200);
                resized = true;
            }
            Ok(Ok(Some(SessionEvent::Closed { reason, code }))) => {
                panic!("closed ({code:?}): {reason}")
            }
            Ok(Ok(Some(_))) => {}
            other => panic!("no Connected: {other:?}"),
        }
    }
    tokio::time::timeout(step, sink.changed()).await.expect("first frame");
    let actions: Vec<_> =
        s.take_audit_events().iter().map(mooring_core::SessionAudit::action).collect();
    assert!(actions.contains(&"session.auth.succeeded"), "{actions:?}");
    s.close().await.expect("close");
}
