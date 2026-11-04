//! Hostile-server tests against QA's `IronRDP` acceptor (`mooring_testsrv::rdp`) with its
//! review-5 knobs: an absurd desktop size (B-5) and oversized channel reassembly (M-14).

use std::time::Duration;

use mooring_core::known_certs::{fingerprint, KnownCerts};
use mooring_core::options::RdpConnOptions;
use mooring_core::session::{CloseCode, ConnectParams, ConnectSecret, Session, SessionEvent, Size};
use mooring_core::FrameSink;
use mooring_testsrv::rdp::{self, RdpConfig, RdpHandle, RdpKnobs};

use crate::{AuditSink, RdpOptions, RdpSession};

pub(crate) fn server(knobs: RdpKnobs) -> RdpHandle {
    rdp::start(RdpConfig { width: 320, height: 240, knobs, ..RdpConfig::default() }, 0)
        .expect("rdp test server")
}

/// Connects with the server's certificate pinned; returns the session, sink and temp dir.
pub(crate) async fn connect(srv: &RdpHandle) -> (RdpSession, FrameSink, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let port = srv.addr().port();
    let mut k = KnownCerts::new();
    k.add("127.0.0.1", port, &fingerprint(srv.cert().cert_der()), time::OffsetDateTime::now_utc());
    k.save(&dir.path().join("known_rdp_certs")).expect("save");
    let mut o = RdpOptions::new(dir.path().join("known_rdp_certs"), RdpConnOptions::default());
    o.connect_timeout = Duration::from_secs(5);
    o.handshake_timeout = Duration::from_secs(20);
    o.keepalive = None;
    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port,
        username: Some("alice".into()),
        secret: ConnectSecret::Password("correct horse".to_owned().into()),
        r#become: None,
        size: Size { width: 320, height: 240 },
    };
    let sink = FrameSink::new();
    let s = RdpSession::connect(params, o, sink.clone(), AuditSink::new()).await.expect("starts");
    (s, sink, dir)
}

/// Events until `Closed`; returns the close code and whether `Connected` was seen.
pub(crate) async fn close_code(s: &mut RdpSession) -> (CloseCode, bool) {
    let mut connected = false;
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(30), s.next_event())
            .await
            .expect("event in time")
            .expect("ok")
            .expect("an event");
        match ev {
            SessionEvent::Connected { .. } => connected = true,
            SessionEvent::Closed { code, .. } => return (code, connected),
            _ => {}
        }
    }
}

/// Peak resident set of this process in KiB (Linux only).
pub(crate) fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn server_desktop_size_is_bounded() {
    use ironrdp_connector::DesktopSize;
    let check = |width, height| crate::active::check_desktop(DesktopSize { width, height });
    for (w, h) in [(8192, 8192), (1, 1), (1024, 768)] {
        assert!(check(w, h).is_ok(), "{w}x{h}");
    }
    for (w, h) in [(0, 768), (1024, 0), (8193, 768), (1024, 8193), (65535, 65535)] {
        let (code, _) = check(w, h).expect_err("refused");
        assert_eq!(code, CloseCode::ProtocolError, "{w}x{h}");
    }
}

#[tokio::test]
async fn huge_server_desktop_is_a_protocol_error_without_allocation() {
    let srv = server(RdpKnobs { advertised_desktop: Some((65535, 65535)), ..RdpKnobs::default() });
    let (mut s, sink, _dir) = connect(&srv).await;
    let (code, connected) = close_code(&mut s).await;
    assert_eq!(code, CloseCode::ProtocolError);
    assert!(!connected, "refused before Connected");
    let (w, h, _) = sink.snapshot();
    assert!(w <= 8192 && h <= 8192);
    if let Some(kib) = peak_rss_kib() {
        assert!(kib < 512 * 1024, "peak RSS {kib} KiB");
    }
}

#[tokio::test]
async fn svc_flood_is_a_protocol_error_with_bounded_memory() {
    let srv = server(RdpKnobs { svc_flood: true, ..RdpKnobs::default() });
    let (mut s, _sink, _dir) = connect(&srv).await;
    let (code, connected) = close_code(&mut s).await;
    assert!(connected);
    assert_eq!(code, CloseCode::ProtocolError);
    if let Some(kib) = peak_rss_kib() {
        assert!(kib < 512 * 1024, "peak RSS {kib} KiB");
    }
}

#[tokio::test]
async fn zero_server_desktop_is_a_protocol_error() {
    let srv = server(RdpKnobs { advertised_desktop: Some((0, 240)), ..RdpKnobs::default() });
    let (mut s, _sink, _dir) = connect(&srv).await;
    assert_eq!(close_code(&mut s).await.0, CloseCode::ProtocolError);
}
