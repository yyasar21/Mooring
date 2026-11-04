//! Loopback end-to-end tests against QA's `IronRDP` acceptor (`mooring_testsrv::rdp`):
//! NLA and TLS-only, certificate TOFU (yes / no / mismatch), bitmap updates into the
//! `FrameSink`, input reaching the server, clipboard text both ways, Display Control resize.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mooring_core::clipboard::Clipboard;
use mooring_core::known_certs::{fingerprint, peer_identity, KnownCerts};
use mooring_core::options::{ClipboardPolicy, RdpConnOptions};
use mooring_core::session::{
    CloseCode, ConnectParams, ConnectSecret, PromptPurpose, Session, SessionEvent, SessionInput,
    Size,
};
use mooring_core::{FrameSink, SessionAudit};
use mooring_proto_rdp::{AuditSink, RdpOptions, RdpSession};
use mooring_testsrv::rdp::{
    self, BitmapMode, InputRecord, RdpConfig, RdpHandle, RdpSecurity, Rect,
};
use mooring_testsrv::tls::TestCert;

#[derive(Debug, Default)]
struct MemClip {
    text: Mutex<Option<String>>,
    written: Mutex<Vec<String>>,
}

impl Clipboard for MemClip {
    fn read_text(&self) -> Option<String> {
        self.text.lock().expect("lock").clone()
    }
    fn write_text(&self, text: &str) -> bool {
        self.written.lock().expect("lock").push(text.to_owned());
        true
    }
}

struct Client {
    s: RdpSession,
    sink: FrameSink,
    clip: Arc<MemClip>,
    audit: AuditSink,
    dir: tempfile::TempDir,
}

const W: u16 = 320;
const H: u16 = 240;

fn server(cfg: RdpConfig) -> RdpHandle {
    rdp::start(RdpConfig { width: W, height: H, ..cfg }, 0).expect("rdp test server")
}

fn pin(dir: &tempfile::TempDir, port: u16, cert: &TestCert) {
    let mut k = KnownCerts::new();
    k.add("127.0.0.1", port, &fingerprint(cert.cert_der()), time::OffsetDateTime::now_utc());
    k.save(&dir.path().join("known_rdp_certs")).expect("save");
}

fn password(p: &str) -> ConnectSecret {
    ConnectSecret::Password(p.to_owned().into())
}

async fn connect(
    srv: &RdpHandle,
    secret: ConnectSecret,
    conn: RdpConnOptions,
    pinned: bool,
) -> Client {
    let dir = tempfile::tempdir().expect("tmp");
    if pinned {
        pin(&dir, srv.addr().port(), srv.cert());
    }
    let clip = Arc::new(MemClip::default());
    let mut o = RdpOptions::new(dir.path().join("known_rdp_certs"), conn)
        .with_clipboard(Arc::clone(&clip) as Arc<dyn Clipboard>);
    o.connect_timeout = Duration::from_secs(5);
    o.handshake_timeout = Duration::from_secs(20);
    o.keepalive = None;
    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port: srv.addr().port(),
        username: Some("alice".into()),
        secret,
        r#become: None,
        size: Size { width: u32::from(W), height: u32::from(H) },
    };
    let (sink, audit) = (FrameSink::new(), AuditSink::new());
    let s = RdpSession::connect(params, o, sink.clone(), audit.clone()).await.expect("starts");
    Client { s, sink, clip, audit, dir }
}

async fn next(s: &mut RdpSession) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(20), s.next_event())
        .await
        .expect("event in time")
        .expect("ok")
        .expect("an event")
}

async fn closed(s: &mut RdpSession) -> CloseCode {
    loop {
        if let SessionEvent::Closed { code, .. } = next(s).await {
            return code;
        }
    }
}

/// `Connected` then the first `DesktopResized`; returns the security label.
async fn up(s: &mut RdpSession) -> String {
    let ev = next(s).await;
    let SessionEvent::Connected { security, .. } = ev else { panic!("connected, got {ev:?}") };
    let ev = next(s).await;
    assert!(matches!(ev, SessionEvent::DesktopResized { .. }), "{ev:?}");
    security.expect("security label")
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn same_rgb(sink: &FrameSink, srv: &RdpHandle) -> bool {
    let fb = srv.framebuffer();
    let (w, h, px) = sink.snapshot();
    (w, h) == (fb.width, fb.height)
        && px.chunks_exact(4).zip(fb.rgba.chunks_exact(4)).all(|(a, b)| a[..3] == b[..3])
}

#[tokio::test]
async fn nla_tofu_yes_then_frames_input_and_clipboard() {
    let srv = server(RdpConfig::default());
    let conn = RdpConnOptions { clipboard: ClipboardPolicy::Both, ..RdpConnOptions::default() };
    let mut c = connect(&srv, password("correct horse"), conn, false).await;
    let SessionEvent::Prompt { id, purpose, certificate, .. } = next(&mut c.s).await else {
        panic!("certificate prompt")
    };
    assert_eq!(purpose, PromptPurpose::CertificateTrust);
    let info = certificate.expect("certificate info");
    assert!(info.is_self_signed());
    c.s.send(SessionInput::Answer { id, text: "yes".to_owned().into() }).await.expect("answer");
    let ev = next(&mut c.s).await;
    let SessionEvent::Connected { peer_identity: peer, security, .. } = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(security.as_deref(), Some("nla"));
    assert_eq!(peer, Some(peer_identity(&fingerprint(srv.cert().cert_der()))));
    assert!(matches!(
        next(&mut c.s).await,
        SessionEvent::DesktopResized { width: 320, height: 240 }
    ));
    // The pin file belongs to the Tauri layer: the session trusted the leaf in memory only.
    let known = KnownCerts::load(&c.dir.path().join("known_rdp_certs")).expect("load");
    assert!(!known.has_pin("127.0.0.1", srv.addr().port()));

    eventually("the first bitmap update", || same_rgb(&c.sink, &srv)).await;
    srv.fill(Rect::new(10, 10, 40, 20), [200, 10, 30, 255]);
    eventually("the fill", || same_rgb(&c.sink, &srv)).await;
    assert!(srv.stats().bitmap_updates >= 2);

    // Input echo counters on the server.
    c.s.send(SessionInput::Key { code: "KeyA".into(), key: "a".into(), pressed: true })
        .await
        .expect("key");
    c.s.send(SessionInput::Key { code: "KeyA".into(), key: "a".into(), pressed: false })
        .await
        .expect("key up");
    c.s.send(SessionInput::Pointer { x: 33, y: 44, buttons: 1 }).await.expect("pointer");
    c.s.send(SessionInput::Unicode { text: "é".into() }).await.expect("unicode");
    let key = |release| InputRecord::Key { code: 0x1e, extended: false, release };
    eventually("key and pointer", || {
        let i = srv.stats().inputs;
        i.contains(&key(false))
            && i.contains(&key(true))
            && i.iter().any(|r| matches!(r, InputRecord::Mouse { x: 33, y: 44, .. }))
            && i.iter().any(|r| matches!(r, InputRecord::Unicode { code: 0xe9, release: false }))
    })
    .await;

    // Clipboard text both ways.
    srv.set_clipboard("from the server");
    eventually("remote copy", || !c.clip.written.lock().expect("l").is_empty()).await;
    assert_eq!(c.clip.written.lock().expect("l").as_slice(), ["from the server".to_owned()]);
    *c.clip.text.lock().expect("l") = Some("from the client".into());
    c.s.send(SessionInput::ClipboardOffer).await.expect("offer");
    eventually("paste on the server", || {
        srv.stats().clipboard_from_client.contains(&"from the client".to_owned())
    })
    .await;

    // Display Control resize (debounced 300 ms).
    c.s.send(SessionInput::Resize { size: Size { width: 400, height: 300 } })
        .await
        .expect("resize");
    eventually("monitor layout", || srv.stats().layouts.contains(&(400, 300))).await;

    c.s.close().await.expect("close");
    assert_eq!(closed(&mut c.s).await, CloseCode::User);
    let actions: Vec<_> = c.audit.take().iter().map(SessionAudit::action).collect();
    assert!(actions.contains(&"session.auth.succeeded"), "{actions:?}");
    assert!(actions.contains(&"session.clipboard"), "{actions:?}");
    assert!(!actions.iter().any(|a| a.starts_with("trust.cert.")), "{actions:?}");
}

#[tokio::test]
async fn tofu_no_closes_with_trust_rejected() {
    let srv = server(RdpConfig::default());
    let mut c = connect(&srv, password("correct horse"), RdpConnOptions::default(), false).await;
    let SessionEvent::Prompt { id, .. } = next(&mut c.s).await else { panic!("prompt") };
    c.s.send(SessionInput::Answer { id, text: "no".to_owned().into() }).await.expect("answer");
    assert_eq!(closed(&mut c.s).await, CloseCode::TrustRejected);
    assert_eq!(srv.stats().accepted, 0);
}

#[tokio::test]
async fn changed_certificate_is_a_hard_stop() {
    let srv = server(RdpConfig::default());
    let dir = tempfile::tempdir().expect("tmp");
    let other = TestCert::generate(&[]).expect("cert");
    pin(&dir, srv.addr().port(), &other);
    let mut o = RdpOptions::new(dir.path().join("known_rdp_certs"), RdpConnOptions::default());
    o.connect_timeout = Duration::from_secs(5);
    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port: srv.addr().port(),
        username: Some("alice".into()),
        secret: password("correct horse"),
        r#become: None,
        size: Size { width: 320, height: 240 },
    };
    let audit = AuditSink::new();
    let mut s =
        RdpSession::connect(params, o, FrameSink::new(), audit.clone()).await.expect("starts");
    let SessionEvent::Closed { code, reason } = next(&mut s).await else { panic!("closed") };
    assert_eq!(code, CloseCode::TrustMismatch);
    assert!(reason.starts_with("CERTIFICATE CHANGED"), "{reason}");
    assert!(audit.take().iter().any(|a| matches!(a, SessionAudit::CertMismatch { .. })));
}

#[tokio::test]
async fn wrong_password_is_auth_failed() {
    let srv = server(RdpConfig::default());
    let mut c = connect(&srv, password("wrong"), RdpConnOptions::default(), true).await;
    assert_eq!(closed(&mut c.s).await, CloseCode::AuthFailed);
    assert!(c.audit.take().contains(&SessionAudit::AuthFailed));
}

#[tokio::test]
async fn tls_only_needs_the_option_and_is_audited() {
    let srv = server(RdpConfig { security: RdpSecurity::Tls, ..RdpConfig::default() });
    let mut refused =
        connect(&srv, password("correct horse"), RdpConnOptions::default(), true).await;
    // The test acceptor drops the TCP connection instead of sending RDP_NEG_FAILURE, so the
    // client sees the connection end during negotiation; it never reaches TLS-only.
    let code = closed(&mut refused.s).await;
    assert!(matches!(code, CloseCode::ProtocolError | CloseCode::Network), "{code:?}");
    eventually("negotiation refused on the server", || {
        srv.stats().errors.iter().any(|e| e.starts_with("negotiation"))
    })
    .await;
    assert_eq!(srv.stats().accepted, 0);

    let conn = RdpConnOptions { allow_tls_without_nla: true, ..RdpConnOptions::default() };
    let mut c = connect(&srv, password("correct horse"), conn, true).await;
    assert_eq!(up(&mut c.s).await, "tls");
    eventually("bitmap over TLS-only", || same_rgb(&c.sink, &srv)).await;
    assert!(c.audit.take().contains(&SessionAudit::RdpLegacySecurity));
}

#[tokio::test]
async fn planar_bitmaps_reach_the_sink() {
    let srv = server(RdpConfig { bitmap: BitmapMode::Planar, ..RdpConfig::default() });
    let mut c = connect(&srv, password("correct horse"), RdpConnOptions::default(), true).await;
    assert_eq!(up(&mut c.s).await, "nla");
    eventually("planar frame", || same_rgb(&c.sink, &srv)).await;
    assert!(srv.stats().planar_tiles > 0);
}

#[tokio::test]
async fn out_of_bounds_tiles_do_not_break_the_session() {
    let knobs = rdp::RdpKnobs { out_of_bounds_bitmap: Some(16), ..rdp::RdpKnobs::default() };
    let srv = server(RdpConfig { knobs, ..RdpConfig::default() });
    let mut c = connect(&srv, password("correct horse"), RdpConnOptions::default(), true).await;
    assert_eq!(up(&mut c.s).await, "nla");
    // Either clipped into the sink or refused as a protocol error; never a panic or a hang.
    let ev = tokio::time::timeout(Duration::from_secs(2), c.s.next_event()).await;
    if let Ok(Ok(Some(SessionEvent::Closed { code, .. }))) = ev {
        assert_eq!(code, CloseCode::ProtocolError);
    }
}
