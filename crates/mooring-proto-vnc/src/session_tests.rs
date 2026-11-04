//! Loopback end-to-end tests against QA's real RFB 3.8 server (`mooring_testsrv::rfb`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mooring_core::audit::{AuthMethod, ClipboardDirection};
use mooring_core::frame::FrameSink;
use mooring_core::known_certs::{fingerprint, peer_identity, KnownCerts};
use mooring_core::options::{ClipboardPolicy, VncConnOptions, VncSecurity};
use mooring_core::session::{
    CloseCode, ConnectParams, ConnectSecret, PromptPurpose, SessionEvent, SessionInput, Size,
};
use mooring_core::{Session, SessionAudit};
use mooring_testsrv::rfb::{
    self, encoding, Knobs, Rect, RfbConfig, RfbHandle, SecurityOffer as Sec, TightMode,
    VeNCryptSub as Sub, ZrleMode,
};
use mooring_testsrv::tls::TestCert;
use secrecy::SecretString;

use crate::{AuditLog, Clipboard, VncOptions, VncSession};

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
    s: VncSession,
    sink: FrameSink,
    clip: Arc<MemClip>,
    dir: tempfile::TempDir,
}

fn params(port: u16, secret: ConnectSecret) -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".into(),
        port,
        username: None,
        secret,
        r#become: None,
        size: Size { width: 800, height: 600 },
    }
}

fn pw(p: &str) -> ConnectSecret {
    ConnectSecret::Password(SecretString::from(p.to_owned()))
}

async fn server(cfg: RfbConfig) -> RfbHandle {
    rfb::start(cfg, 0).await.expect("rfb test server")
}

fn small(security: Vec<Sec>) -> RfbConfig {
    RfbConfig { width: 64, height: 48, security, ..RfbConfig::default() }
}

fn pin(dir: &tempfile::TempDir, port: u16, cert: &TestCert) {
    let mut k = KnownCerts::new();
    k.add("127.0.0.1", port, &fingerprint(cert.cert_der()), time::OffsetDateTime::now_utc());
    k.save(&dir.path().join("known_vnc_certs")).expect("save");
}

async fn client_with(
    port: u16,
    secret: ConnectSecret,
    conn: VncConnOptions,
    dir: Option<tempfile::TempDir>,
    trusted_once: Option<[u8; 32]>,
) -> Client {
    let dir = dir.unwrap_or_else(|| tempfile::tempdir().expect("tmp"));
    let clip = Arc::new(MemClip::default());
    let mut o = VncOptions::new(dir.path().join("known_vnc_certs"), conn);
    o.clipboard = Arc::clone(&clip) as Arc<dyn Clipboard>;
    o.handshake_timeout = Duration::from_secs(5);
    o.trusted_once = trusted_once;
    let sink = FrameSink::new();
    let s = VncSession::connect(params(port, secret), o, sink.clone(), AuditLog::default())
        .await
        .expect("connect");
    Client { s, sink, clip, dir }
}

async fn client(port: u16, secret: ConnectSecret, conn: VncConnOptions) -> Client {
    client_with(port, secret, conn, None, None).await
}

async fn next(s: &mut VncSession) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(10), s.next_event())
        .await
        .expect("event in time")
        .expect("ok")
        .expect("some")
}

async fn closed(s: &mut VncSession) -> CloseCode {
    loop {
        if let SessionEvent::Closed { code, .. } = next(s).await {
            return code;
        }
    }
}

async fn connected(s: &mut VncSession) -> (Option<String>, Option<String>) {
    match next(s).await {
        SessionEvent::Connected { peer_identity, security, .. } => (peer_identity, security),
        other => panic!("{other:?}"),
    }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..250 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn same_pixels(sink: &FrameSink, srv: &RfbHandle) -> bool {
    let fb = srv.framebuffer();
    let (w, h, px) = sink.snapshot();
    (w, h) == (fb.width, fb.height) && px == fb.rgba
}

#[tokio::test]
async fn none_auth_frames_clipboard_and_input() {
    let srv = server(small(vec![Sec::None])).await;
    let conn = VncConnOptions { clipboard: ClipboardPolicy::Both, ..Default::default() };
    let mut c = client(srv.addr().port(), ConnectSecret::None, conn).await;
    assert_eq!(connected(&mut c.s).await, (None, Some("none".into())));
    assert!(matches!(next(&mut c.s).await, SessionEvent::DesktopResized { width: 64, height: 48 }));
    eventually("the first full frame", || same_pixels(&c.sink, &srv)).await;

    // An incremental update after a server-side change.
    srv.fill(Rect::new(3, 4, 10, 5), [9, 8, 7, 255]);
    eventually("the fill", || same_pixels(&c.sink, &srv)).await;

    srv.server_cut_text(b"h\xe9y");
    eventually("remote cut text", || c.clip.written.lock().expect("l").len() == 1).await;
    assert_eq!(c.clip.written.lock().expect("l").as_slice(), &["h\u{e9}y".to_owned()]);

    let key = |pressed| SessionInput::Key { code: "KeyA".into(), key: "a".into(), pressed };
    c.s.send(key(true)).await.expect("key");
    c.s.send(SessionInput::Pointer { x: 50, y: 1, buttons: 1 }).await.expect("ptr");
    c.s.send(SessionInput::Pointer { x: 5000, y: 1, buttons: 0 }).await.expect("ptr clamp");
    c.s.send(SessionInput::Wheel { dx: 0, dy: 120 }).await.expect("wheel");
    c.s.send(SessionInput::ReleaseAll).await.expect("release");
    *c.clip.text.lock().expect("l") = Some("ok".into());
    c.s.send(SessionInput::ClipboardOffer).await.expect("offer");
    eventually("client cut text", || srv.stats().client_cut_text.contains(&b"ok".to_vec())).await;
    let st = srv.stats();
    let a = st.key_events.iter().find(|k| k.keysym == 0x61).expect("KeyA reached the server");
    assert!(a.down);
    assert_eq!(a.qemu_keycode, Some(0x1e), "QEMU extended key once the server confirmed it");
    assert!(st.key_events.iter().any(|k| k.keysym == 0x61 && !k.down), "release all");
    assert!(st.pointer_events >= 4, "pointer + wheel press/release");
    assert_eq!(st.last_pointer.map(|p| p.1), Some(63), "pointer clamped to the framebuffer");
    assert!(c.s.send(SessionInput::Bytes { data: vec![1] }).await.is_err());

    c.s.close().await.expect("close");
    assert_eq!(closed(&mut c.s).await, CloseCode::User);
    let audit = c.s.take_audit_events();
    assert!(audit.contains(&SessionAudit::AuthSucceeded { method: AuthMethod::None }));
    assert!(audit.contains(&SessionAudit::VncPlaintext { security: "none" }));
    assert!(audit.iter().any(|a| matches!(
        a,
        SessionAudit::Clipboard { direction: ClipboardDirection::FromRemote, bytes: 4 }
    )));
    assert!(audit.iter().any(|a| matches!(
        a,
        SessionAudit::Clipboard { direction: ClipboardDirection::ToRemote, .. }
    )));
}

#[tokio::test]
async fn every_encoder_path_reaches_the_sink() {
    let force = |e| Knobs { force_encoding: Some(e), ..Knobs::default() };
    for (name, cfg) in [
        ("raw", RfbConfig { knobs: force(encoding::RAW), ..small(vec![Sec::None]) }),
        ("zrle auto", RfbConfig { knobs: force(encoding::ZRLE), ..small(vec![Sec::None]) }),
        (
            "zrle raw tiles",
            RfbConfig {
                zrle_mode: ZrleMode::Raw,
                knobs: force(encoding::ZRLE),
                ..small(vec![Sec::None])
            },
        ),
        (
            "zrle plain rle",
            RfbConfig {
                zrle_mode: ZrleMode::PlainRle,
                knobs: force(encoding::ZRLE),
                ..small(vec![Sec::None])
            },
        ),
        ("tight auto", RfbConfig { knobs: force(encoding::TIGHT), ..small(vec![Sec::None]) }),
        (
            "tight copy",
            RfbConfig {
                tight_mode: TightMode::Copy,
                knobs: force(encoding::TIGHT),
                ..small(vec![Sec::None])
            },
        ),
        (
            "tight palette",
            RfbConfig {
                tight_mode: TightMode::Palette,
                knobs: force(encoding::TIGHT),
                ..small(vec![Sec::None])
            },
        ),
        (
            "tight gradient",
            RfbConfig {
                tight_mode: TightMode::Gradient,
                knobs: force(encoding::TIGHT),
                ..small(vec![Sec::None])
            },
        ),
        (
            "last rect",
            RfbConfig {
                knobs: Knobs { use_last_rect: true, ..Knobs::default() },
                ..small(vec![Sec::None])
            },
        ),
    ] {
        let srv = server(cfg).await;
        let mut c = client(srv.addr().port(), ConnectSecret::None, VncConnOptions::default()).await;
        connected(&mut c.s).await;
        eventually(name, || same_pixels(&c.sink, &srv)).await;
        srv.copy(Rect::new(0, 0, 16, 16), 20, 20);
        eventually(name, || same_pixels(&c.sink, &srv)).await;
        assert!(srv.stats().errors.is_empty(), "{name}: {:?}", srv.stats().errors);
    }
}

#[tokio::test]
async fn vnc_auth_good_bad_and_missing_password() {
    let srv =
        server(RfbConfig { password: Some("secret".into()), ..small(vec![Sec::VncAuth]) }).await;
    let port = srv.addr().port();
    let mut ok = client(port, pw("secret"), VncConnOptions::default()).await;
    assert_eq!(connected(&mut ok.s).await.1.as_deref(), Some("vnc-auth"));
    assert!(ok
        .s
        .take_audit_events()
        .contains(&SessionAudit::VncPlaintext { security: "vnc-auth" }));

    let mut bad = client(port, pw("wrong"), VncConnOptions::default()).await;
    assert_eq!(closed(&mut bad.s).await, CloseCode::AuthFailed);
    assert!(bad.s.take_audit_events().contains(&SessionAudit::AuthFailed));

    let mut none = client(port, ConnectSecret::None, VncConnOptions::default()).await;
    assert_eq!(closed(&mut none.s).await, CloseCode::AuthFailed, "server needs a password");
}

#[tokio::test]
async fn require_tls_refuses_plaintext_servers() {
    let srv = server(small(vec![Sec::None, Sec::VncAuth])).await;
    let conn = VncConnOptions { security: VncSecurity::RequireTls, ..Default::default() };
    let mut c = client(srv.addr().port(), pw("x"), conn).await;
    assert_eq!(closed(&mut c.s).await, CloseCode::ProtocolError);
}

#[tokio::test]
async fn vencrypt_tofu_yes_reconnects_then_strip_and_mismatch_stop() {
    let cert = TestCert::generate(&["127.0.0.1"]).expect("cert");
    let tls = |cert: &TestCert| RfbConfig {
        cert: Some(cert.clone()),
        password: Some("pw".into()),
        ..small(vec![Sec::VeNCrypt(vec![Sub::X509Vnc]), Sec::VncAuth])
    };
    let srv = server(tls(&cert)).await;
    let port = srv.addr().port();
    let mut c = client(port, pw("pw"), VncConnOptions::default()).await;
    let SessionEvent::Prompt { id, purpose, certificate, .. } = next(&mut c.s).await else {
        panic!("prompt")
    };
    assert_eq!(purpose, PromptPurpose::CertificateTrust);
    assert!(certificate.expect("certificate info").is_self_signed());
    c.s.send(SessionInput::Answer { id, text: SecretString::from("yes".to_owned()) })
        .await
        .expect("answer");
    let (peer, security) = connected(&mut c.s).await;
    assert_eq!(security.as_deref(), Some("vencrypt-x509"));
    assert_eq!(peer, Some(peer_identity(&fingerprint(cert.cert_der()))));
    assert_eq!(srv.stats().connections, 2, "reconnected after yes");
    let audit = c.s.take_audit_events();
    assert!(!audit.iter().any(|a| matches!(a, SessionAudit::CertAdded { .. })), "R2 audits");
    assert!(audit.contains(&SessionAudit::AuthSucceeded { method: AuthMethod::VncAuth }));
    let known = KnownCerts::load(&c.dir.path().join("known_vnc_certs")).expect("load");
    assert!(!known.has_pin("127.0.0.1", port), "the session never writes pins");
    drop(c);

    // A MITM strips VeNCrypt from the next connection to a pinned host: hard stop.
    srv.set_knobs(Knobs { strip_tls_after: Some(srv.stats().connections), ..Knobs::default() });
    let dir = tempfile::tempdir().expect("tmp");
    pin(&dir, port, &cert);
    let conn = VncConnOptions { security: VncSecurity::AllowPlaintext, ..Default::default() };
    let mut s = client_with(port, pw("pw"), conn, Some(dir), None).await;
    assert_eq!(closed(&mut s.s).await, CloseCode::TrustMismatch);
    assert!(s
        .s
        .take_audit_events()
        .iter()
        .any(|a| matches!(a, SessionAudit::CertMismatch { presented, .. } if presented == "none")));

    // A different certificate on a pinned port: hard stop.
    let other = server(tls(&TestCert::generate(&["127.0.0.1"]).expect("cert"))).await;
    let dir = tempfile::tempdir().expect("tmp");
    pin(&dir, other.addr().port(), &cert);
    let mut m =
        client_with(other.addr().port(), pw("pw"), VncConnOptions::default(), Some(dir), None)
            .await;
    assert_eq!(closed(&mut m.s).await, CloseCode::TrustMismatch);
    assert!(m.s.take_audit_events().iter().any(|a| matches!(a, SessionAudit::CertMismatch { .. })));
}

#[tokio::test]
async fn trusted_once_connects_without_a_prompt_or_a_pin_write() {
    let srv = server(small(vec![Sec::VeNCrypt(vec![Sub::X509None])])).await;
    let fp = fingerprint(srv.cert().expect("cert").cert_der());
    let port = srv.addr().port();
    let mut c =
        client_with(port, ConnectSecret::None, VncConnOptions::default(), None, Some(fp)).await;
    assert_eq!(connected(&mut c.s).await.1.as_deref(), Some("vencrypt-x509"));
    let known = KnownCerts::load(&c.dir.path().join("known_vnc_certs")).expect("load");
    assert!(!known.has_pin("127.0.0.1", port));
}

#[tokio::test]
async fn tofu_no_rejects_and_anonymous_tls_falls_back() {
    let srv = server(small(vec![Sec::VeNCrypt(vec![Sub::X509None])])).await;
    let mut c = client(srv.addr().port(), ConnectSecret::None, VncConnOptions::default()).await;
    let SessionEvent::Prompt { id, .. } = next(&mut c.s).await else { panic!("prompt") };
    c.s.send(SessionInput::Answer { id, text: SecretString::from("no".to_owned()) })
        .await
        .expect("answer");
    assert_eq!(closed(&mut c.s).await, CloseCode::TrustRejected);
    assert!(!c
        .s
        .take_audit_events()
        .iter()
        .any(|a| matches!(a, SessionAudit::CertRejected { .. })));

    // VeNCrypt with anonymous-TLS subtypes only: one retry without VeNCrypt.
    let anon = server(RfbConfig {
        password: Some("pw".into()),
        ..small(vec![Sec::VeNCrypt(vec![Sub::TlsNone, Sub::TlsVnc]), Sec::VncAuth])
    })
    .await;
    let mut f = client(anon.addr().port(), pw("pw"), VncConnOptions::default()).await;
    assert_eq!(connected(&mut f.s).await.1.as_deref(), Some("vnc-auth"));
    assert_eq!(anon.stats().connections, 2);
}

#[tokio::test]
async fn view_only_drops_input_but_releases_keys() {
    let srv = server(small(vec![Sec::None])).await;
    let conn =
        VncConnOptions { view_only: true, clipboard: ClipboardPolicy::Both, ..Default::default() };
    let mut c = client(srv.addr().port(), ConnectSecret::None, conn).await;
    connected(&mut c.s).await;
    let ctl = c.s.control();
    assert!(ctl.view_only());
    c.s.send(SessionInput::Key { code: "KeyA".into(), key: "a".into(), pressed: true })
        .await
        .expect("k");
    c.s.send(SessionInput::Pointer { x: 1, y: 1, buttons: 1 }).await.expect("p");
    c.s.send(SessionInput::ClipboardOffer).await.expect("c");
    c.s.send(SessionInput::ReleaseAll).await.expect("r");
    ctl.set_view_only(false);
    c.s.send(SessionInput::Key { code: "Enter".into(), key: "Enter".into(), pressed: true })
        .await
        .expect("k");
    eventually("Enter", || srv.stats().key_events.iter().any(|k| k.keysym == 0xff0d)).await;
    let st = srv.stats();
    assert!(!st.key_events.iter().any(|k| k.keysym == 0x61), "view-only key never sent");
    assert_eq!(st.pointer_events, 0, "no pointer event");
    assert!(st.client_cut_text.is_empty());
    assert_eq!(ctl.dropped_inputs(), 3);
}

#[tokio::test]
async fn hostile_updates_close_with_protocol_error() {
    for (name, knobs) in [
        ("oversized rect", Knobs { oversized_rect: Some(4), ..Knobs::default() }),
        (
            "tight jpeg",
            Knobs { tight_jpeg: true, force_encoding: Some(encoding::TIGHT), ..Knobs::default() },
        ),
        (
            "zlib length lie",
            Knobs {
                lie_zlib_length: Some(u32::MAX),
                force_encoding: Some(encoding::ZRLE),
                ..Knobs::default()
            },
        ),
    ] {
        let srv = server(RfbConfig { knobs, ..small(vec![Sec::None]) }).await;
        let mut c = client(srv.addr().port(), ConnectSecret::None, VncConnOptions::default()).await;
        assert_eq!(closed(&mut c.s).await, CloseCode::ProtocolError, "{name}");
    }
}

#[tokio::test]
async fn desktop_resize_both_ways() {
    let srv = server(small(vec![Sec::None])).await;
    let mut c = client(srv.addr().port(), ConnectSecret::None, VncConnOptions::default()).await;
    connected(&mut c.s).await;
    assert!(matches!(next(&mut c.s).await, SessionEvent::DesktopResized { width: 64, height: 48 }));
    eventually("first frame", || same_pixels(&c.sink, &srv)).await;
    srv.resize(80, 60);
    assert!(matches!(next(&mut c.s).await, SessionEvent::DesktopResized { width: 80, height: 60 }));
    eventually("the resized frame", || same_pixels(&c.sink, &srv)).await;
    c.s.send(SessionInput::Resize { size: Size { width: 320, height: 240 } })
        .await
        .expect("resize");
    eventually("SetDesktopSize", || srv.stats().desktop_size_requests.contains(&(320, 240))).await;
}

#[tokio::test]
async fn pinned_x509_plain_with_username() {
    let cert = TestCert::generate(&["127.0.0.1"]).expect("cert");
    let srv = server(RfbConfig {
        cert: Some(cert.clone()),
        plain_user: Some(("alice".into(), "pw".into())),
        ..small(vec![Sec::VeNCrypt(vec![Sub::X509Vnc, Sub::X509Plain])])
    })
    .await;
    let dir = tempfile::tempdir().expect("tmp");
    pin(&dir, srv.addr().port(), &cert);
    let secret = ConnectSecret::DomainPassword {
        user: "alice".into(),
        domain: String::new(),
        password: SecretString::from("pw".to_owned()),
    };
    let mut c =
        client_with(srv.addr().port(), secret, VncConnOptions::default(), Some(dir), None).await;
    assert_eq!(connected(&mut c.s).await.1.as_deref(), Some("vencrypt-x509"));
    let audit = c.s.take_audit_events();
    assert!(audit.contains(&SessionAudit::AuthSucceeded { method: AuthMethod::VncPlain }));
    assert!(!audit.iter().any(|a| matches!(a, SessionAudit::CertCaValid { .. })));
    assert_eq!(srv.stats().chosen_security.last(), Some(&(19, Some(262))));
}

#[tokio::test]
async fn bad_inputs_are_refused_at_connect() {
    let o = VncOptions::new("/nonexistent/known_vnc_certs", VncConnOptions::default());
    let mut p = params(0, ConnectSecret::None);
    assert!(VncSession::connect(p, o.clone(), FrameSink::new(), AuditLog::default())
        .await
        .is_err());
    p = params(5900, ConnectSecret::Agent { fingerprint: None });
    assert!(VncSession::connect(p, o.clone(), FrameSink::new(), AuditLog::default())
        .await
        .is_err());
    p = params(5900, ConnectSecret::None);
    p.host = "bad host".into();
    assert!(VncSession::connect(p, o, FrameSink::new(), AuditLog::default()).await.is_err());
}
