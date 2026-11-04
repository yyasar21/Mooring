//! Loopback end-to-end tests against the in-test RFB server (`testsrv`).

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
use secrecy::SecretString;

use crate::messages::enc;
use crate::testsrv::{cert, rect, start, update, SrvConfig};
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
    _dir: tempfile::TempDir,
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

async fn client(
    port: u16,
    secret: ConnectSecret,
    conn: VncConnOptions,
    dir: Option<tempfile::TempDir>,
) -> Client {
    let dir = dir.unwrap_or_else(|| tempfile::tempdir().expect("tmp"));
    let clip = Arc::new(MemClip::default());
    let mut o = VncOptions::new(dir.path().join("known_vnc_certs"), conn);
    o.clipboard = Arc::clone(&clip) as Arc<dyn Clipboard>;
    o.handshake_timeout = Duration::from_secs(5);
    let sink = FrameSink::new();
    let s = VncSession::connect(params(port, secret), o, sink.clone(), AuditLog::default())
        .await
        .expect("connect");
    Client { s, sink, clip, _dir: dir }
}

async fn next(s: &mut VncSession) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(5), s.next_event())
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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn zrle_solid(rgb: [u8; 3]) -> Vec<u8> {
    use flate2::{Compress, Compression, FlushCompress};
    let mut c = Compress::new(Compression::default(), true);
    let mut z = Vec::with_capacity(64);
    c.compress_vec(&[1, rgb[0], rgb[1], rgb[2]], &mut z, FlushCompress::Sync).expect("z");
    let mut p = u32::try_from(z.len()).expect("len").to_be_bytes().to_vec();
    p.extend_from_slice(&z);
    p
}

#[tokio::test]
async fn none_auth_frames_clipboard_and_input() {
    let mut script = update(4);
    script.extend(rect(0, 0, 1, 1, enc::RAW, &[10, 20, 30, 0]));
    script.extend(rect(1, 0, 1, 1, enc::TIGHT, &[0x80, 1, 2, 3]));
    script.extend(rect(0, 1, 2, 1, enc::ZRLE, &zrle_solid([7, 8, 9])));
    script.extend(rect(0, 0, 0, 0, enc::QEMU_EXT_KEY, &[]));
    script.extend([2]); // Bell
    script.extend([3, 0, 0, 0, 0, 0, 0, 3, b'h', 0xe9, b'y']);
    let mut srv = start(SrvConfig {
        security: vec![1],
        fb: (2, 2),
        script: vec![script],
        ..Default::default()
    })
    .await;
    let mut c = client(srv.addr.port(), ConnectSecret::None, VncConnOptions::default(), None).await;
    assert_eq!(connected(&mut c.s).await, (None, Some("none".into())));
    assert!(matches!(next(&mut c.s).await, SessionEvent::DesktopResized { width: 2, height: 2 }));

    // The update and the next incremental request.
    let mut got = Vec::new();
    assert!(srv.until(&mut got, |b| contains(b, &[3, 1, 0, 0, 0, 0, 0, 2, 0, 2])).await);
    let (_, _, px) = c.sink.snapshot();
    assert_eq!(&px[0..8], &[10, 20, 30, 255, 1, 2, 3, 255]);
    assert_eq!(&px[8..16], &[7, 8, 9, 255, 7, 8, 9, 255]);
    assert_eq!(c.clip.written.lock().expect("l").as_slice(), &["h\u{e9}y".to_owned()]);

    // Input: QEMU extended keys after the server confirmed them; pointer; wheel.
    let key = |pressed| SessionInput::Key { code: "KeyA".into(), key: "a".into(), pressed };
    c.s.send(key(true)).await.expect("key");
    c.s.send(SessionInput::Pointer { x: 50, y: 1, buttons: 1 }).await.expect("ptr");
    c.s.send(SessionInput::Wheel { dx: 0, dy: 120 }).await.expect("wheel");
    c.s.send(SessionInput::ReleaseAll).await.expect("release");
    *c.clip.text.lock().expect("l") = Some("ok".into());
    c.s.send(SessionInput::ClipboardOffer).await.expect("offer");
    assert!(
        srv.until(&mut got, |b| contains(b, &[6, 0, 0, 0, 0, 0, 0, 2, b'o', b'k'])).await,
        "{got:?}"
    );
    assert!(contains(&got, &[255, 0, 0, 1, 0, 0, 0, 0x61, 0, 0, 0, 0x1e]), "qemu key down");
    assert!(contains(&got, &[255, 0, 0, 0, 0, 0, 0, 0x61, 0, 0, 0, 0x1e]), "release all");
    assert!(contains(&got, &[5, 1, 0, 1, 0, 1]), "pointer clamped to the framebuffer");
    assert!(contains(&got, &[5, 0x11, 0, 1, 0, 1]) && contains(&got, &[5, 1, 0, 1, 0, 1]), "wheel");
    assert!(contains(&got, &[5, 0, 0, 1, 0, 1]), "buttons released");
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
async fn vnc_auth_good_and_bad_password() {
    let cfg = SrvConfig {
        security: vec![2],
        password: Some(b"secret".to_vec()),
        fb: (4, 4),
        ..Default::default()
    };
    let srv = start(cfg).await;
    let mut ok = client(srv.addr.port(), pw("secret"), VncConnOptions::default(), None).await;
    assert_eq!(connected(&mut ok.s).await.1.as_deref(), Some("vnc-auth"));
    assert!(ok
        .s
        .take_audit_events()
        .contains(&SessionAudit::VncPlaintext { security: "vnc-auth" }));

    let mut bad = client(srv.addr.port(), pw("wrong"), VncConnOptions::default(), None).await;
    assert_eq!(closed(&mut bad.s).await, CloseCode::AuthFailed);
    assert!(bad.s.take_audit_events().contains(&SessionAudit::AuthFailed));

    let mut none =
        client(srv.addr.port(), ConnectSecret::None, VncConnOptions::default(), None).await;
    assert_eq!(closed(&mut none.s).await, CloseCode::AuthFailed, "server needs a password");
}

#[tokio::test]
async fn require_tls_refuses_plaintext_servers() {
    let srv = start(SrvConfig { security: vec![1, 2], fb: (4, 4), ..Default::default() }).await;
    let conn = VncConnOptions { security: VncSecurity::RequireTls, ..Default::default() };
    let mut c = client(srv.addr.port(), pw("x"), conn, None).await;
    assert_eq!(closed(&mut c.s).await, CloseCode::ProtocolError);
}

#[tokio::test]
async fn vencrypt_tofu_pin_then_strip_and_mismatch() {
    let (der, key) = cert("127.0.0.1");
    let tls_cfg = SrvConfig {
        security: vec![19, 2],
        subtypes: vec![260, 261],
        tls: Some((der.clone(), key)),
        password: Some(b"pw".to_vec()),
        fb: (4, 4),
        ..Default::default()
    };
    let mut srv = start(tls_cfg.clone()).await;
    let dir = tempfile::tempdir().expect("tmp");
    let pin_path = dir.path().join("known_vnc_certs");
    let mut c = client(srv.addr.port(), pw("pw"), VncConnOptions::default(), Some(dir)).await;
    let SessionEvent::Prompt { id, purpose, certificate, .. } = next(&mut c.s).await else {
        panic!()
    };
    assert_eq!(purpose, PromptPurpose::CertificateTrust);
    let info = certificate.expect("certificate info");
    assert!(info.is_self_signed());
    c.s.send(SessionInput::Answer { id, text: SecretString::from("yes".to_owned()) })
        .await
        .expect("answer");
    let (peer, security) = connected(&mut c.s).await;
    assert_eq!(security.as_deref(), Some("vencrypt-x509"));
    assert_eq!(peer, Some(peer_identity(&fingerprint(&der))));
    assert_eq!(srv.conns.load(std::sync::atomic::Ordering::SeqCst), 2, "reconnected after yes");
    let audit = c.s.take_audit_events();
    // The pin file and the decision audit belong to the Tauri layer (R2 contract).
    assert!(!audit.iter().any(|a| matches!(a, SessionAudit::CertAdded { .. })));
    assert!(audit.contains(&SessionAudit::AuthSucceeded { method: AuthMethod::VncAuth }));
    assert!(!audit.iter().any(|a| matches!(a, SessionAudit::VncPlaintext { .. })));
    let known = KnownCerts::load(&pin_path).expect("load");
    assert!(!known.has_pin("127.0.0.1", srv.addr.port()), "the session never writes pins");
    let _ = srv.rx.try_recv();
    drop(c);

    // Same port, but now a server that strips VeNCrypt: hard stop (downgrade guard).
    let stripped = start(SrvConfig { security: vec![2], fb: (4, 4), ..Default::default() }).await;
    let dir2 = tempfile::tempdir().expect("tmp");
    let mut k = KnownCerts::new();
    k.add("127.0.0.1", stripped.addr.port(), &fingerprint(&der), time::OffsetDateTime::now_utc());
    k.save(&dir2.path().join("known_vnc_certs")).expect("save");
    let conn = VncConnOptions { security: VncSecurity::AllowPlaintext, ..Default::default() };
    let mut s = client(stripped.addr.port(), pw("pw"), conn, Some(dir2)).await;
    assert_eq!(closed(&mut s.s).await, CloseCode::TrustMismatch);
    assert!(s
        .s
        .take_audit_events()
        .iter()
        .any(|a| matches!(a, SessionAudit::CertMismatch { presented, .. } if presented == "none")));

    // A different certificate on a pinned port: hard stop.
    let (other_der, other_key) = cert("127.0.0.1");
    let other = start(SrvConfig { tls: Some((other_der, other_key)), ..tls_cfg }).await;
    let dir3 = tempfile::tempdir().expect("tmp");
    let mut k = KnownCerts::new();
    k.add("127.0.0.1", other.addr.port(), &fingerprint(&der), time::OffsetDateTime::now_utc());
    k.save(&dir3.path().join("known_vnc_certs")).expect("save");
    let mut m = client(other.addr.port(), pw("pw"), VncConnOptions::default(), Some(dir3)).await;
    assert_eq!(closed(&mut m.s).await, CloseCode::TrustMismatch);
}

#[tokio::test]
async fn trusted_once_connects_without_a_prompt_or_a_pin_write() {
    let (der, key) = cert("127.0.0.1");
    let srv = start(SrvConfig {
        security: vec![19],
        subtypes: vec![260],
        tls: Some((der.clone(), key)),
        fb: (4, 4),
        ..Default::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("known_vnc_certs");
    let mut o = VncOptions::new(&path, VncConnOptions::default());
    o.trusted_once = Some(fingerprint(&der));
    o.handshake_timeout = Duration::from_secs(5);
    let mut s = VncSession::connect(
        params(srv.addr.port(), ConnectSecret::None),
        o,
        FrameSink::new(),
        AuditLog::default(),
    )
    .await
    .expect("connect");
    assert_eq!(connected(&mut s).await.1.as_deref(), Some("vencrypt-x509"));
    assert!(!KnownCerts::load(&path).expect("load").has_pin("127.0.0.1", srv.addr.port()));
}

#[tokio::test]
async fn tofu_no_rejects_and_anonymous_tls_falls_back() {
    let (der, key) = cert("127.0.0.1");
    let srv = start(SrvConfig {
        security: vec![19],
        subtypes: vec![260],
        tls: Some((der, key)),
        fb: (4, 4),
        ..Default::default()
    })
    .await;
    let mut c = client(srv.addr.port(), ConnectSecret::None, VncConnOptions::default(), None).await;
    let SessionEvent::Prompt { id, .. } = next(&mut c.s).await else { panic!() };
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
    let anon = start(SrvConfig {
        security: vec![19, 2],
        subtypes: vec![257, 258],
        password: Some(b"pw".to_vec()),
        fb: (4, 4),
        ..Default::default()
    })
    .await;
    let mut f = client(anon.addr.port(), pw("pw"), VncConnOptions::default(), None).await;
    assert_eq!(connected(&mut f.s).await.1.as_deref(), Some("vnc-auth"));
    assert_eq!(anon.conns.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn view_only_drops_input_but_releases_keys() {
    let mut srv = start(SrvConfig { security: vec![1], fb: (4, 4), ..Default::default() }).await;
    let conn =
        VncConnOptions { view_only: true, clipboard: ClipboardPolicy::Both, ..Default::default() };
    let mut c = client(srv.addr.port(), ConnectSecret::None, conn, None).await;
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
    let mut got = Vec::new();
    assert!(srv.until(&mut got, |b| contains(b, &[4, 1, 0, 0, 0, 0, 0xff, 0x0d])).await);
    assert!(!contains(&got, &[4, 1, 0, 0, 0, 0, 0, 0x61]), "view-only key never sent");
    assert!(!got.contains(&5), "no pointer event");
    assert_eq!(ctl.dropped_inputs(), 3);
}

#[tokio::test]
async fn hostile_updates_close_with_protocol_error() {
    for script in [
        [update(1), rect(3, 3, 2, 2, enc::RAW, &[0; 16])].concat(),
        [update(1), rect(0, 0, 2, 2, enc::TIGHT, &[0x90, 1, 2])].concat(),
        [update(1), rect(0, 0, 1, 1, 5, &[])].concat(),
        vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        vec![99],
    ] {
        let srv = start(SrvConfig {
            security: vec![1],
            fb: (4, 4),
            script: vec![script],
            ..Default::default()
        })
        .await;
        let mut c =
            client(srv.addr.port(), ConnectSecret::None, VncConnOptions::default(), None).await;
        assert_eq!(closed(&mut c.s).await, CloseCode::ProtocolError);
    }
}

#[tokio::test]
async fn desktop_resize_reaches_sink_and_events() {
    let script = [update(1), rect(0, 0, 8, 6, enc::DESKTOP_SIZE, &[])].concat();
    let mut srv = start(SrvConfig {
        security: vec![1],
        fb: (4, 4),
        script: vec![script],
        ..Default::default()
    })
    .await;
    let mut c = client(srv.addr.port(), ConnectSecret::None, VncConnOptions::default(), None).await;
    connected(&mut c.s).await;
    assert!(matches!(next(&mut c.s).await, SessionEvent::DesktopResized { width: 4, height: 4 }));
    assert!(matches!(next(&mut c.s).await, SessionEvent::DesktopResized { width: 8, height: 6 }));
    assert_eq!(c.sink.size(), (8, 6));
    let mut got = Vec::new();
    assert!(
        srv.until(&mut got, |b| contains(b, &[3, 0, 0, 0, 0, 0, 0, 8, 0, 6])).await,
        "full request after resize"
    );
}

#[tokio::test]
async fn pinned_x509_plain_with_username() {
    let (der, key) = cert("127.0.0.1");
    let srv = start(SrvConfig {
        security: vec![19],
        subtypes: vec![261, 262],
        tls: Some((der.clone(), key)),
        fb: (4, 4),
        ..Default::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("tmp");
    let mut k = KnownCerts::new();
    k.add("127.0.0.1", srv.addr.port(), &fingerprint(&der), time::OffsetDateTime::now_utc());
    k.save(&dir.path().join("known_vnc_certs")).expect("save");
    let secret = ConnectSecret::DomainPassword {
        user: "alice".into(),
        domain: String::new(),
        password: SecretString::from("pw".to_owned()),
    };
    let mut c = client(srv.addr.port(), secret, VncConnOptions::default(), Some(dir)).await;
    assert_eq!(connected(&mut c.s).await.1.as_deref(), Some("vencrypt-x509"));
    let audit = c.s.take_audit_events();
    assert!(audit.contains(&SessionAudit::AuthSucceeded { method: AuthMethod::VncPlain }));
    assert!(!audit
        .iter()
        .any(|a| matches!(a, SessionAudit::CertAdded { .. } | SessionAudit::CertCaValid { .. })));
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
