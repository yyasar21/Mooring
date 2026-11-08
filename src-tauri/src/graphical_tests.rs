//! Graphical session task: frames end to end, reconnect schedule, certificate prompt.

use mooring_core::frame::{PixelOrder, Rect};
use mooring_core::known_certs::{CertProblem, CertTrust, CertificateInfo, KnownCerts};
use mooring_core::session::{CloseCode, PromptPurpose, SessionEvent, SessionInput};
use mooring_core::SessionAudit;
use secrecy::SecretString;
use time::OffsetDateTime;

use super::*;
use crate::commands::session_graphics as gfx;
use crate::commands::sessions::{self as sess, WireInput};
use crate::test_graphical::{audit, bench, gone, next_conn, open, Bench, FakeConn, Ui};

const DER: &[u8] = b"synthetic leaf certificate";

fn info() -> CertificateInfo {
    let t = OffsetDateTime::UNIX_EPOCH;
    CertificateInfo::new(DER, "CN=rdp.example.test", "CN=rdp.example.test", t, t, &[], vec![
        CertProblem::SelfSigned,
    ])
}

fn prompt(conn: &FakeConn, id: u32) {
    conn.send(SessionEvent::Prompt {
        id,
        message: "Unknown certificate".into(),
        secret: false,
        purpose: PromptPurpose::CertificateTrust,
        account: None,
        certificate: Some(info()),
        hop: None,
    });
}

async fn answer(b: &Bench, ui: &Ui, id: u32, text: &str) {
    let a = WireInput::Answer { id, text: SecretString::from(text.to_owned()) };
    sess::send(&b.f.state, &ui.session_id, a).await.expect("answer accepted");
}

async fn expect_kind(ui: &mut Ui, kind: &str) -> serde_json::Value {
    let e = ui.event().await;
    assert_eq!(e["kind"], kind, "{e}");
    e
}

fn pin_path(b: &Bench) -> std::path::PathBuf {
    b.f.dir.path().join("known_rdp_certs")
}

#[tokio::test]
async fn frames_flow_with_credits_attach_and_screenshot() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    assert_eq!(conn.size, crate::test_graphical::DESKTOP);
    assert!(matches!(conn.options, mooring_core::ProtocolOptions::Rdp(_)), "options read");
    assert_eq!(sess::list(&b.f.state).expect("list")[0].protocol, "rdp");
    conn.connected();
    let connected = expect_kind(&mut ui, "connected").await;
    assert_eq!(connected["security"], "nla");
    let err = gfx::screenshot(&b.f.state, &ui.session_id).expect_err("no desktop yet");
    assert_eq!(err.code, "session.not_connected");

    conn.frames.resize(4, 2).expect("resize");
    let first = ui.frame().await;
    assert_eq!(first.seq, 1);
    assert!(first.is_full() && first.is_resized());
    conn.frames.fill(Rect::new(0, 0, 1, 1), [1, 2, 3, 255]).expect("fill");
    assert_eq!(ui.frame().await.seq, 2);
    conn.frames.blit(Rect::new(1, 1, 1, 1), &[9, 9, 9, 9], 4, PixelOrder::Bgra).expect("blit");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(ui.frames.try_recv().is_err(), "two in flight: the third waits");
    gfx::frame_ack(&b.f.state, &ui.session_id, 99).expect("forged ack is ignored");
    assert!(ui.frames.try_recv().is_err());
    gfx::frame_ack(&b.f.state, &ui.session_id, 1).expect("ack");
    assert_eq!(ui.frame().await.seq, 3);

    // Re-attach: credits reset (2 and 3 are never acked) and the next message is full.
    let att = gfx::attach(&b.f.state, &ui.session_id).expect("attach");
    assert_eq!((att.protocol, att.state, att.size.width, att.size.height), ("rdp", "connected", 4, 2));
    let full = ui.frame().await;
    assert!(full.is_full() && !full.is_resized(), "full frame after attach");

    let shot = gfx::screenshot(&b.f.state, &ui.session_id).expect("screenshot");
    assert_eq!((shot.width, shot.height), (4, 2));
    let image = b.f.clipboard.peek_image().expect("image on the clipboard");
    assert_eq!((image.0, image.1), (4, 2));
    assert!(audit(&b).contains(r#""event":"session_screenshot""#));
    // vault_lock / exit clear the screenshot while it is still on the clipboard.
    b.f.state.clear_pending_clipboard();
    assert_eq!(b.f.clipboard.peek_image(), None, "screenshot cleared on lock");
    gfx::screenshot(&b.f.state, &ui.session_id).expect("screenshot");
    crate::clipboard::Clipboard::set(&*b.f.clipboard, "copied by the user").expect("set");
    b.f.state.clear_pending_clipboard();
    assert_eq!(b.f.clipboard.peek().as_deref(), Some("copied by the user"), "user copy kept");

    sess::close(&b.f.state, &ui.session_id).await.expect("close");
    let closed = expect_kind(&mut ui, "closed").await;
    assert_eq!(closed["code"], "user");
    gone(&b).await;
    assert!(audit(&b).contains(r#""event":"session_closed""#));
}

#[tokio::test]
async fn network_drop_after_connected_reconnects_then_auth_failure_stops() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    conn.connected();
    expect_kind(&mut ui, "connected").await;
    let resize = WireInput::Resize { size: mooring_core::session::Size { width: 1600, height: 900 } };
    sess::send(&b.f.state, &ui.session_id, resize).await.expect("resize");
    conn.closed(CloseCode::Network);
    let r = expect_kind(&mut ui, "reconnecting").await;
    assert_eq!(r["attempt"], 1);
    assert!(r["delay_ms"].as_u64().is_some(), "{r}");
    let second = next_conn(&mut b).await;
    assert_eq!(second.size.width, 1600, "reconnect uses the last requested size");
    second.connected();
    expect_kind(&mut ui, "connected").await;
    second.closed(CloseCode::AuthFailed);
    let closed = expect_kind(&mut ui, "closed").await;
    assert_eq!(closed["code"], "auth_failed");
    gone(&b).await;
    assert!(b.conns.try_recv().is_err(), "no retry after auth_failed");
    let log = audit(&b);
    assert_eq!(log.matches(r#""event":"session_opened""#).count(), 2, "{log}");
    assert_eq!(log.matches(r#""event":"session_closed""#).count(), 1, "{log}");
}

#[tokio::test]
async fn no_retry_before_connected() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    conn.closed(CloseCode::Network);
    assert_eq!(expect_kind(&mut ui, "closed").await["code"], "network");
    gone(&b).await;
    assert!(b.conns.try_recv().is_err());
}

#[tokio::test]
async fn retries_stop_after_six_attempts() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    conn.connected();
    expect_kind(&mut ui, "connected").await;
    for _ in 0..6 {
        b.factory.fail.lock().expect("f").push_back(IpcError::session_failed("connection refused"));
    }
    conn.closed(CloseCode::ServerEnded);
    for attempt in 1..=6 {
        assert_eq!(expect_kind(&mut ui, "reconnecting").await["attempt"], attempt);
    }
    let closed = expect_kind(&mut ui, "closed").await;
    assert_eq!(closed["code"], "network");
    assert_eq!(closed["reason"], "connection refused");
    gone(&b).await;
}

#[tokio::test]
async fn a_locked_vault_stops_the_retries() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    conn.connected();
    expect_kind(&mut ui, "connected").await;
    crate::commands::vault::lock(&b.f.state, None).expect("lock");
    conn.closed(CloseCode::Network);
    expect_kind(&mut ui, "reconnecting").await;
    let closed = expect_kind(&mut ui, "closed").await;
    assert_eq!(closed["code"], "vault_locked", "{closed}");
    gone(&b).await;
    assert!(b.conns.try_recv().is_err(), "the factory was never called");
}

#[tokio::test]
async fn certificate_yes_pins_and_reconnects() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    prompt(&conn, 7);
    let p = expect_kind(&mut ui, "prompt").await;
    assert_eq!(p["purpose"], "certificate_trust");
    assert_eq!(p["certificate"]["sha256"].as_str().map(str::len), Some(64));
    // The protocol may end its stream after the prompt: the answer decides.
    conn.closed(CloseCode::TrustRejected);
    answer(&b, &ui, 7, "yes").await;
    let second = next_conn(&mut b).await;
    assert_eq!(second.trusted_once, None, "pin stored, nothing to accept once");
    let store = KnownCerts::load(&pin_path(&b)).expect("load");
    let sha = mooring_core::known_certs::fingerprint(DER);
    assert_eq!(store.check("rdp.example.test", 3389, &sha), CertTrust::Trusted);
    second.connected();
    expect_kind(&mut ui, "connected").await;
    let log = audit(&b);
    assert!(log.contains(r#""event":"cert_decision""#) && log.contains(r#""decision":"accepted""#), "{log}");
    assert!(log.contains(r#""host":"rdp.example.test:3389""#), "{log}");
}

#[tokio::test]
async fn certificate_no_closes_with_trust_rejected() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    prompt(&conn, 3);
    expect_kind(&mut ui, "prompt").await;
    answer(&b, &ui, 3, "no").await;
    assert_eq!(expect_kind(&mut ui, "closed").await["code"], "trust_rejected");
    gone(&b).await;
    assert!(b.conns.try_recv().is_err());
    assert!(!pin_path(&b).exists(), "no pin written");
    assert!(audit(&b).contains(r#""decision":"rejected""#));
}

#[tokio::test]
async fn certificate_yes_with_an_unwritable_store_trusts_once() {
    let mut b = bench("rdp");
    std::fs::create_dir(pin_path(&b)).expect("a directory where the file should be");
    let (mut ui, conn) = open(&mut b).await;
    prompt(&conn, 1);
    expect_kind(&mut ui, "prompt").await;
    answer(&b, &ui, 1, "YES").await;
    let second = next_conn(&mut b).await;
    assert_eq!(second.trusted_once, Some(mooring_core::known_certs::fingerprint(DER)));
    assert!(audit(&b).contains(r#""decision":"accepted_session_only""#));
}

/// U2: `once` trusts for this connect only: `trusted_once`, no pin, audited `trusted_once`.
#[tokio::test]
async fn certificate_once_trusts_this_connect_without_a_pin() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    prompt(&conn, 5);
    expect_kind(&mut ui, "prompt").await;
    answer(&b, &ui, 5, " Once ").await;
    let second = next_conn(&mut b).await;
    assert_eq!(second.trusted_once, Some(mooring_core::known_certs::fingerprint(DER)));
    assert!(!pin_path(&b).exists(), "no pin written");
    let log = audit(&b);
    assert_eq!(log.matches(r#""decision":"trusted_once""#).count(), 1, "{log}");
    assert!(!log.contains(r#""decision":"accepted""#), "{log}");
}

#[tokio::test]
async fn certificate_mismatch_is_a_hard_stop() {
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    conn.audits.lock().expect("a").push(SessionAudit::CertMismatch {
        host: "rdp.example.test".into(),
        port: 3389,
        expected: "SHA256:old".into(),
        presented: "SHA256:new".into(),
    });
    conn.closed(CloseCode::TrustMismatch);
    assert_eq!(expect_kind(&mut ui, "closed").await["code"], "trust_mismatch");
    gone(&b).await;
    assert!(b.conns.try_recv().is_err(), "never retried");
    let log = audit(&b);
    assert!(log.contains(r#""decision":"changed""#) && log.contains(r#""expected":"SHA256:old""#));
}

#[tokio::test]
async fn view_only_drops_input_but_release_all_passes() {
    let mut b = bench("rdp");
    let (mut ui, mut conn) = open(&mut b).await;
    conn.connected();
    expect_kind(&mut ui, "connected").await;
    gfx::set_view_only(&b.f.state, &ui.session_id, true).expect("view only");
    let ptr = WireInput::Pointer { x: 1, y: 1, buttons: 1 };
    sess::send(&b.f.state, &ui.session_id, ptr).await.expect("dropped, not refused");
    sess::send(&b.f.state, &ui.session_id, WireInput::ReleaseAll {}).await.expect("release");
    assert!(matches!(conn.input().await, SessionInput::ReleaseAll), "pointer never arrived");
    gfx::set_view_only(&b.f.state, &ui.session_id, false).expect("off");
    sess::send(&b.f.state, &ui.session_id, WireInput::Wheel { dx: 0, dy: 120 }).await.expect("wheel");
    assert!(matches!(conn.input().await, SessionInput::Wheel { dx: 0, dy: 120 }), "DOM sign unchanged");
    // L-26: each toggle is audited; screenshot and the toggle need an unlocked vault.
    let log = audit(&b);
    assert_eq!(log.matches(r#""event":"session_view_only""#).count(), 2, "{log}");
    assert!(log.contains(r#""view_only":true"#) && log.contains(r#""view_only":false"#), "{log}");
    conn.frames.resize(4, 2).expect("resize");
    crate::commands::vault::lock(&b.f.state, None).expect("lock");
    let e = gfx::set_view_only(&b.f.state, &ui.session_id, true).expect_err("locked");
    assert_eq!(e.code, "vault.locked");
    assert_eq!(gfx::screenshot(&b.f.state, &ui.session_id).expect_err("locked").code, "vault.locked");
    assert_eq!(b.f.clipboard.peek_image(), None, "nothing captured behind the lock");
}

#[tokio::test]
async fn hostile_graphical_ipc_is_refused() {
    let mut b = bench("rdp");
    let (sk, _rx) = {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<crate::sessions::WireEvent>();
        let sk: crate::sessions::EventSink = std::sync::Arc::new(move |e| tx.send(e).is_ok());
        (sk, rx)
    };
    let e = sess::open(&b.f.state, &b.conn, crate::test_graphical::DESKTOP, sk.clone()).await;
    assert_eq!(e.expect_err("no onFrame").code, "input.invalid");
    let out: crate::frame_pump::FrameOut = std::sync::Arc::new(|_| true);
    let odd = mooring_core::session::Size { width: 1281, height: 800 };
    let e = sess::open_with(&b.f.state, &b.conn, odd, sk.clone(), Some(out.clone())).await;
    assert_eq!(e.expect_err("odd width").code, "input.invalid");
    let (ui, _conn) = open(&mut b).await;
    let bad = WireInput::Resize { size: mooring_core::session::Size { width: 100, height: 100 } };
    assert_eq!(sess::send(&b.f.state, &ui.session_id, bad).await.expect_err("small").code, "input.invalid");
    for id in ["", "missing", &"x".repeat(65)] {
        let e = gfx::frame_ack(&b.f.state, id, 1).expect_err("unknown");
        assert!(matches!(e.code, "input.invalid" | "session.not_found"), "{id}: {}", e.code);
        assert!(gfx::screenshot(&b.f.state, id).is_err());
        assert!(gfx::attach(&b.f.state, id).is_err());
    }
    // SSH connections take no frame channel.
    let root = b.f.state.with_ready(|_, s| Ok(crate::commands::tree::root_id(s).to_string())).expect("r");
    let fields = crate::commands::tree::ConnectionFields::basic(&root, "ssh", "ssh", "192.0.2.1");
    let ssh = crate::commands::tree::create_connection(&b.f.state, fields).expect("ssh").id;
    let size = mooring_core::session::Size { width: 80, height: 24 };
    let e = sess::open_with(&b.f.state, &ssh, size, sk, Some(out)).await.expect_err("frames on ssh");
    assert_eq!(e.code, "input.invalid");
}

#[tokio::test]
async fn builtin_factory_opens_real_vnc_sessions() {
    let mut b = bench("vnc");
    b.f.state.settings.graphical = std::sync::Arc::new(crate::session_factory::BuiltinFactory);
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<crate::sessions::WireEvent>();
    let sk: crate::sessions::EventSink = std::sync::Arc::new(move |e| tx.send(e).is_ok());
    let out: crate::frame_pump::FrameOut = std::sync::Arc::new(|_| true);
    let opened = sess::open_with(&b.f.state, &b.conn, crate::test_graphical::DESKTOP, sk, Some(out))
        .await
        .expect("the real VNC session starts (TCP runs in its task)");
    assert_eq!(sess::list(&b.f.state).expect("list").len(), 1);
    sess::close(&b.f.state, &opened.session_id).await.expect("close");
    gone(&b).await;
}

#[test]
fn connect_errors_map_to_close_codes() {
    for (code, want) in [
        ("vault.locked", CloseCode::VaultLocked),
        ("session.trust_mismatch", CloseCode::TrustMismatch),
        ("session.trust_rejected", CloseCode::TrustRejected),
        ("session.unsupported_security", CloseCode::ProtocolError),
        ("credential.secret_missing", CloseCode::AuthFailed),
        ("session.failed", CloseCode::Network),
    ] {
        assert_eq!(close_code_of(&IpcError::new(code, "x")), want, "{code}");
    }
}

fn vnc_connected(conn: &FakeConn, security: &str) {
    conn.send(SessionEvent::Connected {
        protocol: Protocol::Vnc,
        peer_identity: None,
        security: Some(security.to_owned()),
        hop: None,
    });
}

#[tokio::test]
async fn vnc_tls_connect_records_the_tls_seen_marker() {
    let mut b = bench("vnc");
    let (mut ui, conn) = open(&mut b).await;
    let path = b.f.dir.path().join("known_vnc_certs");
    vnc_connected(&conn, "vnc-auth");
    expect_kind(&mut ui, "connected").await;
    assert!(!path.exists(), "plaintext connects record nothing");
    conn.closed(CloseCode::Network);
    expect_kind(&mut ui, "reconnecting").await;
    let second = next_conn(&mut b).await;
    vnc_connected(&second, "vencrypt-x509");
    expect_kind(&mut ui, "connected").await;
    let text = std::fs::read_to_string(&path).expect("marker written");
    assert_eq!(text.matches(" tls-required - ").count(), 1, "{text}");
    assert!(KnownCerts::load(&path).expect("load").is_empty(), "a marker, not a pin");
    sess::close(&b.f.state, &ui.session_id).await.expect("close");
}

/// L-25: offers are audited (vault secrets as `credential_sent_to_remote`); the remote
/// cannot write, and nothing is offered, while the vault is locked.
#[tokio::test]
async fn remote_clipboard_is_gated_by_the_lock_and_offers_are_audited() {
    use mooring_core::clipboard::Clipboard as _;
    let mut b = bench("rdp");
    let (mut ui, conn) = open(&mut b).await;
    conn.connected();
    expect_kind(&mut ui, "connected").await;
    crate::clipboard::Clipboard::set(&*b.f.clipboard, "copied-secret").expect("set");
    *b.f.state.copied_credential.lock().expect("lock") =
        Some((crate::clipboard::digest("copied-secret"), "cred-42".to_owned()));
    assert_eq!(conn.clipboard.read_text().as_deref(), Some("copied-secret"));
    let log = audit(&b);
    assert!(log.contains(r#""event":"session_clipboard_offer""#) && log.contains(r#""bytes":13"#), "{log}");
    assert!(log.contains(r#""event":"credential_sent_to_remote""#) && log.contains(r#""credential":"cred-42""#));
    assert!(!log.contains("copied-secret"), "never the text");
    assert!(conn.clipboard.write_text("from the remote"), "unlocked: written");

    crate::commands::vault::lock(&b.f.state, None).expect("lock");
    assert!(!conn.clipboard.write_text("pastejack"), "locked: refused");
    assert!(!conn.clipboard.write_text("pastejack again"));
    assert_ne!(b.f.clipboard.peek().as_deref(), Some("pastejack"));
    assert_eq!(conn.clipboard.read_text(), None, "nothing offered while locked");
    let log = audit(&b);
    assert_eq!(log.matches(r#""event":"session_clipboard_blocked""#).count(), 1, "{log}");
    assert_eq!(log.matches(r#""event":"session_clipboard_offer""#).count(), 1, "{log}");
}

// --- ADR-0027: RD Gateway trust and credential ------------------------------------------

fn with_gateway(b: &Bench, credential: Option<&str>) {
    let id = crate::dto::connection_id("id", &b.conn).expect("id");
    b.f.state
        .with_ready(|_, s| {
            let gateway = mooring_core::RdGatewayOptions {
                host: "gw01.example.test".into(),
                port: 443,
                usage: mooring_core::options::GatewayUsage::Always,
                allow_basic_gateway: false,
                ca_pem: None,
            };
            let o = mooring_core::options::RdpConnOptions { gateway: Some(gateway), ..Default::default() };
            s.set_connection_options(id, &mooring_core::ProtocolOptions::Rdp(o))?;
            if let Some(c) = credential {
                let c = crate::dto::credential_id("c", c)?;
                s.set_connection_role_credential(id, mooring_core::Role::Gateway, Some(c))?;
            }
            Ok(())
        })
        .expect("gateway options");
}

fn gateway_prompt(conn: &FakeConn, id: u32) {
    conn.send(SessionEvent::Prompt {
        id,
        message: "Unknown RD Gateway certificate".into(),
        secret: false,
        purpose: PromptPurpose::GatewayCertificateTrust,
        account: None,
        certificate: Some(info()),
        hop: None,
    });
}

#[tokio::test]
async fn gateway_certificate_yes_pins_known_rdg_certs_and_reconnects() {
    let mut b = bench("rdp");
    with_gateway(&b, None);
    let (mut ui, conn) = open(&mut b).await;
    let g = conn.gateway.as_ref().expect("gateway config");
    assert!(matches!(*g.credential, mooring_proto_rdp::GatewayCredential::SameAsSignIn));
    assert!(g.known_certs.ends_with("known_rdg_certs") && g.trusted_once.is_none());
    gateway_prompt(&conn, 4);
    assert_eq!(expect_kind(&mut ui, "prompt").await["purpose"], "gateway_certificate_trust");
    answer(&b, &ui, 4, "yes").await;
    let second = next_conn(&mut b).await;
    assert_eq!((second.trusted_once, second.gateway.as_ref().and_then(|g| g.trusted_once)), (None, None));
    let rdg = KnownCerts::load(&b.f.dir.path().join("known_rdg_certs")).expect("load");
    let sha = mooring_core::known_certs::fingerprint(DER);
    assert_eq!(rdg.check("gw01.example.test", 443, &sha), CertTrust::Trusted);
    assert!(!pin_path(&b).exists(), "the RDP store is untouched");
    let log = audit(&b);
    assert!(log.contains(r#""protocol":"rdg""#) && log.contains(r#""host":"gw01.example.test:443""#), "{log}");
}

#[tokio::test]
async fn gateway_once_then_target_once_are_both_kept() {
    let mut b = bench("rdp");
    with_gateway(&b, None);
    let (mut ui, conn) = open(&mut b).await;
    gateway_prompt(&conn, 1);
    expect_kind(&mut ui, "prompt").await;
    answer(&b, &ui, 1, "once").await;
    let second = next_conn(&mut b).await;
    let sha = mooring_core::known_certs::fingerprint(DER);
    assert_eq!(second.gateway.as_ref().and_then(|g| g.trusted_once), Some(sha));
    prompt(&second, 2);
    expect_kind(&mut ui, "prompt").await;
    answer(&b, &ui, 2, "once").await;
    let third = next_conn(&mut b).await;
    assert_eq!(third.trusted_once, Some(sha));
    assert_eq!(third.gateway.as_ref().and_then(|g| g.trusted_once), Some(sha), "gateway once kept");
}

#[tokio::test]
async fn gateway_role_credential_reaches_the_protocol() {
    let mut b = bench("rdp");
    let id = b.f.state
        .with_ready(|v, s| {
            let secrets = std::collections::BTreeMap::from([(mooring_core::SecretName::Password, &b"gw pass"[..])]);
            let fields = serde_json::json!({"username": "gwuser", "domain": "CORP"});
            let kind = mooring_core::CredentialKind::UserPassword;
            let c = s.create_credential(v, "gw", kind, &fields, &secrets)?;
            Ok(c.id.to_string())
        })
        .expect("credential");
    with_gateway(&b, Some(&id));
    let (_ui, conn) = open(&mut b).await;
    let g = conn.gateway.as_ref().expect("gateway");
    let mooring_proto_rdp::GatewayCredential::Account(a) = &*g.credential else { panic!("account") };
    assert_eq!((a.username.as_str(), a.domain.as_deref()), ("gwuser", Some("CORP")));
    assert!(audit(&b).contains(&id), "credential_used names the gateway credential");
    assert_eq!(close_code_of(&IpcError::new("rdp.gateway_auth", "x")), CloseCode::GatewayAuth);
    assert_eq!(close_code_of(&IpcError::new("rdp.gateway_refused", "x")), CloseCode::GatewayRefused);
    assert_eq!(close_code_of(&IpcError::new("rdp.gateway_unsupported", "x")), CloseCode::GatewayUnsupported);
}
