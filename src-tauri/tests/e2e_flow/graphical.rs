//! A2 end to end: RDP and VNC sessions through the IPC command functions against QA's loopback
//! servers (`mooring_testsrv`), with the real `BuiltinFactory`: open → certificate TOFU (the
//! Tauri layer pins) → ≥ 1 MFR1 frame on the frame channel → ack → key + pointer → resize →
//! close.

use std::sync::Arc;
use std::time::Duration;

use mooring_core::frame::decode_mfr1;
use mooring_core::session::Size;
use mooring_testsrv::{rdp, rfb};
use tokio::sync::mpsc;

use crate::commands::credentials::{self, NewCredential};
use crate::commands::session_graphics as gfx;
use crate::commands::sessions as sess;
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing;
use crate::support::{next, sink, wait_until_empty, wire_input, Events};

const DESKTOP: Size = Size { width: 320, height: 240 };

struct Open {
    id: String,
    events: Events,
    frames: mpsc::UnboundedReceiver<Vec<u8>>,
}

async fn open(st: &crate::state::AppState, conn: &str) -> Open {
    let (s, events) = sink();
    let (ftx, frames) = mpsc::unbounded_channel();
    let out: mooring_app_lib::frame_pump::FrameOut = Arc::new(move |m| ftx.send(m).is_ok());
    let id = sess::open_with(st, conn, DESKTOP, s, Some(out)).await.expect("open").session_id;
    Open { id, events, frames }
}

/// Events until `kind`; a `certificate_trust` prompt on the way is answered `yes`.
async fn until(st: &crate::state::AppState, o: &mut Open, kind: &str) -> serde_json::Value {
    loop {
        let e = next(&mut o.events).await;
        if e["kind"] == kind {
            return e;
        }
        if e["kind"] == "prompt" && e["purpose"] == "certificate_trust" {
            let answer = serde_json::json!({"kind": "answer", "id": e["id"], "text": "yes"});
            sess::send(st, &o.id, wire_input(&answer).expect("wire")).await.expect("answer");
            continue;
        }
        assert_ne!(e["kind"], "closed", "{e}");
    }
}

async fn frame(o: &mut Open) -> mooring_core::frame::Mfr1Frame {
    let m = tokio::time::timeout(Duration::from_secs(20), o.frames.recv())
        .await
        .expect("frame within 20 s")
        .expect("channel open");
    decode_mfr1(&m).expect("valid MFR1")
}

async fn drive(st: &crate::state::AppState, o: &mut Open) {
    let first = frame(o).await;
    assert!(first.is_full(), "first message is full");
    gfx::frame_ack(st, &o.id, first.seq).expect("ack");
    for input in [
        serde_json::json!({"kind": "key", "code": "KeyA", "key": "a", "pressed": true}),
        serde_json::json!({"kind": "key", "code": "KeyA", "key": "a", "pressed": false}),
        serde_json::json!({"kind": "pointer", "x": 12, "y": 34, "buttons": 1}),
        serde_json::json!({"kind": "pointer", "x": 12, "y": 34, "buttons": 0}),
        serde_json::json!({"kind": "resize", "size": {"width": 400, "height": 300}}),
    ] {
        sess::send(st, &o.id, wire_input(&input).expect("wire")).await.expect("input");
    }
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

#[tokio::test]
async fn rdp_session_through_ipc_against_the_test_acceptor() {
    let srv =
        rdp::start(rdp::RdpConfig { width: 320, height: 240, ..rdp::RdpConfig::default() }, 0)
            .expect("rdp server");
    let f = testing::unlocked();
    let st = &f.state;
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let cred =
        credentials::create(st, NewCredential::user_password("rdp", "alice", "correct horse"))
            .expect("credential");
    let conn = tree::create_connection(
        st,
        ConnectionFields {
            port: Some(u32::from(srv.addr().port())),
            credential_id: Some(cred.id),
            ..ConnectionFields::basic(&root, "desk", "rdp", "127.0.0.1")
        },
    )
    .expect("connection")
    .id;

    let mut o = open(st, &conn).await;
    let c = until(st, &mut o, "connected").await;
    assert_eq!(c["security"], "nla");
    drive(st, &mut o).await;
    eventually("key + pointer on the server", || {
        let i = srv.stats().inputs;
        i.contains(&rdp::InputRecord::Key { code: 0x1e, extended: false, release: false })
            && i.iter().any(|r| matches!(r, rdp::InputRecord::Mouse { x: 12, y: 34, .. }))
    })
    .await;
    eventually("display control resize", || srv.stats().layouts.contains(&(400, 300))).await;
    assert_eq!(srv.stats().connections, 2, "TOFU yes reconnected on a new TCP connection");

    sess::close(st, &o.id).await.expect("close");
    let closed = until(st, &mut o, "closed").await;
    assert_eq!(closed["code"], "user");
    wait_until_empty(st).await;
    let events = testing::audit_events(st);
    assert!(events.iter().any(|e| e == "cert_decision"), "{events:?}");
    assert_eq!(events.iter().filter(|e| *e == "cert_decision").count(), 1, "audited once");
    let pins = st.data_dir.join("known_rdp_certs");
    let known = mooring_core::known_certs::KnownCerts::load(&pins).expect("pins");
    assert!(known.has_pin("127.0.0.1", srv.addr().port()), "the Tauri layer wrote the pin");
}

#[tokio::test]
async fn vnc_session_through_ipc_against_the_test_server() {
    let cfg = rfb::RfbConfig {
        width: 320,
        height: 240,
        security: vec![rfb::SecurityOffer::VeNCrypt(vec![rfb::VeNCryptSub::X509None])],
        ..rfb::RfbConfig::default()
    };
    let srv = rfb::start(cfg, 0).await.expect("rfb server");
    let f = testing::unlocked();
    let st = &f.state;
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let conn = tree::create_connection(
        st,
        ConnectionFields {
            port: Some(u32::from(srv.addr().port())),
            ..ConnectionFields::basic(&root, "vnc", "vnc", "127.0.0.1")
        },
    )
    .expect("connection")
    .id;

    let mut o = open(st, &conn).await;
    let c = until(st, &mut o, "connected").await;
    assert_eq!(c["security"], "vencrypt-x509");
    drive(st, &mut o).await;
    eventually("key + pointer on the server", || {
        let s = srv.stats();
        s.key_events.iter().any(|k| k.keysym == 0x61 && k.down)
            && s.last_pointer.is_some_and(|p| (p.1, p.2) == (12, 34))
    })
    .await;
    eventually("SetDesktopSize", || srv.stats().desktop_size_requests.contains(&(400, 300))).await;

    sess::close(st, &o.id).await.expect("close");
    assert_eq!(until(st, &mut o, "closed").await["code"], "user");
    wait_until_empty(st).await;
    let events = testing::audit_events(st);
    assert_eq!(events.iter().filter(|e| *e == "cert_decision").count(), 1, "{events:?}");
}
