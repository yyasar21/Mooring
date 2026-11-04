//! Detach routing end to end on the scripted graphical session (`test_graphical`): the
//! detached view takes events and frames over, `main` is told, credits reset, and
//! `window_attach` brings the session back.

use std::time::Duration;

use mooring_core::frame::Rect;
use tokio::sync::mpsc;

use super::*;
use crate::commands::sessions as sess;
use crate::test_graphical::{audit, bench, gone, open, Ui};

/// A second view (the detached window) with its own channels.
fn view() -> (Sinks, Ui) {
    let (etx, events) = mpsc::unbounded_channel();
    let (ftx, frames) = mpsc::unbounded_channel();
    let events_sink: EventSink =
        Arc::new(move |e| etx.send(serde_json::to_value(&e).expect("json")).is_ok());
    let out: FrameOut = Arc::new(move |m| ftx.send(m).is_ok());
    (Sinks { events: events_sink, frames: Some(out) }, Ui { session_id: String::new(), events, frames })
}

async fn kind(ui: &mut Ui) -> String {
    ui.event().await["kind"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn detach_moves_events_and_frames_then_attach_brings_them_back() {
    let mut b = bench("rdp");
    let (mut main, conn) = open(&mut b).await;
    let sid = main.session_id.clone();
    conn.connected();
    assert_eq!(kind(&mut main).await, "connected");
    conn.frames.resize(4, 2).expect("resize");
    assert_eq!(main.frame().await.seq, 1);

    let (label, connection) = plan_detach(&b.f.state, &sid).expect("plan");
    assert_eq!(label, format!("detached-{sid}"));
    assert_eq!(connection, b.conn);
    b.f.state.audit(AuditEvent::SessionDetached { connection, session: sid.clone() });

    // The detached view attaches: main is told, credits reset, a full frame goes to it.
    let (sinks, mut det) = view();
    let att = attach_view(&b.f.state, &sid, &label, sinks).expect("attach");
    assert_eq!((att.protocol, att.state, att.size.width, att.size.height), ("rdp", "connected", 4, 2));
    assert_eq!(kind(&mut main).await, "detached");
    let full = det.frame().await;
    assert!(full.is_full(), "full frame for the new view");
    conn.frames.fill(Rect::new(0, 0, 1, 1), [1, 2, 3, 255]).expect("fill");
    let next = det.frame().await;
    crate::commands::session_graphics::frame_ack(&b.f.state, &sid, next.seq).expect("ack");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(main.frames.try_recv().is_err(), "main gets no frames while detached");

    // window_attach: back to main, which is told and gets a full frame.
    assert_eq!(attach_main(&b.f.state, &sid).expect("attach main").as_deref(), Some(label.as_str()));
    assert_eq!(attach_main(&b.f.state, &sid).expect("again"), None, "closing the window later is a no-op");
    assert_eq!(kind(&mut main).await, "attached");
    assert!(main.frame().await.is_full());
    let log = audit(&b);
    assert!(log.contains(r#""event":"session_detached""#) && log.contains(r#""event":"session_attached""#));

    // Detach again, then the session ends: both views hear `closed`.
    let (sinks, mut det2) = view();
    attach_view(&b.f.state, &sid, &label, sinks).expect("attach");
    assert_eq!(kind(&mut main).await, "detached");
    sess::close(&b.f.state, &sid).await.expect("close");
    assert_eq!(kind(&mut det2).await, "closed");
    assert_eq!(kind(&mut main).await, "closed");
    gone(&b).await;
    assert_eq!(attach_main(&b.f.state, &sid).expect_err("gone").code, "session.not_found");
    drop(det);
}

#[tokio::test]
async fn attach_view_checks_frames_and_ids() {
    let mut b = bench("vnc");
    let (_main, _conn) = open(&mut b).await;
    let sid = sess::list(&b.f.state).expect("list")[0].session_id.clone();
    let (mut sinks, _ui) = view();
    sinks.frames = None;
    let e = attach_view(&b.f.state, &sid, "main", sinks).expect_err("frames required");
    assert_eq!(e.code, "input.invalid");
    for bad in ["", "x", "../main", &"a".repeat(65)] {
        let (sinks, _ui) = view();
        assert_eq!(attach_view(&b.f.state, bad, "main", sinks).expect_err(bad).code, "input.invalid");
        assert_eq!(plan_detach(&b.f.state, bad).expect_err(bad).code, "input.invalid");
    }
    let unknown = uuid::Uuid::new_v4().to_string();
    let (sinks, _ui) = view();
    assert_eq!(attach_view(&b.f.state, &unknown, "main", sinks).expect_err("u").code, "session.not_found");
    assert_eq!(plan_detach(&b.f.state, &unknown).expect_err("u").code, "session.not_found");
    crate::commands::vault::lock(&b.f.state, None).expect("lock");
    assert_eq!(plan_detach(&b.f.state, &sid).expect_err("locked").code, "vault.locked");
}
