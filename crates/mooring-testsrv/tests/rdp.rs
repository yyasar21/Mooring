//! RDP test server self-tests, driven by an `ironrdp-connector` / `ironrdp-session` client.

mod common;

use common::rdp_client::{ClientOptions, RdpClient};
use common::{eventually, within};
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::input::MousePdu;
use mooring_testsrv::rdp::{self, BitmapMode, InputRecord, RdpConfig, RdpKnobs, RdpSecurity, Rect};

fn rgb_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.as_chunks::<4>()
            .0
            .iter()
            .zip(b.as_chunks::<4>().0.iter())
            .all(|(x, y)| x[..3] == y[..3])
}

async fn connect(srv: &rdp::RdpHandle, o: ClientOptions) -> Result<RdpClient, String> {
    within(RdpClient::connect(srv.addr(), o, srv.cert().public_key_raw().to_vec())).await
}

async fn screen_matches(c: &mut RdpClient, srv: &rdp::RdpHandle) {
    let fb = srv.framebuffer().rgba;
    within(c.until(|c| rgb_eq(c.rgba(), &fb))).await.expect("framebuffer reached the client");
}

#[tokio::test]
async fn nla_connect_serves_the_framebuffer_raw_and_planar() {
    for mode in [BitmapMode::Raw, BitmapMode::Planar] {
        let srv = rdp::start(RdpConfig { bitmap: mode, ..RdpConfig::default() }, 0).expect("start");
        let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
        screen_matches(&mut c, &srv).await;
        assert_eq!(c.leaf.as_deref(), Some(srv.cert().cert_der().as_ref()), "TLS leaf is the pin");
        let st = srv.stats();
        assert_eq!((st.accepted, st.security.as_slice()), (1, ["hybrid".to_owned()].as_slice()));
        assert_eq!(st.keyboard_layout, Some(0x041F));
        // 640 × 480 in 64 × 32 tiles = 150, all widths a multiple of 4.
        assert_eq!(st.planar_tiles, if mode == BitmapMode::Planar { 150 } else { 0 });
    }
}

#[tokio::test]
async fn nla_refuses_a_wrong_password() {
    let srv = rdp::start(RdpConfig::default(), 0).expect("start");
    let o = ClientOptions { password: "wrong".to_owned(), ..ClientOptions::default() };
    assert!(connect(&srv, o).await.is_err());
    eventually(|| srv.stats().errors.iter().any(|e| e.starts_with("credssp"))).await;
    assert_eq!(srv.stats().accepted, 0);
}

#[tokio::test]
async fn nla_with_a_domain_account() {
    let cfg = RdpConfig { domain: Some("EXAMPLE".to_owned()), ..RdpConfig::default() };
    let srv = rdp::start(cfg, 0).expect("start");
    let o = ClientOptions { domain: Some("EXAMPLE".to_owned()), ..ClientOptions::default() };
    connect(&srv, o).await.expect("domain login");
}

#[tokio::test]
async fn tls_without_nla_checks_client_info_credentials() {
    let srv = rdp::start(RdpConfig { security: RdpSecurity::Tls, ..RdpConfig::default() }, 0)
        .expect("start");
    let tls = ClientOptions { nla: false, tls: true, ..ClientOptions::default() };
    let mut c = connect(&srv, tls.clone()).await.expect("TLS-only connect");
    screen_matches(&mut c, &srv).await;
    let bad = ClientOptions { password: "wrong".to_owned(), ..tls };
    let refused = match connect(&srv, bad).await {
        Err(_) => true,
        Ok(mut c) => within(c.step()).await.is_err(),
    };
    assert!(refused, "wrong Client Info password must not reach the active stage");
}

#[tokio::test]
async fn nla_only_client_is_refused_by_a_tls_only_server() {
    let srv = rdp::start(RdpConfig { security: RdpSecurity::Tls, ..RdpConfig::default() }, 0)
        .expect("start");
    assert!(connect(&srv, ClientOptions::default()).await.is_err());
    eventually(|| srv.stats().errors.iter().any(|e| e.starts_with("negotiation"))).await;
}

#[tokio::test]
async fn incremental_bitmap_after_fill() {
    let srv = rdp::start(RdpConfig::default(), 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    screen_matches(&mut c, &srv).await;
    srv.fill(Rect::new(100, 50, 70, 40), [200, 10, 20, 255]);
    screen_matches(&mut c, &srv).await;
}

#[tokio::test]
async fn fast_path_input_is_recorded() {
    let srv = rdp::start(RdpConfig::default(), 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    let mouse = MousePdu {
        flags: PointerFlags::MOVE,
        number_of_wheel_rotation_units: 0,
        x_position: 12,
        y_position: 34,
    };
    c.input(&[
        FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x1E),
        FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE | KeyboardFlags::EXTENDED, 0x48),
        FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), u16::from(b'z')),
        FastPathInputEvent::MouseEvent(mouse),
    ])
    .await
    .expect("input");
    eventually(|| srv.stats().inputs.len() >= 4).await;
    let inputs = srv.stats().inputs;
    assert!(inputs.contains(&InputRecord::Key { code: 0x1E, extended: false, release: false }));
    assert!(inputs.contains(&InputRecord::Key { code: 0x48, extended: true, release: true }));
    assert!(inputs.contains(&InputRecord::Unicode { code: u16::from(b'z'), release: false }));
    assert!(inputs.iter().any(|i| matches!(i, InputRecord::Mouse { x: 12, y: 34, .. })));
}

#[tokio::test]
async fn display_control_resize_is_recorded() {
    let srv = rdp::start(RdpConfig::default(), 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    within(async {
        while !matches!(c.resize(1024, 768).await, Ok(true)) {
            c.pump(50).await.expect("pump");
        }
    })
    .await;
    eventually(|| srv.stats().layouts.contains(&(1024, 768))).await;
}

#[tokio::test]
async fn clipboard_text_both_ways() {
    let srv = rdp::start(RdpConfig::default(), 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    within(async {
        while !c.clipboard_ready() {
            c.pump(50).await.expect("pump");
        }
    })
    .await;

    srv.set_clipboard("from server: çğü");
    within(c.until(|c| !c.clip.lock().expect("log").received.is_empty())).await.expect("paste");
    assert_eq!(c.clip.lock().expect("log").received, ["from server: çğü"]);
    assert_eq!(srv.stats().clipboard_served, 1);

    c.set_local_text("from client: ışık");
    c.copy_text().await.expect("copy");
    within(async {
        while srv.stats().clipboard_from_client.is_empty() {
            c.pump(50).await.expect("pump");
        }
    })
    .await;
    assert_eq!(srv.stats().clipboard_from_client, ["from client: ışık"]);
}

#[tokio::test]
async fn graceful_shutdown_is_recorded() {
    let srv = rdp::start(RdpConfig::default(), 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    c.shutdown().await.expect("send shutdown");
    eventually(|| srv.stats().shutdown_requests == 1).await;
}

#[tokio::test]
async fn hostile_knobs() {
    let knobs = RdpKnobs { out_of_bounds_bitmap: Some(16), ..RdpKnobs::default() };
    let srv = rdp::start(RdpConfig { knobs, ..RdpConfig::default() }, 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    // IronRDP's session skips (does not apply) the out-of-bounds tile; the rest still renders.
    screen_matches(&mut c, &srv).await;

    let knobs = RdpKnobs { drop_after_accept: true, ..RdpKnobs::default() };
    let srv = rdp::start(RdpConfig { knobs, ..RdpConfig::default() }, 0).expect("start");
    let mut c = connect(&srv, ClientOptions::default()).await.expect("connect");
    assert!(within(c.step()).await.is_err(), "connection dropped right after accept");
}
