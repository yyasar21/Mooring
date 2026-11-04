//! RFB test server self-tests: every encoding round-trips the synthetic framebuffer; updates,
//! `CopyRect`, resize, input counters and cut text.

mod common;

use common::rfb_client::{Auth, Client, ServerMsg};
use common::{eventually, within};
use mooring_testsrv::rfb::{self, encoding, Rect, RfbConfig, TightMode, ZrleMode};

async fn client_for(cfg: RfbConfig, encodings: &[i32]) -> (rfb::RfbHandle, Client) {
    let srv = rfb::start(cfg, 0).await.expect("start");
    let mut c = within(Client::connect(srv.addr(), Auth::None)).await.expect("connect");
    c.set_encodings(encodings).await.expect("encodings");
    (srv, c)
}

async fn full_update_matches(cfg: RfbConfig, enc: i32) {
    let (srv, mut c) = client_for(cfg, &[enc]).await;
    c.request(false).await.expect("request");
    let rects = within(c.read_update()).await.expect("update");
    assert!(rects.iter().all(|(_, e)| *e == enc), "{rects:?}");
    assert_eq!(c.fb, srv.framebuffer().rgba, "decoded framebuffer differs ({enc})");
}

#[tokio::test]
async fn raw_full_update() {
    full_update_matches(RfbConfig::default(), encoding::RAW).await;
}

#[tokio::test]
async fn zrle_every_tile_mode() {
    for mode in [ZrleMode::Auto, ZrleMode::Raw, ZrleMode::PlainRle] {
        full_update_matches(RfbConfig { zrle_mode: mode, ..RfbConfig::default() }, encoding::ZRLE)
            .await;
    }
}

#[tokio::test]
async fn tight_every_filter() {
    for mode in [TightMode::Auto, TightMode::Copy, TightMode::Palette, TightMode::Gradient] {
        full_update_matches(
            RfbConfig { tight_mode: mode, ..RfbConfig::default() },
            encoding::TIGHT,
        )
        .await;
    }
}

#[tokio::test]
async fn persistent_zlib_streams_survive_many_updates() {
    for enc in [encoding::ZRLE, encoding::TIGHT] {
        let (srv, mut c) = client_for(RfbConfig::default(), &[enc]).await;
        for i in 0..5u8 {
            srv.fill(Rect::new(u16::from(i) * 50, 10, 120, 90), [i * 40, 255 - i * 40, 7, 255]);
            c.request(i > 0).await.expect("request");
            within(c.read_update()).await.expect("update");
        }
        c.request(false).await.expect("request");
        within(c.read_update()).await.expect("update");
        assert_eq!(c.fb, srv.framebuffer().rgba);
    }
}

#[tokio::test]
async fn incremental_update_sends_only_the_dirty_rect() {
    let (srv, mut c) = client_for(RfbConfig::default(), &[encoding::RAW]).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("first");
    c.request(true).await.expect("incremental");
    srv.fill(Rect::new(10, 20, 30, 40), [9, 8, 7, 255]);
    let rects = within(c.read_update()).await.expect("dirty");
    assert_eq!(rects, [(Rect::new(10, 20, 30, 40), encoding::RAW)]);
    assert_eq!(c.fb, srv.framebuffer().rgba);
}

#[tokio::test]
async fn copy_rect_when_advertised_dirty_otherwise() {
    let (srv, mut c) =
        client_for(RfbConfig::default(), &[encoding::COPY_RECT, encoding::RAW]).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("first");
    c.request(true).await.expect("incremental");
    srv.copy(Rect::new(100, 100, 50, 50), 0, 0);
    let rects = within(c.read_update()).await.expect("copy");
    assert_eq!(rects, [(Rect::new(100, 100, 50, 50), encoding::COPY_RECT)]);
    assert_eq!(c.fb, srv.framebuffer().rgba);

    let (srv, mut c) = client_for(RfbConfig::default(), &[encoding::RAW]).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("first");
    c.request(true).await.expect("incremental");
    srv.copy(Rect::new(100, 100, 50, 50), 0, 0);
    let rects = within(c.read_update()).await.expect("dirty");
    assert_eq!(rects, [(Rect::new(100, 100, 50, 50), encoding::RAW)]);
}

#[tokio::test]
async fn desktop_size_on_server_resize() {
    let (srv, mut c) =
        client_for(RfbConfig::default(), &[encoding::RAW, encoding::DESKTOP_SIZE]).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("first");
    srv.resize(320, 200);
    c.request(true).await.expect("incremental");
    let rects = within(c.read_update()).await.expect("resize");
    assert_eq!(rects, [(Rect::new(0, 0, 320, 200), encoding::DESKTOP_SIZE)]);
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("new screen");
    assert_eq!((c.width, c.height), (320, 200));
    assert_eq!(c.fb, srv.framebuffer().rgba);
}

#[tokio::test]
async fn set_desktop_size_is_answered_with_extended_desktop_size() {
    let encs = [encoding::RAW, encoding::EXTENDED_DESKTOP_SIZE];
    let (srv, mut c) = client_for(RfbConfig::default(), &encs).await;
    c.request(false).await.expect("request");
    let first = within(c.read_update()).await.expect("first");
    assert_eq!(first[0], (Rect::new(0, 0, 640, 480), encoding::EXTENDED_DESKTOP_SIZE));
    c.set_desktop_size(800, 600).await.expect("SetDesktopSize");
    c.request(true).await.expect("incremental");
    let rects = within(c.read_update()).await.expect("answer");
    assert_eq!(rects, [(Rect::new(1, 0, 800, 600), encoding::EXTENDED_DESKTOP_SIZE)]);
    assert_eq!(srv.stats().desktop_size_requests, [(800, 600)]);
    assert_eq!((srv.framebuffer().width, srv.framebuffer().height), (800, 600));

    let cfg = RfbConfig { allow_client_resize: false, ..RfbConfig::default() };
    let (_srv, mut c) = client_for(cfg, &encs).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("first");
    c.set_desktop_size(800, 600).await.expect("SetDesktopSize");
    c.request(true).await.expect("incremental");
    let rects = within(c.read_update()).await.expect("refusal");
    assert_eq!(
        rects,
        [(Rect::new(1, 1, 640, 480), encoding::EXTENDED_DESKTOP_SIZE)],
        "status 1 = prohibited"
    );
}

#[tokio::test]
async fn qemu_extended_key_is_confirmed_and_recorded() {
    let (srv, mut c) =
        client_for(RfbConfig::default(), &[encoding::RAW, encoding::QEMU_EXTENDED_KEY]).await;
    c.request(false).await.expect("request");
    let rects = within(c.read_update()).await.expect("first");
    assert_eq!(rects[0].1, encoding::QEMU_EXTENDED_KEY);
    let mut m = vec![255, 0, 0, 1];
    m.extend_from_slice(&0x61u32.to_be_bytes());
    m.extend_from_slice(&0x1Eu32.to_be_bytes());
    c.send_raw(&m).await.expect("qemu key");
    eventually(|| !srv.stats().key_events.is_empty()).await;
    let k = srv.stats().key_events[0];
    assert_eq!((k.down, k.keysym, k.qemu_keycode), (true, 0x61, Some(0x1E)));
}

#[tokio::test]
async fn pointer_key_and_client_cut_text_are_counted() {
    let (srv, mut c) = client_for(RfbConfig::default(), &[encoding::RAW]).await;
    c.pointer(1, 10, 20).await.expect("pointer");
    c.pointer(0, 11, 21).await.expect("pointer");
    c.key(true, 0xFF0D).await.expect("key");
    c.key(false, 0xFF0D).await.expect("key");
    c.cut_text(b"caf\xe9").await.expect("cut text");
    eventually(|| srv.stats().client_cut_text.len() == 1).await;
    let st = srv.stats();
    assert_eq!(st.pointer_events, 2);
    assert_eq!(st.last_pointer, Some((0, 11, 21)));
    assert_eq!(st.key_events.len(), 2);
    assert_eq!(st.client_cut_text, [b"caf\xe9".to_vec()]);
    assert_eq!(st.encodings, [encoding::RAW]);
    assert_eq!(st.pixel_formats, [rfb::PixelFormat::RGBX]);
}

#[tokio::test]
async fn server_cut_text_reaches_the_client_without_a_request() {
    let (srv, mut c) = client_for(RfbConfig::default(), &[encoding::RAW]).await;
    // Let the session subscribe before broadcasting.
    eventually(|| !srv.stats().encodings.is_empty()).await;
    srv.server_cut_text(b"hello \xfc");
    assert_eq!(
        within(c.read()).await.expect("cut text"),
        ServerMsg::CutText(b"hello \xfc".to_vec())
    );
}

#[tokio::test]
async fn oversized_client_cut_text_ends_the_connection() {
    let (srv, mut c) = client_for(RfbConfig::default(), &[encoding::RAW]).await;
    let mut m = vec![6, 0, 0, 0];
    m.extend_from_slice(&((1u32 << 20) + 1).to_be_bytes());
    c.send_raw(&m).await.expect("header");
    eventually(|| srv.stats().errors.iter().any(|e| e.contains("ClientCutText"))).await;
}

/// `w × h` RGBA pixels cycling through `colours` distinct colours.
fn pattern(w: u16, h: u16, colours: u8) -> Vec<u8> {
    (0..usize::from(w) * usize::from(h))
        .flat_map(|i| {
            let c = u8::try_from(i % usize::from(colours)).expect("small");
            [c.wrapping_mul(37), c.wrapping_mul(11), 200u8.wrapping_sub(c), 255]
        })
        .collect()
}

#[tokio::test]
async fn every_zrle_subencoding_and_tight_filter_is_exercised() {
    let small = || RfbConfig { width: 128, height: 64, ..RfbConfig::default() };
    let (srv, mut c) = client_for(small(), &[encoding::ZRLE]).await;
    srv.blit(Rect::new(0, 0, 64, 64), &pattern(64, 64, 3));
    srv.blit(Rect::new(64, 0, 64, 64), &pattern(64, 64, 50));
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("update");
    assert_eq!(c.fb, srv.framebuffer().rgba);
    srv.fill(Rect::new(0, 0, 64, 64), [1, 2, 3, 255]);
    srv.blit(Rect::new(64, 0, 64, 64), &pattern(64, 64, 2));
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("update");
    assert_eq!(c.fb, srv.framebuffer().rgba);
    assert_eq!(c.inflaters.zrle_subs, [3, 128 + 50, 1, 2]);

    let (srv, mut c) =
        client_for(RfbConfig { zrle_mode: ZrleMode::PlainRle, ..small() }, &[encoding::ZRLE]).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("update");
    assert_eq!(c.fb, srv.framebuffer().rgba);
    assert_eq!(c.inflaters.zrle_subs, [128, 128]);

    let (srv, mut c) = client_for(small(), &[encoding::TIGHT]).await;
    for colours in [1, 2, 5, 200] {
        srv.blit(Rect::new(0, 0, 128, 64), &pattern(128, 64, colours));
        c.request(false).await.expect("request");
        within(c.read_update()).await.expect("update");
        assert_eq!(c.fb, srv.framebuffer().rgba, "{colours} colours");
    }
    // fill, palette(2) and palette(5) on stream 1, copy on stream 0.
    assert_eq!(c.inflaters.tight_kinds, [(0x80, 0), (0x50, 1), (0x50, 1), (0x00, 0)]);

    let cfg = RfbConfig { tight_mode: TightMode::Gradient, ..small() };
    let (srv, mut c) = client_for(cfg, &[encoding::TIGHT]).await;
    c.request(false).await.expect("request");
    within(c.read_update()).await.expect("update");
    assert_eq!(c.fb, srv.framebuffer().rgba);
    assert_eq!(c.inflaters.tight_kinds, [(0x60, 2)]);
}
