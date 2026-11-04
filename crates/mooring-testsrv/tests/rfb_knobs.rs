//! RFB test server self-tests for the hostile knobs: each knob must produce exactly the wire
//! behaviour the product client's negative tests rely on.

mod common;

use std::time::{Duration, Instant};

use common::rfb_client::{Auth, Client};
use common::{eventually, within};
use mooring_testsrv::rfb::{self, encoding, Knobs, RfbConfig, SecurityOffer, VeNCryptSub};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn knobs(k: Knobs) -> RfbConfig {
    RfbConfig { knobs: k, ..RfbConfig::default() }
}

async fn ready(cfg: RfbConfig, encs: &[i32]) -> (rfb::RfbHandle, Client) {
    let srv = rfb::start(cfg, 0).await.expect("start");
    let mut c = within(Client::connect(srv.addr(), Auth::None)).await.expect("connect");
    c.set_encodings(encs).await.expect("encodings");
    (srv, c)
}

#[tokio::test]
async fn version_override_is_sent_verbatim() {
    let srv = rfb::start(knobs(Knobs { version: Some(*b"RFB 003.003\n"), ..Knobs::default() }), 0)
        .await
        .expect("start");
    let mut s = TcpStream::connect(srv.addr()).await.expect("tcp");
    let mut v = [0u8; 12];
    within(s.read_exact(&mut v)).await.expect("version");
    assert_eq!(&v, b"RFB 003.003\n");
}

#[tokio::test]
async fn strip_tls_after_pin_removes_vencrypt_from_later_connections() {
    let cfg = RfbConfig {
        security: vec![SecurityOffer::VeNCrypt(vec![VeNCryptSub::X509None]), SecurityOffer::None],
        knobs: Knobs { strip_tls_after: Some(1), ..Knobs::default() },
        ..RfbConfig::default()
    };
    let srv = rfb::start(cfg, 0).await.expect("start");
    let first = within(Client::connect(
        srv.addr(),
        Auth::VeNCrypt { sub: 260, password: None, plain: None },
    ))
    .await
    .expect("first, with TLS");
    assert_eq!(first.security_types, [19, 1]);
    let second = within(Client::connect(srv.addr(), Auth::None)).await.expect("second");
    assert_eq!(second.security_types, [1], "VeNCrypt stripped");
}

#[tokio::test]
async fn slow_loris_drips_the_handshake() {
    let cfg = knobs(Knobs { slow_loris: Some(Duration::from_millis(20)), ..Knobs::default() });
    let srv = rfb::start(cfg, 0).await.expect("start");
    let t = Instant::now();
    let mut s = TcpStream::connect(srv.addr()).await.expect("tcp");
    let mut v = [0u8; 12];
    within(s.read_exact(&mut v)).await.expect("version");
    assert!(t.elapsed() >= Duration::from_millis(200), "{:?}", t.elapsed());
}

#[tokio::test]
async fn oversized_rect_extends_past_the_framebuffer() {
    let (_srv, mut c) =
        ready(knobs(Knobs { oversized_rect: Some(10), ..Knobs::default() }), &[encoding::RAW])
            .await;
    c.request(false).await.expect("request");
    let e = within(c.read_update()).await.expect_err("rejected");
    assert!(e.contains("outside 640x480"), "{e}");
}

#[tokio::test]
async fn lie_zlib_length_replaces_the_length_field() {
    let (_srv, mut c) =
        ready(knobs(Knobs { lie_zlib_length: Some(7), ..Knobs::default() }), &[encoding::ZRLE])
            .await;
    c.request(false).await.expect("request");
    let head = within(c.read_bytes(4 + 12 + 4)).await.expect("header");
    assert_eq!(&head[12..16], &encoding::ZRLE.to_be_bytes());
    assert_eq!(&head[16..20], &7u32.to_be_bytes());
}

#[tokio::test]
async fn lie_cut_text_length_claims_a_huge_payload() {
    let (srv, mut c) =
        ready(knobs(Knobs { lie_cut_text_length: Some(u32::MAX), ..Knobs::default() }), &[0]).await;
    eventually(|| !srv.stats().encodings.is_empty()).await;
    srv.server_cut_text(b"x");
    let e = within(c.read()).await.expect_err("rejected");
    assert!(e.contains("ServerCutText of 4294967295"), "{e}");
}

#[tokio::test]
async fn missing_rects_announces_more_than_it_sends() {
    let (_srv, mut c) =
        ready(knobs(Knobs { missing_rects: Some(3), ..Knobs::default() }), &[encoding::RAW]).await;
    c.request(false).await.expect("request");
    let head = within(c.read_bytes(4)).await.expect("header");
    assert_eq!(head, [0, 0, 0, 4], "1 real rect + 3 missing");
}

#[tokio::test]
async fn last_rect_terminates_an_open_ended_update() {
    let (srv, mut c) =
        ready(knobs(Knobs { use_last_rect: true, ..Knobs::default() }), &[encoding::RAW]).await;
    c.request(false).await.expect("request");
    let rects = within(c.read_update()).await.expect("update");
    assert_eq!(rects.last().map(|r| r.1), Some(encoding::LAST_RECT));
    assert_eq!(c.fb, srv.framebuffer().rgba);
}

#[tokio::test]
async fn force_encoding_ignores_the_client_list() {
    let (_srv, mut c) =
        ready(knobs(Knobs { force_encoding: Some(encoding::ZRLE), ..Knobs::default() }), &[0])
            .await;
    c.request(false).await.expect("request");
    let rects = within(c.read_update()).await.expect("update");
    assert!(rects.iter().all(|r| r.1 == encoding::ZRLE));
}

#[tokio::test]
async fn tight_jpeg_sends_the_jpeg_control_byte() {
    let (_srv, mut c) =
        ready(knobs(Knobs { tight_jpeg: true, ..Knobs::default() }), &[encoding::TIGHT]).await;
    c.request(false).await.expect("request");
    let e = within(c.read_update()).await.expect_err("rejected");
    assert!(e.contains("0x90"), "{e}");
}

#[tokio::test]
async fn fail_auth_reason_fails_after_a_correct_password() {
    let cfg = RfbConfig {
        security: vec![SecurityOffer::VncAuth],
        password: Some("pw".to_owned()),
        knobs: Knobs { fail_auth_reason: Some("account locked".to_owned()), ..Knobs::default() },
        ..RfbConfig::default()
    };
    let srv = rfb::start(cfg, 0).await.expect("start");
    let e = within(Client::connect(srv.addr(), Auth::Vnc("pw".to_owned())))
        .await
        .err()
        .expect("failed");
    assert!(e.contains("account locked"), "{e}");
}

#[tokio::test]
async fn huge_name_is_sent_in_server_init() {
    let srv = rfb::start(knobs(Knobs { huge_name: Some(70_000), ..Knobs::default() }), 0)
        .await
        .expect("start");
    let c = within(Client::connect(srv.addr(), Auth::None)).await.expect("connect");
    assert_eq!(c.name_len, 70_000);
}

#[tokio::test]
async fn protocol_violations_are_recorded() {
    let (srv, mut c) = ready(RfbConfig::default(), &[0]).await;
    let mut colour_map = vec![0, 0, 0, 0];
    colour_map.extend_from_slice(&[8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    c.send_raw(&colour_map).await.expect("SetPixelFormat");
    eventually(|| srv.stats().errors.iter().any(|e| e.contains("unsupported pixel format"))).await;

    let (srv, mut c) = ready(RfbConfig::default(), &[0]).await;
    c.send_raw(&[77]).await.expect("junk");
    eventually(|| srv.stats().errors.iter().any(|e| e.contains("unknown client message 77"))).await;

    let srv = rfb::start(RfbConfig::default(), 0).await.expect("start");
    let mut s = TcpStream::connect(srv.addr()).await.expect("tcp");
    let mut v = [0u8; 12];
    s.read_exact(&mut v).await.expect("version");
    s.write_all(b"RFB 003.008\n").await.expect("version");
    let mut list = [0u8; 2];
    s.read_exact(&mut list).await.expect("list");
    s.write_all(&[2]).await.expect("choose VncAuth");
    eventually(|| srv.stats().errors.iter().any(|e| e.contains("type 2, not offered"))).await;
    assert_eq!(srv.stats().chosen_security, [(2, None)]);
}
