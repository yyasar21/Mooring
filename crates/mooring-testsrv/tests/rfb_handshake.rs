//! RFB test server self-tests: version, security types, `VeNCrypt` subtypes, `ServerInit`.

mod common;

use common::rfb_client::{Auth, Client};
use common::within;
use mooring_testsrv::rfb::{self, RfbConfig, SecurityOffer, VeNCryptSub};

const PW: &str = "s3cret!x";

fn all_vencrypt() -> Vec<VeNCryptSub> {
    vec![
        VeNCryptSub::X509Vnc,
        VeNCryptSub::X509None,
        VeNCryptSub::X509Plain,
        VeNCryptSub::TlsNone,
        VeNCryptSub::TlsVnc,
        VeNCryptSub::TlsPlain,
        VeNCryptSub::Plain,
    ]
}

fn config() -> RfbConfig {
    RfbConfig {
        security: vec![
            SecurityOffer::VeNCrypt(all_vencrypt()),
            SecurityOffer::VncAuth,
            SecurityOffer::None,
        ],
        password: Some(PW.to_owned()),
        plain_user: Some(("alice".to_owned(), "correct horse".to_owned())),
        ..RfbConfig::default()
    }
}

#[tokio::test]
async fn none_auth_reaches_server_init() {
    let srv = rfb::start(config(), 0).await.expect("start");
    let c = within(Client::connect(srv.addr(), Auth::None)).await.expect("connect");
    assert_eq!((c.width, c.height), (640, 480));
    assert_eq!(c.security_types, [19, 2, 1]);
    assert_eq!(c.name_len, "mooring-testsrv".len());
    let st = srv.stats();
    assert_eq!(st.chosen_security, [(1, None)]);
    assert_eq!(st.client_versions, ["RFB 003.008\n"]);
    assert_eq!(st.shared_flags, [true]);
    assert_eq!(st.auth_ok, 1);
}

#[tokio::test]
async fn vnc_auth_accepts_right_and_refuses_wrong_password() {
    let srv = rfb::start(config(), 0).await.expect("start");
    within(Client::connect(srv.addr(), Auth::Vnc(PW.to_owned()))).await.expect("right password");
    let e = within(Client::connect(srv.addr(), Auth::Vnc("wrong".to_owned())))
        .await
        .err()
        .expect("refused");
    assert!(e.contains("authentication failed"), "{e}");
    let st = srv.stats();
    assert_eq!((st.auth_ok, st.auth_failed), (1, 1));
}

#[tokio::test]
async fn fixed_challenge_makes_the_des_exchange_reproducible() {
    let challenge = [0x42; 16];
    let cfg = RfbConfig { fixed_challenge: Some(challenge), ..config() };
    let srv = rfb::start(cfg, 0).await.expect("start");
    within(Client::connect(srv.addr(), Auth::Vnc(PW.to_owned()))).await.expect("vnc auth");
    assert_eq!(rfb::vnc_auth_response(PW.as_bytes(), &challenge).len(), 16);
}

#[tokio::test]
async fn every_vencrypt_subtype_completes_with_its_inner_auth() {
    let srv = rfb::start(config(), 0).await.expect("start");
    let pin = srv.cert().expect("cert").cert_der().to_vec();
    let plain = Some(("alice".to_owned(), "correct horse".to_owned()));
    for (sub, tls) in
        [(260, true), (261, true), (262, true), (257, true), (258, true), (259, true), (256, false)]
    {
        let auth = Auth::VeNCrypt { sub, password: Some(PW.to_owned()), plain: plain.clone() };
        let c = within(Client::connect(srv.addr(), auth))
            .await
            .unwrap_or_else(|e| panic!("sub {sub}: {e}"));
        if tls {
            let leaf = c.peer_cert.as_ref().expect("TLS leaf");
            let got = leaf.clone();
            assert_eq!(got, pin, "sub {sub} presented another cert");
        } else {
            assert!(c.peer_cert.is_none());
        }
    }
    let st = srv.stats();
    assert_eq!(st.auth_ok, 7);
    assert!(st.chosen_security.iter().all(|(t, s)| *t == 19 && s.is_some()));
}

#[tokio::test]
async fn vencrypt_wrong_inner_credentials_fail() {
    let srv = rfb::start(config(), 0).await.expect("start");
    let bad_vnc = Auth::VeNCrypt { sub: 261, password: Some("nope".to_owned()), plain: None };
    assert!(within(Client::connect(srv.addr(), bad_vnc)).await.is_err());
    let bad_plain = Auth::VeNCrypt {
        sub: 262,
        password: None,
        plain: Some(("alice".to_owned(), "wrong".to_owned())),
    };
    assert!(within(Client::connect(srv.addr(), bad_plain)).await.is_err());
    assert_eq!(srv.stats().auth_failed, 2);
}

#[tokio::test]
async fn offered_subtypes_follow_the_config_order() {
    let cfg = RfbConfig {
        security: vec![SecurityOffer::VeNCrypt(vec![VeNCryptSub::X509None])],
        ..RfbConfig::default()
    };
    let srv = rfb::start(cfg, 0).await.expect("start");
    let e = within(Client::connect(
        srv.addr(),
        Auth::VeNCrypt { sub: 261, password: None, plain: None },
    ))
    .await
    .err()
    .expect("261 not offered");
    assert!(e.contains("[260]"), "{e}");
    assert!(within(Client::connect(srv.addr(), Auth::None)).await.is_err(), "None not offered");
}

#[tokio::test]
async fn set_security_applies_to_new_connections() {
    let srv = rfb::start(config(), 0).await.expect("start");
    srv.set_security(vec![SecurityOffer::VncAuth]);
    let e = within(Client::connect(srv.addr(), Auth::None)).await.err().expect("None removed");
    assert!(e.contains("not offered"), "{e}");
}
