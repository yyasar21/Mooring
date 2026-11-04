//! Stable replay of the VNC fuzz corpora (`rfb_server_msg`, `vnc_zrle`, `vnc_tight`,
//! `rfb_handshake`, `vencrypt_negotiation`) and crash
//! regressions through the same entry points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/rfb_handshake.rs"]
mod rfb_handshake;
#[path = "../../../fuzz/entries/rfb_server_msg.rs"]
mod server_msg;
#[path = "../../../fuzz/entries/vnc_tight.rs"]
mod tight;
#[path = "../../../fuzz/entries/vencrypt_negotiation.rs"]
mod vencrypt_negotiation;
#[path = "../../../fuzz/entries/vnc_zrle.rs"]
mod zrle;

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn rfb_server_msg_corpus() {
    assert!(replay::replay("rfb_server_msg", server_msg::run) >= 5);
}

#[test]
fn vnc_zrle_corpus() {
    assert!(replay::replay("vnc_zrle", zrle::run) >= 2);
}

#[test]
fn vnc_tight_corpus() {
    assert!(replay::replay("vnc_tight", tight::run) >= 3);
}

/// The ZRLE and Tight seeds must keep decoding, or the fuzzer only explores refusals.
#[test]
fn decoder_seeds_decode() {
    let z = seed("vnc_zrle", "solid");
    let mut d = mooring_proto_vnc::decode::ZStream::new();
    let px = mooring_proto_vnc::decode_zrle(&mut d, &z[2..], 4, 4).expect("zrle seed");
    assert_eq!(&px[..3], &[7, 8, 9]);
    let t = seed("vnc_tight", "fill");
    let mut s = mooring_proto_vnc::TightStreams::default();
    assert!(mooring_proto_vnc::decode_tight(&mut s, &t[2..], 8, 8).is_ok());
}

#[test]
fn rfb_handshake_corpus() {
    assert!(replay::replay("rfb_handshake", rfb_handshake::run) >= 3);
}

#[test]
fn vencrypt_negotiation_corpus() {
    assert!(replay::replay("vencrypt_negotiation", vencrypt_negotiation::run) >= 2);
}

/// The full handshake seed must reach ServerInit, or the fuzzer only explores the version.
#[test]
fn handshake_seed_reaches_server_init() {
    use mooring_proto_vnc::handshake::{
        parse_security_result, parse_security_types, parse_server_init, parse_version,
    };
    use mooring_proto_vnc::Parsed;
    let s = seed("rfb_handshake", "full");
    let Ok(Parsed::Done(_, a)) = parse_version(&s) else { panic!("version") };
    let Ok(Parsed::Done(types, b)) = parse_security_types(&s[a..]) else { panic!("types") };
    assert_eq!(types, vec![1, 2, 19]);
    let Ok(Parsed::Done((), c)) = parse_security_result(&s[a + b..]) else { panic!("result") };
    let Ok(Parsed::Done(init, _)) = parse_server_init(&s[a + b + c..]) else { panic!("init") };
    assert_eq!((init.width, init.height, init.name.as_str()), (1024, 768, "test"));
}
