//! Stable replay of the VNC fuzz corpora (`rfb_server_msg`, `vnc_zrle`, `vnc_tight`) and crash
//! regressions through the same entry points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/rfb_server_msg.rs"]
mod server_msg;
#[path = "../../../fuzz/entries/vnc_tight.rs"]
mod tight;
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
    let mut d = flate2::Decompress::new(true);
    let px = mooring_proto_vnc::decode_zrle(&mut d, &z[2..], 4, 4).expect("zrle seed");
    assert_eq!(&px[..3], &[7, 8, 9]);
    let t = seed("vnc_tight", "fill");
    let mut s = mooring_proto_vnc::TightStreams::default();
    assert!(mooring_proto_vnc::decode_tight(&mut s, &t[2..], 8, 8).is_ok());
}
