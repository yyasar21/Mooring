//! Stable replay of the VNC fuzz corpora (`rfb_server_msg`, `vnc_zrle`, `vnc_tight`,
//! `rfb_handshake`, `vencrypt_negotiation`, `cut_text`) and crash
//! regressions through the same entry points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/cut_text.rs"]
mod cut_text;
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

/// Review 5 L-28: `ServerCutText` + Latin-1 converters.
#[test]
fn cut_text_corpus() {
    assert!(replay::replay("cut_text", cut_text::run) >= 5);
}

/// The framed seed must keep parsing as a `CutText` with the controls dropped, or the fuzzer
/// only explores the converter.
#[test]
fn cut_text_seed_is_a_cut_text_message() {
    use mooring_proto_vnc::{parse_server_message, Parsed, ServerMessage};
    let s = seed("cut_text", "framed-controls");
    let mut msg = vec![3, 0, 0, 0];
    msg.extend_from_slice(&u32::try_from(s.len() - 1).expect("u32").to_be_bytes());
    msg.extend_from_slice(&s[1..]);
    let Ok(Parsed::Done(ServerMessage::CutText(t), used)) = parse_server_message(&msg) else {
        panic!("not a cut text");
    };
    assert_eq!((t.as_str(), used), ("abcdef\n", msg.len()));
}

/// The full handshake seed must reach `ServerInit`, or the fuzzer only explores the version.
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

/// A few thousand pseudo-random inputs through the entry on stable (a cheap stand-in for a
/// nightly run; the seeds above cover the interesting paths). Deterministic xorshift, so a
/// failure reproduces.
#[test]
fn cut_text_random_smoke() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..3000 {
        let len = usize::try_from(next() % 200).expect("usize");
        let data: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        cut_text::run(&data);
    }
}
