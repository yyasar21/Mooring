//! Stable replay of the RDP fuzz corpora (`rdp_fastpath`, `rdp_certificate_info`,
//! `rdp_cliprdr_text`, `rdp_input`, `rdp_reassembly`, `rdp_reactivation`) and the RD Gateway
//! corpora (`rdg_pdu`, `rdg_http_response`) and crash regressions through the same entry points
//! the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/rdp_certificate_info.rs"]
mod certificate_info;
#[path = "../../../fuzz/entries/rdp_cliprdr_text.rs"]
mod cliprdr_text;
#[path = "../../../fuzz/entries/rdp_fastpath.rs"]
mod fastpath;
#[path = "../../../fuzz/entries/rdp_input.rs"]
mod input;
#[path = "../../../fuzz/entries/rdg_http_response.rs"]
mod rdg_http_response;
#[path = "../../../fuzz/entries/rdg_pdu.rs"]
mod rdg_pdu;
#[path = "../../../fuzz/entries/rdp_reactivation.rs"]
mod reactivation;
#[path = "../../../fuzz/entries/rdp_reassembly.rs"]
mod reassembly;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

#[test]
fn rdp_fastpath_corpus() {
    assert!(replay::replay("rdp_fastpath", fastpath::run) >= 2);
}

#[test]
fn rdp_certificate_info_corpus() {
    assert!(replay::replay("rdp_certificate_info", certificate_info::run) >= 2);
}

/// The certificate seed must stay parseable, or the fuzzer never reaches the field decoders.
#[test]
fn rdp_certificate_seed_parses() {
    let der =
        std::fs::read(replay::fuzz_dir().join("corpus/rdp_certificate_info/self-signed-p256"))
            .expect("seed");
    let info = mooring_proto_rdp::cert::certificate_info(
        &der,
        "rdp.example.test",
        time::OffsetDateTime::now_utc(),
        &[],
    )
    .expect("seed parses");
    assert!(info.san.iter().any(|s| s.contains("rdp.example.test")), "{:?}", info.san);
}

#[test]
fn rdp_cliprdr_text_corpus() {
    assert!(replay::replay("rdp_cliprdr_text", cliprdr_text::run) >= 2);
}

#[test]
fn rdp_input_corpus() {
    assert!(replay::replay("rdp_input", input::run) >= 2);
}

#[test]
fn rdp_reassembly_corpus() {
    assert!(replay::replay("rdp_reassembly", reassembly::run) >= 4);
}

#[test]
fn rdp_reactivation_corpus() {
    assert!(replay::replay("rdp_reactivation", reactivation::run) >= 5);
}

/// The full-sequence seeds must keep finalizing (Demand Active → Synchronize → Control ×2 →
/// Font Map), or the fuzzer never reaches `check_desktop` / `ActiveStage::reactivate`; the
/// oversized desktop must be refused there, and a hostile prefix must stop the sequence.
#[test]
fn rdp_reactivation_seeds_reach_the_reactivation_branch() {
    let seed = |name: &str| {
        std::fs::read(replay::fuzz_dir().join("corpus/rdp_reactivation").join(name)).expect("seed")
    };
    let outcome = mooring_proto_rdp::fuzz::reactivation_outcome;
    assert_eq!(outcome(&seed("demand-active-finalized")), Some((1024, 768)));
    assert_eq!(outcome(&seed("deactivate-then-demand")), Some((1280, 800)));
    assert_eq!(outcome(&seed("oversize-desktop")), None);
    assert_eq!(outcome(&seed("truncated")), None);
    assert_eq!(outcome(&seed("error-info")), None);
}

#[test]
fn rdg_pdu_corpus() {
    assert!(replay::replay("rdg_pdu", rdg_pdu::run) >= 7);
}

#[test]
fn rdg_http_response_corpus() {
    assert!(replay::replay("rdg_http_response", rdg_http_response::run) >= 5);
}

/// The gateway's whole server flow must keep decoding packet by packet, and the masked
/// WebSocket seed must unwrap to the client flow, or the fuzzer only explores refusals.
#[test]
fn rdg_pdu_seeds_decode() {
    use mooring_proto_rdp::gateway::{pdu, ws};
    let seed = |name: &str| {
        std::fs::read(replay::fuzz_dir().join("corpus/rdg_pdu").join(name)).expect("seed")
    };
    let flow = seed("server-flow");
    let (mut rest, mut kinds) = (&flow[..], Vec::new());
    while let Some(n) = pdu::peek_len(rest).expect("length") {
        kinds.push(pdu::decode(&rest[..n]).expect("packet"));
        rest = &rest[n..];
    }
    assert!(rest.is_empty());
    assert_eq!(kinds.len(), 8, "{kinds:?}");
    assert!(matches!(kinds[3], pdu::Packet::ChannelResponse { error: 0, channel_id: Some(7) }));
    assert!(pdu::peek_len(&seed("bad-length")).is_err());
    let client = seed("client-flow");
    let masked = seed("ws-binary-masked");
    let (frame, used) = ws::Decoder::new(true).decode(&masked).expect("frame").expect("whole");
    assert_eq!(used, masked.len());
    assert_eq!(frame, ws::Frame::Binary(client));
}

/// The 401 seed offers NTLM with a token and Negotiate; the Basic seed only Basic; the upgrade
/// seed is a 101 with the WebSocket upgrade token.
#[test]
fn rdg_http_seeds_reach_the_challenges() {
    use mooring_proto_rdp::gateway::http;
    let head = |name: &str| {
        let b = std::fs::read(replay::fuzz_dir().join("corpus/rdg_http_response").join(name))
            .expect("seed");
        let end = http::head_end(&b).expect("head").expect("complete");
        http::parse_head(&b[..end]).expect("parses")
    };
    let up = head("upgrade-101");
    assert!(up.status == 101 && up.has_token("upgrade", "websocket"));
    let c = http::challenges(&head("ntlm-401")).expect("challenges");
    assert!(c.ntlm && c.negotiate && !c.basic && c.ntlm_token.is_some());
    let b = http::challenges(&head("basic-401")).expect("challenges");
    assert!(b.basic && !b.ntlm);
    assert!(http::challenges(&head("ntlm-bad-base64")).is_none(), "a bad NTLM token is refused");
}
