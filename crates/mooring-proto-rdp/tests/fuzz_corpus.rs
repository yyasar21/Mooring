//! Stable replay of the RDP fuzz corpora (`rdp_fastpath`, `rdp_certificate_info`,
//! `rdp_cliprdr_text`, `rdp_input`, `rdp_reassembly`, `rdp_reactivation`) and crash regressions through the same entry points the
//! cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/rdp_certificate_info.rs"]
mod certificate_info;
#[path = "../../../fuzz/entries/rdp_cliprdr_text.rs"]
mod cliprdr_text;
#[path = "../../../fuzz/entries/rdp_fastpath.rs"]
mod fastpath;
#[path = "../../../fuzz/entries/rdp_input.rs"]
mod input;
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
