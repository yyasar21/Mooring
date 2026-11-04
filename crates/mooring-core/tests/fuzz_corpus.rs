//! Stable replay of the `kubeconfig_parse` fuzz corpus and crash regressions through the same
//! entry point the cargo-fuzz target uses (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/kubeconfig.rs"]
mod kubeconfig;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

#[test]
fn kubeconfig_parse_corpus() {
    assert!(replay::replay("kubeconfig_parse", kubeconfig::run) >= 7);
}

/// The valid seed must stay valid, or the fuzzer loses its path into the accepting branch.
#[test]
fn kubeconfig_valid_seed_is_accepted() {
    let path = replay::fuzz_dir().join("corpus/kubeconfig_parse/valid-two-contexts");
    let seed = std::fs::read(path).expect("read seed");
    let info = mooring_core::credential::kubeconfig::parse(&seed).expect("seed is accepted");
    assert_eq!(info.contexts, ["lab", "lab-admin"]);
    assert_eq!(info.current_context.as_deref(), Some("lab"));
}
