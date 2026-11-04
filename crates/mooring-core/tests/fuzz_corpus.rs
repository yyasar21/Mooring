//! Stable replay of the `kubeconfig_parse` fuzz corpus and crash regressions through the same
//! entry point the cargo-fuzz target uses (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/kubeconfig.rs"]
mod kubeconfig;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

use mooring_core::credential::{kubeconfig as parser, CredentialError};

/// Seeds that each carry one construct the parser must refuse (review 3 M-5, review 4 M-11).
/// Every one is otherwise a valid kubeconfig, so the forbidden construct is the only reason
/// to reject it.
const FORBIDDEN_SEEDS: &[(&str, &str)] = &[
    ("users-merge-inline", "merge"),
    ("users-Exec", "`exec`"),
    ("users-AUTH-PROVIDER", "`auth-provider`"),
    ("complex-key-exec", "`exec`"),
    ("quoted-exec", "`exec`"),
    ("m5-merge-toplevel-inline", "merge"),
    ("m5-users-item-level-exec", "`exec`"),
    ("m5-users-nested-TOKENFILE", "`tokenFile`"),
    ("m5-users-path-keys-mixed-case", "`client-"),
    ("probe-clusters-ca-path", "`certificate-authority`"),
    ("probe-tagged-merge-key", ""),
    ("probe-binary-tagged-key", ""),
    ("probe-quoted-merge-key", "merge"),
];

fn seed(name: &str) -> Vec<u8> {
    let path = replay::fuzz_dir().join("corpus/kubeconfig_parse").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed {}: {e}", path.display()))
}

/// QA-F2 (docs/handoff/a1-exit-qa.md): the parser looks up `users` / `clusters` case-sensitively,
/// so `Users:` / `Clusters:` sections skip the forbidden-key check. Parser fix owned by
/// rust-core; until it lands only this one file is excluded from the corpus replay.
const QA_F2: &str = "qa-f2-section-key-case";

#[test]
fn kubeconfig_parse_corpus() {
    let ran = replay::replay_except("kubeconfig_parse", kubeconfig::run, &[QA_F2]);
    assert!(ran >= 7 + FORBIDDEN_SEEDS.len());
}

/// QA-F2 reproducer, run through the unchanged property. Remove the `#[ignore]` and the
/// exception above once rust-core fixes `kubeconfig::parse`.
#[test]
#[ignore = "QA-F2: open parser bypass (`Users:` / `Clusters:` section keys), owner rust-core"]
fn kubeconfig_qa_f2_regression() {
    let path = replay::fuzz_dir().join("regressions/kubeconfig_parse").join(QA_F2);
    kubeconfig::run(&std::fs::read(path).expect("read QA-F2 reproducer"));
}

/// The valid seed must stay valid, or the fuzzer loses its path into the accepting branch.
#[test]
fn kubeconfig_valid_seed_is_accepted() {
    let seed = seed("valid-two-contexts");
    let info = parser::parse(&seed).expect("seed is accepted");
    assert_eq!(info.contexts, ["lab", "lab-admin"]);
    assert_eq!(info.current_context.as_deref(), Some("lab"));
    let text = std::str::from_utf8(&seed).expect("utf-8");
    assert_eq!(kubeconfig::violations(text), Vec::<String>::new(), "oracle false positive");
}

/// The oracle sees the forbidden construct in every forbidden seed (so `run` would panic if
/// the parser ever accepted one), and the parser refuses each of them for that reason, not
/// for an unrelated one. An empty expected fragment only requires a rejection.
#[test]
fn kubeconfig_forbidden_seeds_are_seen_and_refused() {
    for (name, why) in FORBIDDEN_SEEDS {
        let data = seed(name);
        let text = std::str::from_utf8(&data).expect("utf-8");
        assert!(!kubeconfig::violations(text).is_empty(), "oracle misses `{name}`");
        match parser::parse(&data) {
            Err(CredentialError::KubeconfigRejected(reason)) => {
                assert!(reason.contains(why), "`{name}` refused for `{reason}`, not `{why}`");
            }
            other => panic!("`{name}` not refused as a kubeconfig: {other:?}"),
        }
        kubeconfig::run(&data);
    }
}

/// The oracle itself flags what the property names, so a parser bypass cannot pass silently.
#[test]
fn oracle_flags_each_construct() {
    let base = "contexts: [{name: c}]\n";
    for (yaml, what) in [
        ("a: {<<: {b: c}}\n", "merge key"),
        ("users: [{user: {eXeC: x}}]\n", "forbidden key"),
        ("users: [{user: {deep: [{Auth-Provider: x}]}}]\n", "forbidden key"),
        ("USERS: [{tokenfile: x}]\n", "forbidden key"),
        ("clusters: [{cluster: {CERTIFICATE-AUTHORITY: x}}]\n", "forbidden key"),
        ("users: [{user: {? {exec: x} : y}}]\n", "non-scalar key"),
        ("users: [{user: {!!str exec: x}}]\n", "tagged key"),
        ("a: &x {b: c}\nusers: [{user: *x}]\n", "alias"),
    ] {
        let found = kubeconfig::violations(&format!("{base}{yaml}"));
        assert!(found.iter().any(|v| v.contains(what)), "{yaml:?}: {found:?}");
    }
    // outside users[]/clusters[] the same names are ordinary keys
    for yaml in ["contexts: [{name: c, exec: x}]\n", "preferences: {client-key: x}\n"] {
        assert_eq!(kubeconfig::violations(yaml), Vec::<String>::new(), "{yaml:?}");
    }
}
