//! Stable replay of the A5 `mooring-core` fuzz corpora (`op_reference_parse`, `sk_key_parse`)
//! and crash regressions through the same entry points the cargo-fuzz targets use, plus the
//! fuzz inventory gate: every cargo-fuzz target runs nightly and has seeds (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/op_reference_parse.rs"]
mod op_reference_parse;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/sk_key_parse.rs"]
mod sk_key_parse;

use mooring_core::credential::sk_key::{parse_sk_key_handle, parse_sk_public_line};
use mooring_core::credential::{parse_bws_reference, parse_op_reference, testdata, BwsReference};

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

fn text(target: &str, name: &str) -> String {
    String::from_utf8(seed(target, name)).expect("utf-8 seed")
}

#[test]
fn op_reference_parse_corpus() {
    assert!(replay::replay("op_reference_parse", op_reference_parse::run) >= 6);
}

/// Each grammar has an accepted seed of every shape and a refused one, so the fuzzer starts on
/// both sides of the round-trip assertion.
#[test]
fn op_reference_seeds_cover_both_grammars() {
    for (name, section, field) in [
        ("op-field", None, Some("password")),
        ("op-section-field", Some("admin"), Some("password")),
        ("op-item", None, None),
    ] {
        let r = parse_op_reference(&text("op_reference_parse", name)).expect(name);
        assert_eq!((r.section.as_deref(), r.field.as_deref()), (section, field), "{name}");
    }
    assert!(parse_op_reference(&text("op_reference_parse", "op-query-refused")).is_err());
    assert!(matches!(
        parse_bws_reference(&text("op_reference_parse", "bws-id")),
        Ok(BwsReference::Id(_))
    ));
    assert!(matches!(
        parse_bws_reference(&text("op_reference_parse", "bws-project-key")),
        Ok(BwsReference::ProjectKey { .. })
    ));
}

#[test]
fn sk_key_parse_corpus() {
    assert!(replay::replay("sk_key_parse", sk_key_parse::run) >= 6);
}

/// Both `sk-*` lines parse to their fingerprint's key; a plain Ed25519 line and a non-`ssh:`
/// application are refused.
#[test]
fn sk_key_seeds_split_accept_and_refuse() {
    for name in ["ed25519-sk-line", "ecdsa-sk-line"] {
        let k = parse_sk_public_line(text("sk_key_parse", name).trim_end()).expect(name);
        assert!(k.fingerprint.starts_with("SHA256:"), "{name}");
        assert_eq!(k.application, "ssh:", "{name}");
    }
    assert!(parse_sk_public_line(text("sk_key_parse", "plain-ed25519-line").trim_end()).is_err());
    assert!(mooring_core::credential::sk_key::parse_sk_public_blob(&seed(
        "sk_key_parse",
        "app-not-ssh"
    ))
    .is_err());
}

/// The key-handle file (`id_ed25519_sk`) is PEM-armoured like a private key, so it is never
/// committed (secret scanning); it is built here from the shared fixture and run through the
/// entry, which must accept it. Copy it into a local corpus by hand to seed a nightly run.
#[test]
fn sk_key_handle_built_at_test_time_parses_through_the_entry() {
    let public = testdata::sk_ed25519_public([7; 32], "ssh:");
    let pem = testdata::sk_key_handle_pem(&public, 0x01, b"handle-bytes-for-tests");
    assert!(!pem.is_empty());
    let h = parse_sk_key_handle(pem.as_bytes()).expect("fixture handle parses");
    assert_eq!((h.flags, h.encrypted), (Some(0x01), false));
    sk_key_parse::run(pem.as_bytes());
    let mut cut = pem.into_bytes();
    cut.truncate(cut.len() / 2);
    sk_key_parse::run(&cut);
}

/// Every `[[bin]]` of `fuzz/Cargo.toml` is in the nightly matrix, has a non-empty seed corpus
/// and a regressions directory: a target added without them would never run.
#[test]
fn every_fuzz_target_runs_nightly_with_seeds() {
    let fuzz = replay::fuzz_dir();
    let manifest = std::fs::read_to_string(fuzz.join("Cargo.toml")).expect("fuzz manifest");
    let nightly = std::fs::read_to_string(fuzz.join("../.github/workflows/fuzz-nightly.yml"))
        .expect("nightly workflow");
    let matrix: Vec<&str> =
        nightly.lines().filter_map(|l| l.trim().strip_prefix("- ")).map(str::trim).collect();
    let mut targets = 0;
    let mut lines = manifest.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "[[bin]]" {
            continue;
        }
        let name = lines
            .next()
            .and_then(|l| l.trim().strip_prefix("name = \""))
            .and_then(|l| l.strip_suffix('"'))
            .expect("`name` right after [[bin]]");
        assert!(matrix.contains(&name), "fuzz target `{name}` is missing from fuzz-nightly.yml");
        let corpus = fuzz.join("corpus").join(name);
        let seeds = std::fs::read_dir(&corpus).map_or(0, Iterator::count);
        assert!(seeds > 0, "fuzz target `{name}` has no seeds in {}", corpus.display());
        assert!(fuzz.join("regressions").join(name).is_dir(), "`{name}`: no regressions dir");
        targets += 1;
    }
    assert!(targets >= 66, "only {targets} fuzz targets found");
}
