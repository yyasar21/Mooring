//! Stable replay of the `vault_header_from_bytes` and `import_age` fuzz corpora and crash
//! regressions through the same entry points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/import_age.rs"]
mod import_age;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/vault_header.rs"]
mod vault_header;

#[test]
fn vault_header_from_bytes_corpus() {
    assert!(replay::replay("vault_header_from_bytes", vault_header::run) >= 5);
}

#[test]
fn import_age_corpus() {
    assert!(replay::replay("import_age", import_age::run) >= 6);
}

/// The vector seeds must keep decrypting / parsing, or the fuzzer never reaches the JSON and
/// header checks behind them.
#[test]
fn vector_seeds_are_accepted() {
    let corpus = replay::fuzz_dir().join("corpus");
    let pass = secrecy::SecretString::from("nexus-export-vector-passphrase".to_owned());
    for name in ["vector-armored", "vector-binary"] {
        let seed = std::fs::read(corpus.join("import_age").join(name)).expect("read seed");
        mooring_vault::import_age(&seed, &pass).expect("vector seed decrypts");
    }
    let header = std::fs::read(corpus.join("vault_header_from_bytes/vector-v2")).expect("read");
    mooring_vault::Header::from_bytes(&header).expect("vector header seed is accepted");
}
