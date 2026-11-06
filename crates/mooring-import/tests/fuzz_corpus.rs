//! Stable replay of the importer fuzz corpora (`import_*`) and crash regressions through the
//! same entry points the cargo-fuzz targets use (docs/qa/fuzzing.md, A4 targets). Also pins
//! that the fixture seeds keep being accepted, so the fuzzer never loses its path past the
//! format checks.

#[path = "../../../fuzz/entries/import_detect.rs"]
mod import_detect;
#[path = "../../../fuzz/entries/import_mremoteng.rs"]
mod import_mremoteng;
#[path = "../../../fuzz/entries/import_putty_reg.rs"]
mod import_putty_reg;
#[path = "../../../fuzz/entries/import_putty_session.rs"]
mod import_putty_session;
#[path = "../../../fuzz/entries/import_rdm.rs"]
mod import_rdm;
#[path = "../../../fuzz/entries/import_royalts.rs"]
mod import_royalts;
#[path = "../../../fuzz/entries/import_ssh_config.rs"]
mod import_ssh_config;
#[path = "../../../fuzz/entries/import_termius_csv.rs"]
mod import_termius_csv;
#[path = "../../../fuzz/entries/import_termius_json.rs"]
mod import_termius_json;
#[path = "../../../fuzz/entries/ldap_ber_response.rs"]
mod ldap_ber_response;
#[path = "../../../fuzz/entries/ldap_filter_escape.rs"]
mod ldap_filter_escape;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

use mooring_import::{detect, parse, ImportFormat, ImportOptions, ImportSource};

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn corpora_replay() {
    assert!(replay::replay("import_royalts", import_royalts::run) >= 3);
    assert!(replay::replay("import_rdm", import_rdm::run) >= 3);
    assert!(replay::replay("import_termius_csv", import_termius_csv::run) >= 3);
    assert!(replay::replay("import_termius_json", import_termius_json::run) >= 3);
    assert!(replay::replay("import_mremoteng", import_mremoteng::run) >= 3);
    assert!(replay::replay("import_putty_reg", import_putty_reg::run) >= 3);
    assert!(replay::replay("import_putty_session", import_putty_session::run) >= 1);
    assert!(replay::replay("import_ssh_config", import_ssh_config::run) >= 3);
    assert!(replay::replay("import_detect", import_detect::run) >= 8);
    assert!(replay::replay("ldap_filter_escape", ldap_filter_escape::run) >= 5);
    assert!(replay::replay("ldap_ber_response", ldap_ber_response::run) >= 6);
}

/// Every `fixture-plain` seed (opt-in byte stripped) parses to a plan with connections, and
/// `detect` names the right format for each.
#[test]
fn fixture_seeds_are_accepted() {
    let cases = [
        ("import_royalts", "x.rtsx", ImportFormat::RoyalTs),
        ("import_rdm", "x.rdm", ImportFormat::Rdm),
        ("import_termius_csv", "x.csv", ImportFormat::Termius),
        ("import_termius_json", "x.json", ImportFormat::Termius),
        ("import_mremoteng", "confCons.xml", ImportFormat::Mremoteng),
        ("import_putty_reg", "x.reg", ImportFormat::Putty),
        ("import_ssh_config", "config", ImportFormat::Openssh),
    ];
    for (target, name, format) in cases {
        let bytes = seed(target, "fixture-plain");
        let body = &bytes[1..];
        assert_eq!(detect(body, name), Some(format), "{target}");
        assert_eq!(detect(body, "unknown"), Some(format), "{target} by content");
        let plan =
            parse(format, ImportSource::File { name, bytes: body }, &ImportOptions::default())
                .unwrap_or_else(|e| panic!("{target}: {e}"));
        assert!(plan.counts().connections >= 2, "{target}");
        assert_eq!(plan.counts().secrets, 0, "{target}: no secret without the opt-in");
    }
}
