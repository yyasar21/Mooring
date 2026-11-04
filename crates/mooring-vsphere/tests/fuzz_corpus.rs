//! Stable replay of the vSphere fuzz corpora (`vsphere_inventory_json`,
//! `vsphere_session_token`, `vsphere_ticket_url`) and crash regressions through the same entry
//! points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/replay.rs"]
mod replay;
#[path = "../../../fuzz/entries/vsphere_inventory_json.rs"]
mod vsphere_inventory_json;
#[path = "../../../fuzz/entries/vsphere_session_token.rs"]
mod vsphere_session_token;
#[path = "../../../fuzz/entries/vsphere_ticket_url.rs"]
mod vsphere_ticket_url;

use mooring_vsphere::{parse_session_token, parse_vmrc_ticket, MoId};

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn vsphere_inventory_json_corpus() {
    assert!(replay::replay("vsphere_inventory_json", vsphere_inventory_json::run) >= 7);
}

#[test]
fn vsphere_session_token_corpus() {
    assert!(replay::replay("vsphere_session_token", vsphere_session_token::run) >= 1);
}

/// The session seed must keep parsing, or the fuzzer only explores refusals.
#[test]
fn session_seed_is_accepted() {
    let t = parse_session_token(&seed("vsphere_session_token", "session")).expect("token");
    assert_eq!(t.len(), 32);
}

#[test]
fn vsphere_ticket_url_corpus() {
    assert!(replay::replay("vsphere_ticket_url", vsphere_ticket_url::run) >= 3);
}

/// The VMRC seed is accepted against the fuzz entry's fixed host and VM; the other-host and
/// WebMKS seeds are refused.
#[test]
fn ticket_seeds_split_accept_and_refuse() {
    let vm = MoId::new("vm-42").expect("id");
    let text = |n: &str| String::from_utf8(seed("vsphere_ticket_url", n)).expect("utf-8");
    assert!(parse_vmrc_ticket(&text("vmrc"), "vc.example.test", &vm).is_ok());
    assert!(parse_vmrc_ticket(&text("wrong-host"), "vc.example.test", &vm).is_err());
    assert!(parse_vmrc_ticket(&text("webmks"), "vc.example.test", &vm).is_err());
}
