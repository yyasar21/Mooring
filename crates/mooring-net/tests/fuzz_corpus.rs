//! Stable replay of the network-tool fuzz corpora (`net_ping_output`,
//! `net_traceroute_output`, `net_wg_output`) and crash regressions through the same entry
//! points the cargo-fuzz targets use (docs/qa/fuzzing.md).

#[path = "../../../fuzz/entries/net_ping_output.rs"]
mod net_ping_output;
#[path = "../../../fuzz/entries/net_traceroute_output.rs"]
mod net_traceroute_output;
#[path = "../../../fuzz/entries/net_wg_output.rs"]
mod net_wg_output;
#[path = "../../../fuzz/entries/replay.rs"]
mod replay;

use mooring_net::{parse_ping, parse_traceroute, parse_wg, Iface, WgQuery, WgResult};

fn seed(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(replay::fuzz_dir().join("corpus").join(target).join(name)).expect("seed")
}

#[test]
fn net_ping_output_corpus() {
    assert!(replay::replay("net_ping_output", net_ping_output::run) >= 5);
}

#[test]
fn net_traceroute_output_corpus() {
    assert!(replay::replay("net_traceroute_output", net_traceroute_output::run) >= 4);
}

#[test]
fn net_wg_output_corpus() {
    assert!(replay::replay("net_wg_output", net_wg_output::run) >= 6);
}

/// The well-formed seeds must keep parsing into a summary (the fuzzer must keep a path past
/// the "no numbers found" branch), and the hostile ones must stay clean.
#[test]
fn seeds_keep_their_shape() {
    for name in ["iputils", "bsd", "windows-en", "windows-tr"] {
        let r = parse_ping(&seed("net_ping_output", name));
        assert!(r.sent >= 2 && r.received >= 2 && r.min_ms.is_some(), "{name}: {r:?}");
    }
    let hostile = parse_ping(&seed("net_ping_output", "hostile"));
    assert!(hostile.lines.iter().all(|l| mooring_net::sanitize::is_clean(l)));
    for name in ["linux", "tracepath", "windows"] {
        let r = parse_traceroute(&seed("net_traceroute_output", name));
        assert!(r.reached && r.hops.len() >= 3, "{name}: {r:?}");
    }
    let wg0 = Iface::parse("wg0").expect("iface");
    let body = |n: &str| seed("net_wg_output", n)[1..].to_vec();
    assert!(
        matches!(parse_wg(&WgQuery::Interfaces, &body("interfaces")), WgResult::Interfaces(v) if v.len() == 2)
    );
    assert!(
        matches!(parse_wg(&WgQuery::Endpoints(wg0.clone()), &body("endpoints")), WgResult::Endpoints(v) if v.len() == 2)
    );
    assert!(
        matches!(parse_wg(&WgQuery::Transfer(wg0.clone()), &body("transfer")), WgResult::Transfer(v) if v.len() == 1)
    );
    assert_eq!(
        parse_wg(&WgQuery::ListenPort(wg0), &body("listen-port")),
        WgResult::ListenPort(Some(51820))
    );
    assert!(mooring_net::wg::is_permission_denied(&body("permission-denied")));
}
