use super::*;
use proptest::prelude::*;

// Throwaway test keys (44 base64 characters, no real key material).
pub const KEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
pub const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=";

fn iface() -> Iface {
    Iface::parse("wg0").expect("iface")
}

#[test]
fn interfaces_are_validated_and_capped() {
    let r = parse_wg(&WgQuery::Interfaces, b"wg0 wg-home\t-bad wg 0 ok.1\n");
    let WgResult::Interfaces(list) = r else { panic!("{r:?}") };
    let names: Vec<&str> = list.iter().map(Iface::as_str).collect();
    assert_eq!(names, ["wg0", "wg-home", "wg", "0", "ok.1"]);
    let mut many = String::new();
    for i in 0..50 {
        many.push_str("wg");
        many.push_str(&i.to_string());
        many.push(' ');
    }
    let WgResult::Interfaces(list) = parse_wg(&WgQuery::Interfaces, many.as_bytes()) else {
        panic!()
    };
    assert_eq!(list.len(), MAX_INTERFACES);
}

#[test]
fn listen_port() {
    assert_eq!(
        parse_wg(&WgQuery::ListenPort(iface()), b"51820\n"),
        WgResult::ListenPort(Some(51820))
    );
    assert_eq!(parse_wg(&WgQuery::ListenPort(iface()), b"0\n"), WgResult::ListenPort(None));
    assert_eq!(parse_wg(&WgQuery::ListenPort(iface()), b"70000\n"), WgResult::ListenPort(None));
    assert_eq!(parse_wg(&WgQuery::ListenPort(iface()), b""), WgResult::ListenPort(None));
}

#[test]
fn endpoints_handshakes_transfer_rows() {
    let short_a = short_key(KEY_A).expect("key");
    let short_b = short_key(KEY_B).expect("key");
    assert_eq!(short_a, "AAAAAAAA…AAAA");
    assert!(!short_a.contains(KEY_A));

    let ep = format!("{KEY_A}\t192.0.2.7:51820\n{KEY_B}\t(none)\nnot-a-key\t1.2.3.4:1\n");
    assert_eq!(
        parse_wg(&WgQuery::Endpoints(iface()), ep.as_bytes()),
        WgResult::Endpoints(vec![
            (short_a.clone(), Some("192.0.2.7:51820".into())),
            (short_b.clone(), None)
        ])
    );
    let hs = format!("{KEY_A}\t1700000000\n{KEY_B}\t0\n{KEY_A}\tabc\n");
    assert_eq!(
        parse_wg(&WgQuery::LatestHandshakes(iface()), hs.as_bytes()),
        WgResult::LatestHandshakes(vec![(short_a.clone(), 1_700_000_000), (short_b.clone(), 0)])
    );
    let tr = format!("{KEY_A}\t1024\t2048\n{KEY_B}\t5\n");
    assert_eq!(
        parse_wg(&WgQuery::Transfer(iface()), tr.as_bytes()),
        WgResult::Transfer(vec![(short_a, 1024, 2048)])
    );
    let _ = short_b;
}

#[test]
fn merge_builds_the_status() {
    let short_a = short_key(KEY_A).expect("key");
    let short_b = short_key(KEY_B).expect("key");
    let i = merge_interface(
        &iface(),
        &WgResult::ListenPort(Some(51820)),
        &WgResult::Endpoints(vec![
            (short_a.clone(), Some("192.0.2.7:51820".into())),
            (short_b.clone(), None),
        ]),
        &WgResult::LatestHandshakes(vec![
            (short_a.clone(), 1_700_000_000),
            (short_b.clone(), 0),
            ("unknown".into(), 5),
        ]),
        &WgResult::Transfer(vec![(short_b.clone(), 10, 20)]),
    );
    assert_eq!(i.name, "wg0");
    assert_eq!(i.listen_port, Some(51820));
    assert_eq!(i.peers.len(), 2);
    assert_eq!(i.peers[0].last_handshake_secs, Some(1_700_000_000));
    assert_eq!((i.peers[0].rx_bytes, i.peers[0].tx_bytes), (0, 0));
    assert_eq!(i.peers[1].last_handshake_secs, None);
    assert_eq!((i.peers[1].rx_bytes, i.peers[1].tx_bytes), (10, 20));
    let json = serde_json::to_value(WgStatus { interfaces: vec![i] }).expect("json");
    assert_eq!(json["interfaces"][0]["peers"][0]["publicKey"], short_a);
    assert_eq!(json["interfaces"][0]["listenPort"], 51820);
    // Mismatched results produce an empty interface, never a panic.
    let empty = merge_interface(
        &iface(),
        &WgResult::Interfaces(vec![]),
        &WgResult::Interfaces(vec![]),
        &WgResult::Interfaces(vec![]),
        &WgResult::Interfaces(vec![]),
    );
    assert!(empty.peers.is_empty() && empty.listen_port.is_none());
}

#[test]
fn peer_cap_and_key_shape() {
    let many = format!("{KEY_A}\t1\n").repeat(300);
    let WgResult::LatestHandshakes(rows) =
        parse_wg(&WgQuery::LatestHandshakes(iface()), many.as_bytes())
    else {
        panic!()
    };
    // The line cap (200) binds before the peer cap (256): 200 peers per interface in practice.
    assert_eq!(rows.len(), MAX_PEERS.min(crate::sanitize::MAX_LINES));
    assert!(short_key("AAAA").is_none());
    assert!(short_key(&"A".repeat(44)).is_none(), "must end with =");
    assert!(short_key(&format!("{}=", "A".repeat(43))).is_some());
    assert!(short_key(&format!("{}!=", "A".repeat(42))).is_none());
}

#[test]
fn permission_denied_detection() {
    assert!(is_permission_denied(b"Unable to access interface: Operation not permitted\n"));
    assert!(is_permission_denied(b"wg: Permission denied"));
    assert!(is_permission_denied(b"Access is denied."));
    assert!(!is_permission_denied(b"Unable to access interface: No such device\n"));
    assert!(!is_permission_denied(b""));
}

proptest! {
    #[test]
    fn never_panics_and_caps_hold(raw in proptest::collection::vec(any::<u8>(), 0..2048)) {
        for q in [
            WgQuery::Interfaces,
            WgQuery::Endpoints(iface()),
            WgQuery::LatestHandshakes(iface()),
            WgQuery::Transfer(iface()),
            WgQuery::ListenPort(iface()),
        ] {
            match parse_wg(&q, &raw) {
                WgResult::Interfaces(v) => prop_assert!(v.len() <= MAX_INTERFACES),
                WgResult::Endpoints(v) => {
                    prop_assert!(v.len() <= MAX_PEERS);
                    prop_assert!(v.iter().all(|(k, _)| k.len() < 44));
                }
                WgResult::LatestHandshakes(v) => prop_assert!(v.len() <= MAX_PEERS),
                WgResult::Transfer(v) => prop_assert!(v.len() <= MAX_PEERS),
                WgResult::ListenPort(p) => prop_assert!(p != Some(0)),
            }
        }
        let _ = is_permission_denied(&raw);
    }
}
