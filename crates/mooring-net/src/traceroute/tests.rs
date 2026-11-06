use super::*;
use proptest::prelude::*;

pub const LINUX: &str = "traceroute to 192.0.2.1 (192.0.2.1), 30 hops max, 60 byte packets
 1  192.0.2.254  0.321 ms
 2  *
 3  198.51.100.1  12.345 ms !H
 4  192.0.2.1  13.001 ms
";

pub const TRACEPATH: &str = " 1?: [LOCALHOST]                      pmtu 1500
 1:  192.0.2.254                                           0.321ms
 1:  192.0.2.254                                           0.250ms
 2:  no reply
 3:  192.0.2.1                                            12.345ms reached
     Resume: pmtu 1500 hops 3 back 3
";

pub const WINDOWS: &str = "\r
Tracing route to 192.0.2.1 over a maximum of 30 hops\r
\r
  1    <1 ms    <1 ms    <1 ms  192.0.2.254\r
  2     *        *        *     Request timed out.\r
  3    12 ms    13 ms    12 ms  192.0.2.1\r
\r
Trace complete.\r
";

pub const WINDOWS_TR: &str = "
En fazla 30 atlama üzerinden 192.0.2.1 yolu izleniyor

  1    <1 ms    <1 ms    <1 ms  192.0.2.254
  2     *        *        *     İstek zaman aşımına uğradı.
  3     2 ms     3 ms     2 ms  192.0.2.1

İzleme tamamlandı.
";

#[test]
fn linux_golden() {
    let r = parse_traceroute(LINUX.as_bytes());
    assert_eq!(r.hops.len(), 4);
    assert_eq!(
        r.hops[0],
        Hop {
            hop: 1,
            addr: Some("192.0.2.254".into()),
            rtts_ms: vec![0.321],
            timeouts: 0,
            note: None
        }
    );
    assert_eq!(r.hops[1], Hop { hop: 2, addr: None, rtts_ms: vec![], timeouts: 1, note: None });
    assert_eq!(r.hops[2].note.as_deref(), Some("!H"));
    assert!(r.reached);
    assert_eq!(r.lines.len(), 5);
}

#[test]
fn tracepath_rows_merge_per_hop() {
    let r = parse_traceroute(TRACEPATH.as_bytes());
    assert_eq!(r.hops.len(), 3);
    assert_eq!(r.hops[0].rtts_ms, [0.321, 0.250]);
    assert_eq!(r.hops[1], Hop { hop: 2, addr: None, rtts_ms: vec![], timeouts: 0, note: None });
    assert_eq!(r.hops[2].note.as_deref(), Some("reached"));
    assert!(r.reached);
}

#[test]
fn windows_golden_en_and_tr() {
    for (text, last) in [(WINDOWS, [12.0, 13.0, 12.0]), (WINDOWS_TR, [2.0, 3.0, 2.0])] {
        let r = parse_traceroute(text.as_bytes());
        assert_eq!(r.hops.len(), 3, "{:?}", r.hops);
        assert_eq!(r.hops[0].rtts_ms, [0.5, 0.5, 0.5]);
        assert_eq!(r.hops[0].addr.as_deref(), Some("192.0.2.254"));
        assert_eq!(r.hops[1].timeouts, 3);
        assert_eq!(r.hops[1].addr, None);
        assert_eq!(r.hops[2].rtts_ms, last);
        assert!(r.reached);
    }
}

#[test]
fn unreached_and_ipv6() {
    let r = parse_traceroute(b" 1  2001:db8::1  0.5 ms\n 2  *\n 3  *\n");
    assert_eq!(r.hops[0].addr.as_deref(), Some("2001:db8::1"));
    assert!(!r.reached);
    assert!(!parse_traceroute(b"").reached);
    assert!(parse_traceroute(b"1?: [LOCALHOST] pmtu 1500\n").hops.is_empty());
}

#[test]
fn caps_hold() {
    let mut many = String::new();
    for i in 1..=120 {
        many.push_str(&i.to_string());
        many.push_str("  192.0.2.1  1 ms\n");
    }
    assert_eq!(parse_traceroute(many.as_bytes()).hops.len(), MAX_HOP_ROWS);
    let rtts = " 1  192.0.2.1 ".to_owned() + &"1 ms ".repeat(20);
    assert_eq!(parse_traceroute(rtts.as_bytes()).hops[0].rtts_ms.len(), MAX_RTTS);
    let stars = " 1 ".to_owned() + &"* ".repeat(300);
    assert_eq!(parse_traceroute(stars.as_bytes()).hops[0].timeouts, 255);
    assert!(parse_traceroute(b"999  192.0.2.1 1 ms\n0 192.0.2.1 1 ms\n1234 x\n").hops.is_empty());
}

proptest! {
    #[test]
    fn never_panics_and_results_are_clean(raw in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let r = parse_traceroute(&raw);
        prop_assert!(r.hops.len() <= MAX_HOP_ROWS);
        prop_assert!(r.lines.iter().all(|l| sanitize::is_clean(l)));
        for h in &r.hops {
            prop_assert!(h.rtts_ms.len() <= MAX_RTTS);
            prop_assert!(h.rtts_ms.iter().all(|v| v.is_finite()));
            prop_assert!(h.addr.as_deref().is_none_or(|a| a.parse::<IpAddr>().is_ok()));
        }
    }
}
