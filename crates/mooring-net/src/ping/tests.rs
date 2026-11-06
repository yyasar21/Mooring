use super::*;
use proptest::prelude::*;

pub const IPUTILS: &str = "PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.045 ms
64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=0.050 ms
64 bytes from 192.0.2.1: icmp_seq=3 ttl=64 time=0.040 ms

--- 192.0.2.1 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 0.040/0.045/0.050/0.004 ms
";

pub const BSD: &str = "PING 192.0.2.1 (192.0.2.1): 56 data bytes
64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=0.052 ms
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.070 ms

--- 192.0.2.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.052/0.061/0.070/0.009 ms
";

pub const WIN_EN: &str = "\r\nPinging 192.0.2.1 with 32 bytes of data:\r
Reply from 192.0.2.1: bytes=32 time<1ms TTL=64\r
Reply from 192.0.2.1: bytes=32 time=12ms TTL=64\r
Request timed out.\r
Reply from 192.0.2.1: bytes=32 time=3ms TTL=64\r
\r
Ping statistics for 192.0.2.1:\r
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),\r
Approximate round trip times in milli-seconds:\r
    Minimum = 0ms, Maximum = 12ms, Average = 5ms\r
";

pub const WIN_TR: &str = "
192.0.2.1 için Ping atılıyor 32 bayt veri ile:
192.0.2.1 yanıtı: bayt=32 süre=1ms TTL=64
192.0.2.1 yanıtı: bayt=32 süre=3ms TTL=64
İstek zaman aşımına uğradı.
192.0.2.1 yanıtı: bayt=32 süre<1ms TTL=64
192.0.2.1 yanıtı: bayt=32 süre=2ms TTL=64

192.0.2.1 için Ping istatistikleri:
    Paketler: Gönderilen = 5, Alınan = 4, Kaybolan = 1 (%20 kayıp),
Mili saniye türünden yaklaşık tur süreleri:
    En Az = 1ms, En Çok = 3ms, Ortalama = 2ms
";

#[test]
fn iputils_golden() {
    let r = parse_ping(IPUTILS.as_bytes());
    assert_eq!((r.sent, r.received), (4, 3));
    assert!((r.loss_percent - 25.0).abs() < f64::EPSILON);
    assert_eq!((r.min_ms, r.avg_ms, r.max_ms), (Some(0.040), Some(0.045), Some(0.050)));
    assert_eq!(r.replies.len(), 3);
    assert_eq!(r.replies[0], PingReply { seq: Some(1), ttl: Some(64), rtt_ms: 0.045 });
    assert_eq!(r.lines.len(), 7, "{:?}", r.lines);
}

#[test]
fn bsd_golden() {
    let r = parse_ping(BSD.as_bytes());
    assert_eq!((r.sent, r.received), (2, 2));
    assert!(r.loss_percent.abs() < f64::EPSILON);
    assert_eq!((r.min_ms, r.avg_ms, r.max_ms), (Some(0.052), Some(0.061), Some(0.070)));
    assert_eq!(r.replies[0].seq, Some(0));
}

#[test]
fn windows_en_golden() {
    let r = parse_ping(WIN_EN.as_bytes());
    assert_eq!((r.sent, r.received), (4, 3));
    assert!((r.loss_percent - 25.0).abs() < f64::EPSILON);
    assert_eq!((r.min_ms, r.avg_ms, r.max_ms), (Some(0.0), Some(5.0), Some(12.0)));
    let rtts: Vec<f64> = r.replies.iter().map(|p| p.rtt_ms).collect();
    assert_eq!(rtts, [0.5, 12.0, 3.0]);
    assert!(r.replies.iter().all(|p| p.seq.is_none() && p.ttl == Some(64)));
}

#[test]
fn windows_tr_golden_parses_by_numbers() {
    let r = parse_ping(WIN_TR.as_bytes());
    assert_eq!((r.sent, r.received), (5, 4));
    assert!((r.loss_percent - 20.0).abs() < f64::EPSILON);
    assert_eq!((r.min_ms, r.avg_ms, r.max_ms), (Some(1.0), Some(2.0), Some(3.0)));
    let rtts: Vec<f64> = r.replies.iter().map(|p| p.rtt_ms).collect();
    assert_eq!(rtts, [1.0, 3.0, 0.5, 2.0]);
}

#[test]
fn no_summary_falls_back_to_counting_replies() {
    let partial = "64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=1.5 ms
64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=2.5 ms
";
    let r = parse_ping(partial.as_bytes());
    assert_eq!((r.sent, r.received), (2, 2));
    assert_eq!((r.min_ms, r.avg_ms, r.max_ms), (Some(1.5), Some(2.0), Some(2.5)));
    assert_eq!(parse_ping(b"").sent, 0);
    assert_eq!(parse_ping(b"garbage\n\x1b[2Jmore").replies.len(), 0);
}

#[test]
fn hostile_numbers_never_panic_or_overflow() {
    let r = parse_ping(
        b"99999999999999999999 packets transmitted, 99999999999 received\nttl=1 time=1e308ms\n",
    );
    assert!(r.loss_percent.is_finite() && (0.0..=100.0).contains(&r.loss_percent));
    let r = parse_ping(b"4 packets transmitted, 9 received, 0% loss\n");
    assert_eq!((r.sent, r.received), (9, 9), "received > sent is clamped");
    let r = parse_ping(b"Packets: Sent = 4294967295, Received = 1, Lost = 0 (0% loss)\n");
    assert!(r.loss_percent.is_finite());
    let many = "x: ttl=1 time=1ms\n".repeat(MAX_REPLIES + 50);
    assert_eq!(parse_ping(many.as_bytes()).replies.len(), MAX_REPLIES);
}

#[test]
fn serializes_camel_case() {
    let v = serde_json::to_value(parse_ping(IPUTILS.as_bytes())).expect("json");
    assert!(v["lossPercent"].is_number() && v["minMs"].is_number());
    assert_eq!(v["replies"][0]["rttMs"], 0.045);
}

proptest! {
    #[test]
    fn never_panics_and_results_are_clean(raw in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let r = parse_ping(&raw);
        prop_assert!(r.received <= r.sent);
        prop_assert!(r.loss_percent.is_finite());
        prop_assert!(r.replies.len() <= MAX_REPLIES);
        prop_assert!(r.lines.iter().all(|l| sanitize::is_clean(l)));
        for v in [r.min_ms, r.avg_ms, r.max_ms].into_iter().flatten() {
            prop_assert!(v.is_finite());
        }
    }
}
