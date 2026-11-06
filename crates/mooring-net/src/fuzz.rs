//! Fuzz entries for QA's cargo-fuzz targets (ADR-0020 test plan): `net_ping_output`,
//! `net_traceroute_output`, `net_wg_output`. Oracle: no panic, caps hold, no control or
//! format character in any produced line.

use crate::ping::{parse_ping, MAX_REPLIES};
use crate::sanitize::{is_clean, MAX_LINES};
use crate::tools::{Iface, WgQuery};
use crate::traceroute::{parse_traceroute, MAX_HOP_ROWS, MAX_RTTS};
use crate::wg::{is_permission_denied, parse_wg, WgResult, MAX_INTERFACES, MAX_PEERS};

/// `ping` output of any OS.
pub fn fuzz_ping_output(data: &[u8]) {
    let r = parse_ping(data);
    assert!(r.received <= r.sent);
    assert!(r.loss_percent.is_finite() && (0.0..=100.0).contains(&r.loss_percent));
    assert!(r.replies.len() <= MAX_REPLIES);
    assert!(r.lines.len() <= MAX_LINES && r.lines.iter().all(|l| is_clean(l)));
    assert!([r.min_ms, r.avg_ms, r.max_ms].into_iter().flatten().all(f64::is_finite));
    assert!(r.replies.iter().all(|p| p.rtt_ms.is_finite()));
}

/// `traceroute` / `tracepath` / `tracert` output.
pub fn fuzz_traceroute_output(data: &[u8]) {
    let r = parse_traceroute(data);
    assert!(r.hops.len() <= MAX_HOP_ROWS);
    assert!(r.lines.len() <= MAX_LINES && r.lines.iter().all(|l| is_clean(l)));
    for h in &r.hops {
        assert!(h.hop >= 1);
        assert!(h.rtts_ms.len() <= MAX_RTTS && h.rtts_ms.iter().all(|v| v.is_finite()));
        assert!(h.addr.as_deref().is_none_or(|a| a.parse::<std::net::IpAddr>().is_ok()));
        assert!(h.note.as_deref().is_none_or(|n| n.len() <= 8 && is_clean(n)));
    }
}

/// `wg show` output: the first byte selects the query, the rest is the body.
pub fn fuzz_wg_output(data: &[u8]) {
    let Some((sel, body)) = data.split_first() else { return };
    let Ok(i) = Iface::parse("wg0") else { return };
    let q = match sel % 5 {
        0 => WgQuery::Interfaces,
        1 => WgQuery::Endpoints(i),
        2 => WgQuery::LatestHandshakes(i),
        3 => WgQuery::Transfer(i),
        _ => WgQuery::ListenPort(i),
    };
    match parse_wg(&q, body) {
        WgResult::Interfaces(v) => {
            assert!(v.len() <= MAX_INTERFACES);
            assert!(v.iter().all(|n| Iface::parse(n.as_str()).is_ok()));
        }
        WgResult::Endpoints(v) => {
            assert!(v.len() <= MAX_PEERS);
            assert!(v
                .iter()
                .all(|(k, e)| k.len() < 44 && e.as_deref().is_none_or(|e| e.len() <= 64)));
        }
        WgResult::LatestHandshakes(v) => assert!(v.len() <= MAX_PEERS),
        WgResult::Transfer(v) => assert!(v.len() <= MAX_PEERS),
        WgResult::ListenPort(p) => assert_ne!(p, Some(0)),
    }
    let _ = is_permission_denied(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_run() {
        fuzz_ping_output(crate::ping::tests::IPUTILS.as_bytes());
        fuzz_ping_output(crate::ping::tests::WIN_TR.as_bytes());
        fuzz_traceroute_output(crate::traceroute::tests::WINDOWS.as_bytes());
        fuzz_traceroute_output(crate::traceroute::tests::TRACEPATH.as_bytes());
        for sel in 0..5u8 {
            let mut d = vec![sel];
            d.extend_from_slice(
                b"wg0 wg1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1\t2\n51820\n",
            );
            fuzz_wg_output(&d);
        }
        fuzz_wg_output(b"");
        fuzz_ping_output(b"");
        fuzz_traceroute_output(b"\x1b[2J\xff\xfe");
    }
}
