//! TCP port check in plain Rust (ADR-0020 §2): resolve, connect under one deadline, drop the
//! stream at once. No bytes are sent or read; one port per call.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::net::{lookup_host, TcpStream};

use crate::target::Target;

/// Most addresses tried for one name.
pub const MAX_ADDRS: usize = 16;
/// Shortest deadline.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(100);
/// Longest deadline.
pub const MAX_TIMEOUT: Duration = Duration::from_millis(10_000);
/// Default deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(3_000);

/// Outcome of a port check.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TcpResult {
    /// The handshake completed with `addr`.
    #[serde(rename_all = "camelCase")]
    Open {
        /// `ip:port` that answered.
        addr: String,
        /// Connect time in milliseconds.
        rtt_ms: f64,
    },
    /// Every address refused (RST).
    Closed,
    /// The deadline passed without an answer (filtered, or the host is silent).
    Timeout,
    /// The network or host is unreachable (ICMP error or no route).
    Unreachable,
    /// The name did not resolve.
    DnsFailed,
}

/// Clamp a requested deadline into `MIN_TIMEOUT..=MAX_TIMEOUT`.
#[must_use]
pub fn clamp_timeout(t: Duration) -> Duration {
    t.clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

/// Check `target:port`. Addresses are tried in resolver order under one shared deadline; the
/// first handshake wins. The result reflects the most informative failure: a refusal beats
/// unreachable, which beats a timeout.
pub async fn tcp_check(target: &Target, port: u16, timeout: Duration) -> TcpResult {
    let timeout = clamp_timeout(timeout);
    let started = Instant::now();
    let deadline = started + timeout;
    let addrs = match resolve(target, port, deadline).await {
        Some(a) if !a.is_empty() => a,
        _ => return TcpResult::DnsFailed,
    };
    let mut worst = TcpResult::Timeout;
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let t0 = Instant::now();
        match tokio::time::timeout(left, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                let rtt_ms = t0.elapsed().as_secs_f64() * 1000.0;
                return TcpResult::Open { addr: addr.to_string(), rtt_ms };
            }
            Ok(Err(e)) => worst = rank(worst, classify(&e)),
            Err(_elapsed) => worst = rank(worst, TcpResult::Timeout),
        }
    }
    worst
}

async fn resolve(target: &Target, port: u16, deadline: Instant) -> Option<Vec<SocketAddr>> {
    if let Some(ip) = target.ip() {
        return Some(vec![SocketAddr::new(ip, port)]);
    }
    let left = deadline.saturating_duration_since(Instant::now());
    let lookup = lookup_host((target.as_str(), port));
    let iter = tokio::time::timeout(left, lookup).await.ok()?.ok()?;
    Some(iter.take(MAX_ADDRS).collect())
}

fn classify(e: &std::io::Error) -> TcpResult {
    match e.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => TcpResult::Closed,
        ErrorKind::TimedOut => TcpResult::Timeout,
        _ => TcpResult::Unreachable,
    }
}

/// Keep the more informative of two failures.
fn rank(a: TcpResult, b: TcpResult) -> TcpResult {
    let score = |r: &TcpResult| match r {
        TcpResult::Closed => 3,
        TcpResult::Unreachable => 2,
        _ => 1,
    };
    if score(&b) > score(&a) {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_clamped() {
        assert_eq!(clamp_timeout(Duration::ZERO), MIN_TIMEOUT);
        assert_eq!(clamp_timeout(Duration::from_secs(60)), MAX_TIMEOUT);
        assert_eq!(clamp_timeout(DEFAULT_TIMEOUT), DEFAULT_TIMEOUT);
    }

    #[test]
    fn failure_ranking_prefers_the_informative_one() {
        assert_eq!(rank(TcpResult::Timeout, TcpResult::Closed), TcpResult::Closed);
        assert_eq!(rank(TcpResult::Closed, TcpResult::Timeout), TcpResult::Closed);
        assert_eq!(rank(TcpResult::Timeout, TcpResult::Unreachable), TcpResult::Unreachable);
        assert_eq!(rank(TcpResult::Unreachable, TcpResult::Closed), TcpResult::Closed);
        assert_eq!(
            classify(&std::io::Error::from(ErrorKind::ConnectionRefused)),
            TcpResult::Closed
        );
        assert_eq!(
            classify(&std::io::Error::from(ErrorKind::HostUnreachable)),
            TcpResult::Unreachable
        );
        assert_eq!(classify(&std::io::Error::from(ErrorKind::TimedOut)), TcpResult::Timeout);
    }

    #[test]
    fn serializes_tagged() {
        let v = serde_json::to_value(TcpResult::Open { addr: "127.0.0.1:1".into(), rtt_ms: 0.5 })
            .expect("json");
        assert_eq!(
            v,
            serde_json::json!({ "outcome": "open", "addr": "127.0.0.1:1", "rttMs": 0.5 })
        );
        assert_eq!(
            serde_json::to_value(TcpResult::DnsFailed).expect("json"),
            serde_json::json!({ "outcome": "dns_failed" })
        );
    }
}
