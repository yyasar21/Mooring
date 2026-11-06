//! `ping` output → [`PingResult`] (ADR-0020 §3). Number patterns, not layouts: iputils, BSD
//! and Windows (any locale) all print `ttl=` on a reply line, an RTT as `<n>ms` / `<n> ms` /
//! `<1ms`, a `sent, received` summary and a `min/avg/max` or `Minimum = … Maximum = …
//! Average = …` line. Anything else is kept as a raw (sanitised) line. Never fails.

use serde::Serialize;

use crate::sanitize;

/// Most reply rows kept.
pub const MAX_REPLIES: usize = 64;

/// One echo reply.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingReply {
    /// `icmp_seq`, when printed (Windows prints none).
    pub seq: Option<u32>,
    /// TTL of the reply.
    pub ttl: Option<u32>,
    /// Round-trip time in milliseconds (`<1ms` is 0.5).
    pub rtt_ms: f64,
}

/// Typed summary of one `ping` run.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResult {
    /// Requests sent (from the summary, else the replies counted).
    pub sent: u32,
    /// Replies received.
    pub received: u32,
    /// Loss in percent, 0..=100.
    pub loss_percent: f64,
    /// Fastest RTT in milliseconds.
    pub min_ms: Option<f64>,
    /// Mean RTT.
    pub avg_ms: Option<f64>,
    /// Slowest RTT.
    pub max_ms: Option<f64>,
    /// The reply rows, ≤ [`MAX_REPLIES`].
    pub replies: Vec<PingReply>,
    /// Every sanitised output line (plain text for the card).
    pub lines: Vec<String>,
}

/// Parse `ping` output (stdout and stderr concatenated). Never fails.
#[must_use]
pub fn parse_ping(out: &[u8]) -> PingResult {
    let lines = sanitize::lines(out);
    let mut r = PingResult {
        sent: 0,
        received: 0,
        loss_percent: 0.0,
        min_ms: None,
        avg_ms: None,
        max_ms: None,
        replies: Vec::new(),
        lines: Vec::new(),
    };
    let mut summary: Option<(u32, u32)> = None;
    for line in &lines {
        let lower = line.to_ascii_lowercase();
        if lower.contains("ttl=") {
            if let Some(rtt) = first_ms(&lower) {
                if r.replies.len() < MAX_REPLIES {
                    r.replies.push(PingReply {
                        seq: after_key(&lower, "icmp_seq="),
                        ttl: after_key(&lower, "ttl="),
                        rtt_ms: rtt,
                    });
                }
            }
        } else if lower.contains("transmitted") {
            // iputils / BSD: "N packets transmitted, M [packets] received, …"
            let nums = integers(&lower);
            if nums.len() >= 2 {
                summary = Some((nums[0], nums[1]));
            }
        } else if lower.contains('%') && equals_numbers(&lower).len() >= 3 {
            // Windows (any locale): "Packets: Sent = 4, Received = 3, Lost = 1 (25% loss)"
            let n = equals_numbers(&lower);
            summary = Some((n[0], n[1]));
        } else if lower.contains("min/avg/max") {
            // "rtt min/avg/max/mdev = 0.040/0.045/0.050/0.004 ms" (iputils) / BSD round-trip.
            if let Some(rest) = lower.split('=').nth(1) {
                let f: Vec<f64> = rest.split('/').filter_map(|s| parse_float(s.trim())).collect();
                if f.len() >= 3 {
                    r.min_ms = Some(f[0]);
                    r.avg_ms = Some(f[1]);
                    r.max_ms = Some(f[2]);
                }
            }
        } else if ms_after_equals(&lower).len() == 3 && !lower.contains("ttl") {
            // Windows (any locale): "Minimum = 0ms, Maximum = 12ms, Average = 5ms"
            let f = ms_after_equals(&lower);
            r.min_ms = Some(f[0]);
            r.max_ms = Some(f[1]);
            r.avg_ms = Some(f[2]);
        }
    }
    let counted = u32::try_from(r.replies.len()).unwrap_or(u32::MAX);
    let (sent, received) = summary.unwrap_or((counted, counted));
    r.sent = sent.max(received);
    r.received = received;
    r.loss_percent = if r.sent == 0 {
        0.0
    } else {
        ((f64::from(r.sent - r.received) * 100.0) / f64::from(r.sent)).clamp(0.0, 100.0)
    };
    if r.min_ms.is_none() && !r.replies.is_empty() {
        let rtts = r.replies.iter().map(|p| p.rtt_ms);
        r.min_ms = rtts.clone().reduce(f64::min);
        r.max_ms = rtts.clone().reduce(f64::max);
        let n = u32::try_from(r.replies.len()).unwrap_or(u32::MAX);
        r.avg_ms = Some(rtts.sum::<f64>() / f64::from(n));
    }
    r.lines = lines;
    r
}

/// The first `<number>ms` / `<number> ms` / `<1ms` on the line, in milliseconds.
fn first_ms(lower: &str) -> Option<f64> {
    let mut from = 0;
    while let Some(i) = lower[from..].find("ms") {
        let at = from + i;
        let after_ok = lower[at + 2..].chars().next().is_none_or(|c| !c.is_ascii_alphanumeric());
        if after_ok {
            let before = lower[..at].trim_end();
            let digits_len = before
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
                .count();
            let (head, digits) = before.split_at(before.len() - digits_len);
            let prefix = head.chars().last();
            if prefix == Some('<') && digits == "1" {
                return Some(0.5);
            }
            if let Some(v) = parse_float(digits) {
                return Some(v);
            }
        }
        from = at + 2;
    }
    None
}

/// A decimal with `.` or `,` (tr-TR prints `1,5`); never NaN or infinite.
fn parse_float(s: &str) -> Option<f64> {
    let s = s.trim().replace(',', ".");
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    s.parse::<f64>().ok().filter(|v| v.is_finite())
}

/// The integer right after `key`.
fn after_key(lower: &str, key: &str) -> Option<u32> {
    let rest = &lower[lower.find(key)? + key.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).take(9).collect();
    digits.parse().ok()
}

/// Every standalone integer (≤ 9 digits) on the line, in order.
fn integers(lower: &str) -> Vec<u32> {
    lower
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty() && s.len() <= 9)
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Every integer that follows `= ` on the line (Windows summaries, any locale).
fn equals_numbers(lower: &str) -> Vec<u32> {
    lower
        .split('=')
        .skip(1)
        .filter_map(|s| {
            let d: String =
                s.trim_start().chars().take_while(char::is_ascii_digit).take(9).collect();
            d.parse().ok()
        })
        .collect()
}

/// Every `= <n>ms` on the line.
fn ms_after_equals(lower: &str) -> Vec<f64> {
    lower
        .split('=')
        .skip(1)
        .filter_map(|s| {
            let s = s.trim_start();
            let d: String =
                s.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',').collect();
            let after = s[d.len()..].trim_start();
            after.starts_with("ms").then(|| parse_float(&d)).flatten()
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests;
