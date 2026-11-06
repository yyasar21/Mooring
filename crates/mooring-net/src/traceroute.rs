//! `traceroute` / `tracepath` / `tracert` output → [`TraceResult`] (ADR-0020 §3). A hop line
//! starts with its number; the rest is scanned for IP literals (`-n` / `-d` means no names),
//! `<n> ms` / `<n>ms` / `<1 ms` round trips and `*` probes. `tracepath` repeats a hop number
//! per probe; the rows merge. Everything else is kept as a raw (sanitised) line. Never fails.

use std::net::IpAddr;

use serde::Serialize;

use crate::sanitize;

/// Most hop rows kept.
pub const MAX_HOP_ROWS: usize = 64;
/// Most RTTs per hop.
pub const MAX_RTTS: usize = 8;

/// One hop.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    /// Hop number as printed (1-based).
    pub hop: u8,
    /// First address printed for the hop.
    pub addr: Option<String>,
    /// Round trips in milliseconds, ≤ [`MAX_RTTS`].
    pub rtts_ms: Vec<f64>,
    /// `*` probes without an answer.
    pub timeouts: u8,
    /// ICMP annotation after the RTTs (`!H`, `!N`, `!X`, …), when any.
    pub note: Option<String>,
}

/// Typed summary of one trace.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    /// Hops in order, ≤ [`MAX_HOP_ROWS`].
    pub hops: Vec<Hop>,
    /// Whether the last hop answered (an address with at least one RTT).
    pub reached: bool,
    /// Every sanitised output line.
    pub lines: Vec<String>,
}

/// Parse trace output (stdout and stderr concatenated). Never fails.
#[must_use]
pub fn parse_traceroute(out: &[u8]) -> TraceResult {
    let lines = sanitize::lines(out);
    let mut hops: Vec<Hop> = Vec::new();
    for line in &lines {
        let Some((n, rest)) = hop_prefix(line) else { continue };
        let probe = parse_probe(rest);
        match hops.last_mut() {
            Some(last) if last.hop == n => merge(last, probe),
            _ => {
                if hops.len() < MAX_HOP_ROWS {
                    hops.push(probe.into_hop(n));
                }
            }
        }
    }
    let reached = hops.last().is_some_and(|h| h.addr.is_some() && !h.rtts_ms.is_empty());
    TraceResult { hops, reached, lines }
}

/// `" 3  …"`, `" 3:  …"` (tracepath) → `(3, rest)`. `" 1?: [LOCALHOST] …"` is not a hop.
fn hop_prefix(line: &str) -> Option<(u8, &str)> {
    let t = line.trim_start();
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 3 {
        return None;
    }
    let n: u8 = t[..digits].parse().ok()?;
    let rest = &t[digits..];
    let rest = match rest.chars().next() {
        Some(' ') => rest,
        Some(':') => &rest[1..],
        _ => return None,
    };
    (n >= 1).then_some((n, rest))
}

#[derive(Default)]
struct Probe {
    addr: Option<String>,
    rtts: Vec<f64>,
    timeouts: u8,
    note: Option<String>,
}

impl Probe {
    fn into_hop(self, hop: u8) -> Hop {
        Hop { hop, addr: self.addr, rtts_ms: self.rtts, timeouts: self.timeouts, note: self.note }
    }
}

fn merge(hop: &mut Hop, p: Probe) {
    if hop.addr.is_none() {
        hop.addr = p.addr;
    }
    for r in p.rtts {
        if hop.rtts_ms.len() < MAX_RTTS {
            hop.rtts_ms.push(r);
        }
    }
    hop.timeouts = hop.timeouts.saturating_add(p.timeouts);
    if hop.note.is_none() {
        hop.note = p.note;
    }
}

fn parse_probe(rest: &str) -> Probe {
    let mut p = Probe::default();
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        let next = tokens.get(i + 1).copied();
        if tok == "*" {
            p.timeouts = p.timeouts.saturating_add(1);
        } else if let Some(ip) = parse_ip(tok) {
            if p.addr.is_none() {
                p.addr = Some(ip);
            }
        } else if let Some(ms) = rtt_token(tok) {
            push_rtt(&mut p, ms);
        } else if next == Some("ms") {
            if let Some(ms) = parse_float(tok.trim_start_matches('<')) {
                push_rtt(&mut p, if tok.starts_with('<') { ms / 2.0 } else { ms });
            }
            i += 1;
        } else if tok.starts_with('!') && tok.len() <= 4 && p.note.is_none() {
            p.note = Some(tok.to_owned());
        } else if tok == "reached" && p.note.is_none() {
            p.note = Some("reached".into());
        }
        i += 1;
    }
    p
}

fn push_rtt(p: &mut Probe, ms: f64) {
    if p.rtts.len() < MAX_RTTS {
        p.rtts.push(ms);
    }
}

/// `12.345ms` / `<1ms` as one token.
fn rtt_token(tok: &str) -> Option<f64> {
    let num = tok.strip_suffix("ms")?;
    let half = num.starts_with('<');
    let v = parse_float(num.trim_start_matches('<'))?;
    Some(if half { v / 2.0 } else { v })
}

fn parse_ip(tok: &str) -> Option<String> {
    let t = tok.trim_matches(|c| c == '(' || c == ')' || c == '[' || c == ']' || c == ',');
    t.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn parse_float(s: &str) -> Option<f64> {
    let s = s.replace(',', ".");
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    s.parse::<f64>().ok().filter(|v| v.is_finite())
}

#[cfg(test)]
pub(crate) mod tests;
