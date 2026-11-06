//! `wg show …` output → [`WgResult`] / [`WgStatus`] (ADR-0020 §4). Only the read-only
//! subcommands of [`WgQuery`] are parsed; a public key is validated (44 base64 chars) and
//! shortened before it leaves the crate. Never fails; malformed rows are skipped.

use serde::Serialize;

use crate::sanitize;
use crate::tools::{Iface, WgQuery};

/// Most interfaces reported.
pub const MAX_INTERFACES: usize = 32;
/// Most peers per interface.
pub const MAX_PEERS: usize = 256;

/// One parsed `wg show` output, per query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgResult {
    /// Validated interface names, ≤ [`MAX_INTERFACES`].
    Interfaces(Vec<Iface>),
    /// `(shortened public key, endpoint)`; `(none)` becomes `None`.
    Endpoints(Vec<(String, Option<String>)>),
    /// `(shortened public key, unix seconds of the last handshake; 0 = never)`.
    LatestHandshakes(Vec<(String, u64)>),
    /// `(shortened public key, rx bytes, tx bytes)`.
    Transfer(Vec<(String, u64, u64)>),
    /// The UDP listen port, when one is printed.
    ListenPort(Option<u16>),
}

/// One peer of the merged status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgPeer {
    /// Shortened public key (`AbCdEfGh…wxyz`), never the full key.
    pub public_key: String,
    /// `host:port` of the peer, when known.
    pub endpoint: Option<String>,
    /// Unix seconds of the last handshake; `None` when never.
    pub last_handshake_secs: Option<u64>,
    /// Bytes received from the peer.
    pub rx_bytes: u64,
    /// Bytes sent to the peer.
    pub tx_bytes: u64,
}

/// One interface of the merged status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgInterface {
    /// Interface name.
    pub name: String,
    /// Listen port.
    pub listen_port: Option<u16>,
    /// Peers, ≤ [`MAX_PEERS`].
    pub peers: Vec<WgPeer>,
}

/// `net_wg_show` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgStatus {
    /// Interfaces, ≤ [`MAX_INTERFACES`].
    pub interfaces: Vec<WgInterface>,
}

/// Parse the stdout of `wg show …` for query `q`. Never fails.
#[must_use]
pub fn parse_wg(q: &WgQuery, out: &[u8]) -> WgResult {
    let lines = sanitize::lines(out);
    match q {
        WgQuery::Interfaces => WgResult::Interfaces(
            lines
                .iter()
                .flat_map(|l| l.split_whitespace())
                .filter_map(|n| Iface::parse(n).ok())
                .take(MAX_INTERFACES)
                .collect(),
        ),
        WgQuery::ListenPort(_) => WgResult::ListenPort(
            lines.first().and_then(|l| l.trim().parse::<u16>().ok()).filter(|p| *p != 0),
        ),
        WgQuery::Endpoints(_) => WgResult::Endpoints(
            rows(&lines)
                .map(|(key, f)| {
                    let ep = f.first().copied().unwrap_or("(none)");
                    let ep = (ep != "(none)" && ep.len() <= 64).then(|| ep.to_owned());
                    (key, ep)
                })
                .collect(),
        ),
        WgQuery::LatestHandshakes(_) => WgResult::LatestHandshakes(
            rows(&lines).filter_map(|(key, f)| Some((key, int(f.first()?)?))).collect(),
        ),
        WgQuery::Transfer(_) => WgResult::Transfer(
            rows(&lines)
                .filter_map(|(key, f)| Some((key, int(f.first()?)?, int(f.get(1)?)?)))
                .collect(),
        ),
    }
}

/// `<pubkey> <field>…` rows with a valid key, shortened, ≤ [`MAX_PEERS`].
fn rows(lines: &[String]) -> impl Iterator<Item = (String, Vec<&str>)> + '_ {
    lines
        .iter()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let key = short_key(f.next()?)?;
            Some((key, f.collect::<Vec<_>>()))
        })
        .take(MAX_PEERS)
}

/// A 44-character base64 Curve25519 key → `first 8…last 4`. Anything else is skipped.
#[must_use]
pub fn short_key(key: &str) -> Option<String> {
    let ok = key.len() == 44
        && key.ends_with('=')
        && key[..43].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    ok.then(|| format!("{}…{}", &key[..8], &key[39..43]))
}

fn int(s: &str) -> Option<u64> {
    (s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// Merge the per-interface queries into one status. Peers come from `endpoints`; handshake
/// and transfer rows for an unknown key are ignored.
#[must_use]
pub fn merge_interface(
    iface: &Iface,
    listen_port: &WgResult,
    endpoints: &WgResult,
    handshakes: &WgResult,
    transfer: &WgResult,
) -> WgInterface {
    let listen_port = match listen_port {
        WgResult::ListenPort(p) => *p,
        _ => None,
    };
    let mut peers: Vec<WgPeer> = match endpoints {
        WgResult::Endpoints(rows) => rows
            .iter()
            .take(MAX_PEERS)
            .map(|(k, ep)| WgPeer {
                public_key: k.clone(),
                endpoint: ep.clone(),
                last_handshake_secs: None,
                rx_bytes: 0,
                tx_bytes: 0,
            })
            .collect(),
        _ => Vec::new(),
    };
    if let WgResult::LatestHandshakes(rows) = handshakes {
        for (k, secs) in rows {
            if let Some(p) = peers.iter_mut().find(|p| p.public_key == *k) {
                p.last_handshake_secs = (*secs > 0).then_some(*secs);
            }
        }
    }
    if let WgResult::Transfer(rows) = transfer {
        for (k, rx, tx) in rows {
            if let Some(p) = peers.iter_mut().find(|p| p.public_key == *k) {
                p.rx_bytes = *rx;
                p.tx_bytes = *tx;
            }
        }
    }
    WgInterface { name: iface.as_str().to_owned(), listen_port, peers }
}

/// Whether `wg`'s stderr says it lacks rights (`Operation not permitted`, `Permission denied`,
/// the Windows `Access is denied`).
#[must_use]
pub fn is_permission_denied(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&stderr[..stderr.len().min(sanitize::MAX_BYTES)])
        .to_ascii_lowercase();
    ["operation not permitted", "permission denied", "access is denied", "not permitted"]
        .iter()
        .any(|m| text.contains(m))
}

#[cfg(test)]
mod tests;
