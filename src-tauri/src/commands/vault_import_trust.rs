//! Review 9 L-52: a **merge** import never adds trust for a host this device already pinned.
//! The union of trust lines would otherwise let a crafted backup (the attacker's own vault,
//! both passwords handed over with the file) add a second key of another type for a pinned
//! SSH host — accepted silently by a later MITM — or a second certificate pin that turns the
//! host into a fail-closed `trust_conflict`. Imported lines that name a `host:port` with a
//! local pin are dropped (the local pin is kept) and reported as `trust` conflicts with
//! `kept_local`; lines for hosts without a local pin are added and counted.
//!
//! Lines are hashed (`|1|salt|hmac`), so they can only be matched against known names: the
//! candidates are the `host:port` of every connection on either side (port or the protocol
//! default). A pinned host that no connection names (a gateway or kube API address that lives
//! only in options) is not recognised and keeps the old union behaviour.

use std::collections::BTreeSet;

use mooring_core::known_certs::{host_key, KnownCerts};
use mooring_core::Protocol;
use mooring_proto_ssh::KnownHosts;
use mooring_sync::snapshot::KNOWN_HOSTS;
use mooring_sync::Snapshot;

use super::vault_import::ImportConflict;

/// What [`guard`] did.
#[derive(Debug, Default)]
pub(crate) struct TrustGuard {
    /// One per `host:port` and trust file whose imported lines were dropped.
    pub conflicts: Vec<ImportConflict>,
    /// Imported trust lines that will be added.
    pub added: u64,
}

enum Store {
    Hosts(KnownHosts),
    Certs(KnownCerts),
}

impl Store {
    fn parse(file: &str, text: &[u8]) -> Self {
        if file == KNOWN_HOSTS {
            Self::Hosts(KnownHosts::parse_bytes(text))
        } else {
            Self::Certs(KnownCerts::parse_bytes(text))
        }
    }

    fn pins(&self, host: &str, port: u16) -> bool {
        match self {
            Self::Hosts(k) => k.has_entry(host, port),
            Self::Certs(k) => k.has_pin(host, port),
        }
    }
}

fn candidates(local: &Snapshot, file: &Snapshot) -> BTreeSet<(String, u16)> {
    local
        .connections
        .values()
        .chain(file.connections.values())
        .filter_map(|r| {
            let protocol: Option<Protocol> =
                serde_json::from_value(serde_json::Value::String(r.protocol.clone())).ok();
            let port = r.port.or_else(|| protocol.and_then(Protocol::default_port))?;
            Some((r.host.to_ascii_lowercase(), port))
        })
        .collect()
}

fn joined(lines: &BTreeSet<String>) -> Vec<u8> {
    lines.iter().flat_map(|l| l.bytes().chain(std::iter::once(b'\n'))).collect()
}

/// Drop the imported trust lines of `file` that name a host `local` already pins.
pub(crate) fn guard(local: &Snapshot, file: &mut Snapshot) -> TrustGuard {
    let hosts = candidates(local, file);
    let empty = BTreeSet::new();
    let mut out = TrustGuard::default();
    for (name, lines) in &mut file.trust {
        let mine = local.trust.get(name).unwrap_or(&empty);
        let local_store = Store::parse(name, &joined(mine));
        let pinned: Vec<&(String, u16)> =
            hosts.iter().filter(|(h, p)| local_store.pins(h, *p)).collect();
        if !pinned.is_empty() {
            let fresh: Vec<(String, Store)> = lines
                .difference(mine)
                .map(|l| (l.clone(), Store::parse(name, l.as_bytes())))
                .collect();
            for (host, port) in pinned {
                let hit: Vec<&String> =
                    fresh.iter().filter(|(_, s)| s.pins(host, *port)).map(|(l, _)| l).collect();
                if hit.is_empty() {
                    continue;
                }
                for l in hit {
                    lines.remove(l);
                }
                out.conflicts.push(ImportConflict {
                    kind: "trust",
                    id: host_key(host, *port),
                    name: name.clone(),
                    resolution: "kept_local",
                });
            }
        }
        let added = lines.difference(mine).count();
        out.added += u64::try_from(added).unwrap_or(u64::MAX);
    }
    file.trust.retain(|_, l| !l.is_empty());
    out
}
