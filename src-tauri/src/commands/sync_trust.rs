//! Conflicting pins after a sync apply (review 6 L-35).
//!
//! Owner decision 10 syncs the trust stores, and the merge keeps every line: two devices that
//! first saw a host concurrently and accepted **different** certificates (one of them on a
//! hostile network) both keep their pin, and `KnownCerts::check` trusts either. The lines
//! are salted HMACs, so the merge cannot see that they name one host; the Tauri layer can,
//! for the user's own connections. After every apply, each `host:port` of a connection with
//! more than one distinct fingerprint in its protocol's file is audited
//! `trust_conflict { file, host }` (names only; nothing is resolved — the user removes the
//! wrong pin in the trust store UI). SSH `known_hosts` is exempt: several key types per host
//! are normal there.

use std::path::Path;

use mooring_audit::AuditEvent;
use mooring_core::known_certs::{host_key, CertProtocol, KnownCerts};
use mooring_store::Store;

/// One `host:port` with more than one pinned fingerprint in `file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustConflict {
    /// Trust file name (`known_rdp_certs`, …).
    pub file: &'static str,
    /// `host:port`.
    pub host: String,
}

impl TrustConflict {
    /// The audit row.
    pub fn event(&self) -> AuditEvent {
        AuditEvent::TrustConflict { file: self.file.to_owned(), host: self.host.clone() }
    }
}

/// The conflicts among the connections in `store`, per protocol trust file in `trust_dir`.
/// Unreadable files are skipped (the next connect fails closed on them anyway).
pub fn conflicts(store: &Store, trust_dir: &Path) -> Vec<TrustConflict> {
    let mut out = Vec::new();
    let Ok(folders) = store.list_folders() else { return out };
    let mut hosts: Vec<(CertProtocol, String, u16)> = Vec::new();
    for folder in &folders {
        let Ok(conns) = store.list_connections(folder.id) else { continue };
        for c in conns {
            let Some(cp) = CertProtocol::ALL.into_iter().find(|p| p.connection_protocol() == Some(c.protocol))
            else {
                continue;
            };
            if let Some(port) = c.port.or_else(|| c.protocol.default_port()) {
                hosts.push((cp, c.host, port));
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    let mut file: Option<(CertProtocol, KnownCerts)> = None;
    for (cp, host, port) in hosts {
        if file.as_ref().is_none_or(|(p, _)| *p != cp) {
            let path = trust_dir.join(cp.file_name());
            if !path.exists() {
                continue;
            }
            let Ok(certs) = KnownCerts::load(&path) else { continue };
            file = Some((cp, certs));
        }
        if let Some((_, certs)) = &file {
            if certs.distinct_pins(&host, port) > 1 {
                out.push(TrustConflict { file: cp.file_name(), host: host_key(&host, port) });
            }
        }
    }
    out.sort_by(|a, b| (a.file, &a.host).cmp(&(b.file, &b.host)));
    out.dedup();
    out
}
