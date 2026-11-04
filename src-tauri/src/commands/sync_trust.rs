//! Conflicting pins after a sync apply (review 6 L-35, 6b: fail closed).
//!
//! Owner decision 10 syncs the trust stores, and the merge keeps every line: two devices that
//! first saw a host concurrently and accepted **different** certificates (one of them on a
//! hostile network) both keep their pin. The lines are salted HMACs, so the merge cannot see
//! that they name one host; the Tauri layer can, for the user's own connections. After every
//! apply, each `host:port` of a connection with more than one distinct fingerprint in its
//! protocol's file is audited `trust_conflict { file, host }` (names only) and listed in
//! `sync_status.conflicts` as `{ kind: "trust", id: <file>, name: <host:port> }`. Nothing is
//! resolved here: `KnownCerts::check` / `KnownHosts::check` fail closed (`http.trust_conflict`,
//! `CloseCode::TrustConflict`) until the user removes the pins. SSH `known_hosts` counts per
//! key type: several key *types* per host are normal, two keys of one type are a conflict.

use std::path::Path;

use mooring_audit::AuditEvent;
use mooring_core::known_certs::{host_key, CertProtocol, KnownCerts};
use mooring_core::Protocol;
use mooring_proto_ssh::KnownHosts;
use mooring_store::Store;
use serde::Serialize;

use crate::state::AppState;

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

/// One `sync_status.conflicts` entry: a merge conflict of the last run, or a trust conflict
/// (`{ kind: "trust", id: <file>, name: <host:port> }`) that stands until the user removes the
/// pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum StatusConflict {
    /// A record conflict of the last merge.
    Merge(mooring_sync::Conflict),
    /// Conflicting pins in a trust file (6b L-35).
    Trust {
        /// Always `trust`.
        kind: &'static str,
        /// The trust file (`known_rdp_certs`, `known_hosts`, …).
        id: &'static str,
        /// `host:port`.
        name: String,
    },
}

impl From<TrustConflict> for StatusConflict {
    fn from(c: TrustConflict) -> Self {
        Self::Trust { kind: "trust", id: c.file, name: c.host }
    }
}

/// The merge conflicts of the last run followed by the trust conflicts as they stand now.
pub fn status_conflicts(
    store: &Store,
    trust_dir: &Path,
    merge: Vec<mooring_sync::Conflict>,
) -> Vec<StatusConflict> {
    merge
        .into_iter()
        .map(StatusConflict::Merge)
        .chain(conflicts(store, trust_dir).into_iter().map(StatusConflict::from))
        .collect()
}

/// The conflicts among the connections in `store`, per protocol trust file in `trust_dir`.
/// Unreadable files are skipped (the next connect fails closed on them anyway).
pub fn conflicts(store: &Store, trust_dir: &Path) -> Vec<TrustConflict> {
    let mut out = Vec::new();
    let Ok(folders) = store.list_folders() else { return out };
    let mut hosts: Vec<(CertProtocol, String, u16)> = Vec::new();
    let mut ssh: Vec<(String, u16)> = Vec::new();
    for folder in &folders {
        let Ok(conns) = store.list_connections(folder.id) else { continue };
        for c in conns {
            let Some(port) = c.port.or_else(|| c.protocol.default_port()) else { continue };
            if c.protocol == Protocol::Ssh {
                ssh.push((c.host, port));
                continue;
            }
            if let Some(cp) = CertProtocol::ALL.into_iter().find(|p| p.connection_protocol() == Some(c.protocol)) {
                hosts.push((cp, c.host, port));
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    ssh.sort();
    ssh.dedup();
    let kh_path = trust_dir.join(AppState::KNOWN_HOSTS_FILE);
    if !ssh.is_empty() && kh_path.exists() {
        if let Ok(kh) = KnownHosts::load(&kh_path) {
            for (host, port) in ssh {
                if !kh.conflicting_key_types(&host, port).is_empty() {
                    out.push(TrustConflict { file: AppState::KNOWN_HOSTS_FILE, host: host_key(&host, port) });
                }
            }
        }
    }
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
