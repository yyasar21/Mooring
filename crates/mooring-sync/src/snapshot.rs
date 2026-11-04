//! The logical snapshot (ADR-0017 §1): what one device publishes.
//!
//! * Folders, connections (tags, roles, options), credentials (plaintext fields + secrets
//!   **still sealed** under the DEK; the AAD binds record id + secret name, so they open on
//!   every device of the vault), the trust stores (`known_hosts`, every `known_*_certs`,
//!   owner decision 10) and tombstones.
//! * Not included: the vault header / KEK material (it travels as its own `header` object),
//!   the audit log, per-device settings, web cookie stores, the keyring wrap.
//! * Encoding: canonical JSON — every map is a `BTreeMap`, struct fields are declared in
//!   alphabetical order, trust lines are sorted and unique — so equal snapshots give equal
//!   bytes. Decoding is capped and validated ([`Snapshot::decode`]).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;

use mooring_core::known_certs::CertProtocol;
use mooring_store::{ConnectionRow, CredentialRow, FolderRow, Store, SyncRows};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::blob::MAX_PLAINTEXT;
use crate::error::{Result, SyncError};

/// Snapshot schema version.
pub const SNAPSHOT_VERSION: u32 = 1;
/// SSH trust store file name.
pub const KNOWN_HOSTS: &str = "known_hosts";
/// Largest trust-store file read or written.
pub const MAX_TRUST_FILE: usize = 8 << 20;
/// Longest trust line.
pub const MAX_TRUST_LINE: usize = 16 * 1024;
/// Most rows per table.
pub const MAX_ROWS: usize = 100_000;
/// Most tombstones kept.
pub const MAX_TOMBSTONES: usize = 20_000;

/// Which table a record lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// `folder`.
    Folder,
    /// `connection`.
    Connection,
    /// `credential`.
    Credential,
}

impl RecordKind {
    /// Stable name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Connection => "connection",
            Self::Credential => "credential",
        }
    }
}

/// A deleted record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    /// RFC 3339 time the deletion was first published.
    pub deleted_at: String,
    /// Record id.
    pub id: String,
    /// Table.
    pub kind: RecordKind,
}

/// Tombstone map key: `<kind>:<id>`.
pub fn tomb_key(kind: RecordKind, id: &str) -> String {
    format!("{}:{id}", kind.name())
}

/// One device's logical view of the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Connections by id.
    pub connections: BTreeMap<String, ConnectionRow>,
    /// Credentials by id (secrets sealed).
    pub credentials: BTreeMap<String, CredentialRow>,
    /// Display name of the device that wrote it (conflict suffixes, "last pushed by").
    pub device_name: String,
    /// Folders by id.
    pub folders: BTreeMap<String, FolderRow>,
    /// Deleted records by [`tomb_key`].
    pub tombstones: BTreeMap<String, Tombstone>,
    /// Trust-store file name → sorted unique non-empty lines.
    pub trust: BTreeMap<String, BTreeSet<String>>,
    /// Owning vault.
    pub vault_id: Uuid,
    /// [`SNAPSHOT_VERSION`].
    pub version: u32,
}

/// Every trust-store file that is synced.
pub fn trust_file_names() -> impl Iterator<Item = &'static str> {
    std::iter::once(KNOWN_HOSTS).chain(CertProtocol::ALL.into_iter().map(CertProtocol::file_name))
}

impl Snapshot {
    /// An empty snapshot of `vault_id`.
    pub fn empty(vault_id: Uuid, device_name: &str) -> Self {
        Self {
            connections: BTreeMap::new(),
            credentials: BTreeMap::new(),
            device_name: device_name.to_owned(),
            folders: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            trust: BTreeMap::new(),
            vault_id,
            version: SNAPSHOT_VERSION,
        }
    }

    /// The store rows of this snapshot.
    pub fn rows(&self) -> SyncRows {
        SyncRows {
            connections: self.connections.clone(),
            credentials: self.credentials.clone(),
            folders: self.folders.clone(),
        }
    }

    /// Same rows and trust lines (ignores writer name and tombstones, which are derived).
    pub fn same_content(&self, other: &Self) -> bool {
        self.folders == other.folders
            && self.connections == other.connections
            && self.credentials == other.credentials
            && self.trust == other.trust
    }

    /// Canonical JSON bytes (zeroized on drop: they hold the plaintext inventory).
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let v = serde_json::to_vec(self).map_err(|_| SyncError::Format("snapshot encode"))?;
        if v.len() > MAX_PLAINTEXT {
            return Err(SyncError::TooLarge);
        }
        Ok(Zeroizing::new(v))
    }

    /// Parse and validate; `vault_id` must match. Never panics (fuzz target).
    pub fn decode(bytes: &[u8], vault_id: Uuid) -> Result<Self> {
        if bytes.len() > MAX_PLAINTEXT {
            return Err(SyncError::TooLarge);
        }
        let s: Self =
            serde_json::from_slice(bytes).map_err(|_| SyncError::Format("snapshot JSON"))?;
        s.validate()?;
        if s.vault_id != vault_id {
            return Err(SyncError::WrongVault);
        }
        Ok(s)
    }

    /// Structural checks (the store validates rows again on apply).
    pub fn validate(&self) -> Result<()> {
        let fmt = SyncError::Format;
        if self.version != SNAPSHOT_VERSION {
            return Err(fmt("unsupported snapshot version"));
        }
        if self.device_name.chars().count() > 120 || self.device_name.chars().any(char::is_control)
        {
            return Err(fmt("device name"));
        }
        let rows = [self.folders.len(), self.connections.len(), self.credentials.len()];
        if rows.iter().any(|n| *n > MAX_ROWS) || self.tombstones.len() > MAX_TOMBSTONES {
            return Err(SyncError::TooLarge);
        }
        let ids_match = self.folders.iter().all(|(k, v)| *k == v.id)
            && self.connections.iter().all(|(k, v)| *k == v.id)
            && self.credentials.iter().all(|(k, v)| *k == v.id)
            && self.tombstones.iter().all(|(k, t)| *k == tomb_key(t.kind, &t.id));
        if !ids_match {
            return Err(fmt("map key does not match record id"));
        }
        let names: BTreeSet<&str> = trust_file_names().collect();
        for (name, lines) in &self.trust {
            if !names.contains(name.as_str()) {
                return Err(fmt("unknown trust file"));
            }
            if lines.iter().map(|l| l.len() + 1).sum::<usize>() > MAX_TRUST_FILE {
                return Err(SyncError::TooLarge);
            }
            if lines.iter().any(|l| !valid_line(l)) {
                return Err(fmt("trust line"));
            }
        }
        Ok(())
    }
}

fn valid_line(l: &str) -> bool {
    !l.is_empty() && l.len() <= MAX_TRUST_LINE && !l.contains(['\n', '\r']) && l.trim() == l
}

/// Read one trust file as a sorted line set (absent → empty). Over the cap → `TooLarge`.
pub fn read_trust_file(path: &Path) -> Result<BTreeSet<String>> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    f.take(MAX_TRUST_FILE as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > MAX_TRUST_FILE {
        return Err(SyncError::TooLarge);
    }
    let text = String::from_utf8(buf).map_err(|_| SyncError::Format("trust file is not UTF-8"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.len() <= MAX_TRUST_LINE)
        .map(str::to_owned)
        .collect())
}

/// Atomically replace a trust file (`<name>.sync-tmp` + rename, owner-only on unix).
pub fn write_trust_file(path: &Path, lines: &BTreeSet<String>) -> Result<()> {
    let mut text = String::new();
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    let tmp = path.with_extension("sync-tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        std::io::Write::write_all(&mut f, text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Build the local snapshot: every store row plus the trust files under `trust_dir`.
/// Tombstones are left empty; the engine derives them against its base.
pub fn from_store(
    store: &Store,
    trust_dir: &Path,
    vault_id: Uuid,
    device_name: &str,
) -> Result<Snapshot> {
    let rows = store.export_sync_rows()?;
    let mut s = Snapshot::empty(vault_id, device_name);
    s.folders = rows.folders;
    s.connections = rows.connections;
    s.credentials = rows.credentials;
    for name in trust_file_names() {
        let lines = read_trust_file(&trust_dir.join(name))?;
        if !lines.is_empty() {
            s.trust.insert(name.to_owned(), lines);
        }
    }
    s.validate()?;
    if s.encode()?.len() > MAX_PLAINTEXT {
        return Err(SyncError::TooLarge);
    }
    Ok(s)
}

/// Write `snapshot` to the device: store rows in one transaction, then each trust file whose
/// content differs (files the snapshot does not name are emptied when they exist).
pub fn apply(store: &Store, trust_dir: &Path, snapshot: &Snapshot) -> Result<()> {
    snapshot.validate()?;
    store.replace_sync_rows(&snapshot.rows())?;
    let empty = BTreeSet::new();
    for name in trust_file_names() {
        let want = snapshot.trust.get(name).unwrap_or(&empty);
        let path = trust_dir.join(name);
        let have = read_trust_file(&path)?;
        if &have != want && (path.exists() || !want.is_empty()) {
            write_trust_file(&path, want)?;
        }
    }
    Ok(())
}

/// Tombstones of `local` against `base`: the base's, plus every base record missing locally,
/// minus every record that exists locally again. Capped to the newest [`MAX_TOMBSTONES`].
pub fn derive_tombstones(local: &mut Snapshot, base: Option<&Snapshot>, now: &str) {
    let Some(base) = base else { return };
    let mut t = base.tombstones.clone();
    let mut gone = |kind: RecordKind, id: &String| {
        t.entry(tomb_key(kind, id)).or_insert_with(|| Tombstone {
            deleted_at: now.to_owned(),
            id: id.clone(),
            kind,
        });
    };
    base.folders.keys().filter(|k| !local.folders.contains_key(*k)).for_each(|k| {
        gone(RecordKind::Folder, k);
    });
    base.connections.keys().filter(|k| !local.connections.contains_key(*k)).for_each(|k| {
        gone(RecordKind::Connection, k);
    });
    base.credentials.keys().filter(|k| !local.credentials.contains_key(*k)).for_each(|k| {
        gone(RecordKind::Credential, k);
    });
    local.tombstones.extend(t);
    prune_tombstones(local);
}

/// Drop tombstones of live records and keep the newest [`MAX_TOMBSTONES`].
pub fn prune_tombstones(s: &mut Snapshot) {
    let live = |t: &Tombstone| match t.kind {
        RecordKind::Folder => s.folders.contains_key(&t.id),
        RecordKind::Connection => s.connections.contains_key(&t.id),
        RecordKind::Credential => s.credentials.contains_key(&t.id),
    };
    let mut keep: Vec<(String, Tombstone)> = s
        .tombstones
        .iter()
        .filter(|(_, t)| !live(t))
        .map(|(k, t)| (k.clone(), t.clone()))
        .collect();
    if keep.len() > MAX_TOMBSTONES {
        keep.sort_by(|a, b| b.1.deleted_at.cmp(&a.1.deleted_at).then_with(|| a.0.cmp(&b.0)));
        keep.truncate(MAX_TOMBSTONES);
    }
    s.tombstones = keep.into_iter().collect();
}
