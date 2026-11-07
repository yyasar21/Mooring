//! Portable backup document v2 (ADR-0023 §1): the vault header (without the per-device
//! `keyring_wrap`) plus the logical [`Snapshot`], inside the passphrase-protected `age`
//! container of `mooring-vault` (`export_age_bytes` / `import_age_bytes`, caps and work
//! factors there). Secrets stay sealed under the exporting vault's DEK; a foreign document is
//! opened with the source master password and re-sealed by [`reseal_snapshot`].
//!
//! v1 documents (`mooring_vault::ExportDocument`, the committed vectors) still import:
//! credentials only, the opaque `folders` / `connections` values are ignored with a report.
//!
//! Every byte of an import is hostile (T4): the payload is parsed with `deny_unknown_fields`,
//! duplicate JSON keys are refused (a map that silently keeps the last value would let one
//! record shadow another), ids are checked across tables, the folder graph must be acyclic
//! and closed, kinds and protocols must be known. A document that fails any check is refused
//! as a whole; nothing is applied partially.

use std::collections::{BTreeMap, BTreeSet};

use mooring_core::{CredentialKind, Protocol};
use mooring_store::{ConnectionRow, CredentialRow, FolderRow};
use mooring_vault::{Header, Sealed, Vault, VaultError};
use secrecy::SecretString;
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::snapshot::{Snapshot, Tombstone, SNAPSHOT_VERSION};
use crate::SyncError;

/// Document version written by [`export_age`].
pub const DOCUMENT_VERSION: u32 = 2;
/// Longest `exported_at` / `app_version` text accepted.
pub const MAX_META_CHARS: usize = 64;
/// Every protocol a connection row may name (the store's own list is private).
const PROTOCOLS: [Protocol; 6] = [
    Protocol::Ssh,
    Protocol::Rdp,
    Protocol::Vnc,
    Protocol::Web,
    Protocol::Kubernetes,
    Protocol::VsphereConsole,
];

/// What a backup holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportDocument {
    /// [`DOCUMENT_VERSION`].
    pub version: u32,
    /// Vault header without `keyring_wrap` (the wrap is per device, ADR-0022).
    pub header: Header,
    /// Folders, connections, credentials (sealed secrets) and trust stores.
    pub snapshot: Snapshot,
    /// RFC 3339 time of the export.
    pub exported_at: String,
    /// Mooring version that wrote it.
    pub app_version: String,
}

/// A parsed import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Imported {
    /// A v2 document, validated.
    V2(ExportDocument),
    /// A v1 document: credentials only (`folders` / `connections` were opaque and are
    /// ignored); `note` is the report line for the user.
    V1 {
        /// Source vault header.
        header: Header,
        /// Credential records with their sealed fields.
        credentials: Vec<mooring_vault::ExportedRecord>,
        /// Report line.
        note: &'static str,
    },
}

/// Export / import failure. Fixed texts; never the passphrase or any plaintext.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    /// The export passphrase is shorter than the policy minimum.
    #[error("export passphrase too short (minimum {min} characters)")]
    WeakPassphrase {
        /// Minimum accepted length in characters.
        min: usize,
    },
    /// Wrong passphrase, or the file was modified.
    #[error("wrong passphrase or corrupted export")]
    Passphrase,
    /// Over a cap (file, payload, record count, trust file).
    #[error("export file too large")]
    TooLarge,
    /// A document version this build cannot read.
    #[error("unsupported export document version {0}")]
    Version(u32),
    /// Malformed document.
    #[error("malformed export document: {0}")]
    Format(&'static str),
    /// A sealed secret of the file could not be opened (foreign vault: wrong source password
    /// or tampered record).
    #[error("a sealed secret of the export could not be opened")]
    Sealed,
}

impl From<VaultError> for ExportError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::WeakPassword { min } => Self::WeakPassphrase { min },
            VaultError::Export(
                "export file too large" | "export payload too large" | "export too large",
            ) => Self::TooLarge,
            VaultError::Export("wrong passphrase or corrupted export") => Self::Passphrase,
            VaultError::Export(what) => Self::Format(what),
            VaultError::Tampered | VaultError::Locked => Self::Sealed,
            VaultError::KdfParams(_) | VaultError::Format(_) => Self::Format("vault header"),
            _ => Self::Format("vault"),
        }
    }
}

impl From<SyncError> for ExportError {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::TooLarge => Self::TooLarge,
            SyncError::Format(what) => Self::Format(what),
            SyncError::Vault(v) => v.into(),
            _ => Self::Format("snapshot"),
        }
    }
}

/// The header to write: the vault's, without the per-device wrap.
pub fn exportable_header(vault: &Vault) -> Header {
    Header { keyring_wrap: None, ..vault.header().clone() }
}

/// Encrypt `doc` to an armored `age` file (work factor of `mooring-vault`). `keyring_wrap`
/// is stripped, tombstones are dropped (a backup never deletes), the payload is zeroized.
pub fn export_age(doc: &ExportDocument, passphrase: &SecretString) -> Result<Vec<u8>, ExportError> {
    export_inner(doc, passphrase, None)
}

/// [`export_age`] with a low scrypt work factor: tests only.
pub fn export_age_fast(
    doc: &ExportDocument,
    passphrase: &SecretString,
) -> Result<Vec<u8>, ExportError> {
    export_inner(doc, passphrase, Some(10))
}

fn export_inner(
    doc: &ExportDocument,
    passphrase: &SecretString,
    log_n: Option<u8>,
) -> Result<Vec<u8>, ExportError> {
    let mut clean = doc.clone();
    clean.version = DOCUMENT_VERSION;
    clean.header.keyring_wrap = None;
    clean.snapshot.tombstones.clear();
    validate(&clean)?;
    let json = Zeroizing::new(
        serde_json::to_vec(&clean).map_err(|_| ExportError::Format("could not serialise"))?,
    );
    Ok(match log_n {
        None => mooring_vault::export_age_bytes(&json, passphrase)?,
        Some(n) => mooring_vault::export_age_bytes_with_work_factor(&json, passphrase, n)?,
    })
}

/// Decrypt and parse an export (v2, or v1 for credentials only). Refused as a whole on any
/// structural problem; nothing here touches a store.
pub fn import_age(bytes: &[u8], passphrase: &SecretString) -> Result<Imported, ExportError> {
    #[derive(Deserialize)]
    struct Probe {
        version: Option<u32>,
    }
    let json = mooring_vault::import_age_bytes(bytes, passphrase)?;
    let probe: Probe = serde_json::from_slice(&json).map_err(|_| ExportError::Format("JSON"))?;
    match probe.version {
        Some(DOCUMENT_VERSION) => {
            let wire: DocumentWire =
                serde_json::from_slice(&json).map_err(|_| ExportError::Format("document"))?;
            let doc = wire.into_document();
            validate(&doc)?;
            Ok(Imported::V2(doc))
        }
        None => {
            let v1: mooring_vault::ExportDocument = serde_json::from_slice(&json)
                .map_err(|_| ExportError::Format("not a Mooring document"))?;
            v1.header.check().map_err(|_| ExportError::Format("vault header"))?;
            if v1.header.keyring_wrap.is_some() {
                return Err(ExportError::Format("v1 document carries a keyring wrap"));
            }
            Ok(Imported::V1 {
                header: v1.header,
                credentials: v1.credentials,
                note: "v1 backup: credentials imported; folders and connections were not \
                       part of the v1 format and were skipped",
            })
        }
        Some(other) => Err(ExportError::Version(other)),
    }
}

/// Structural checks of a v2 document (export and import sides alike).
pub fn validate(doc: &ExportDocument) -> Result<(), ExportError> {
    if doc.version != DOCUMENT_VERSION {
        return Err(ExportError::Version(doc.version));
    }
    doc.header.check().map_err(|_| ExportError::Format("vault header"))?;
    if doc.header.keyring_wrap.is_some() {
        return Err(ExportError::Format("document carries a keyring wrap"));
    }
    if doc.header.vault_id.is_nil() || doc.snapshot.vault_id != doc.header.vault_id {
        return Err(ExportError::Format("vault id"));
    }
    let meta_ok = |s: &str| s.chars().count() <= MAX_META_CHARS && !s.chars().any(char::is_control);
    if !meta_ok(&doc.exported_at) || !meta_ok(&doc.app_version) {
        return Err(ExportError::Format("metadata"));
    }
    let s = &doc.snapshot;
    s.validate()?;
    if s.version != SNAPSHOT_VERSION {
        return Err(ExportError::Format("snapshot version"));
    }
    // One id namespace across the three tables: a credential that is also a folder is a
    // crafted file, not a backup.
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for id in s.folders.keys().chain(s.connections.keys()).chain(s.credentials.keys()) {
        if !ids.insert(id) {
            return Err(ExportError::Format("duplicate id"));
        }
    }
    for f in s.folders.values() {
        if let Some(p) = &f.parent_id {
            if !s.folders.contains_key(p) {
                return Err(ExportError::Format("folder parent missing"));
            }
        }
        if f.default_credential_id.as_ref().is_some_and(|c| !s.credentials.contains_key(c)) {
            return Err(ExportError::Format("folder default credential missing"));
        }
    }
    if s.folders.keys().any(|id| has_cycle(s, id)) {
        return Err(ExportError::Format("folder cycle"));
    }
    if s.folders.values().filter(|f| f.parent_id.is_none()).count() > 1 {
        return Err(ExportError::Format("several root folders"));
    }
    for c in s.connections.values() {
        if !s.folders.contains_key(&c.folder_id) {
            return Err(ExportError::Format("connection folder missing"));
        }
        if !PROTOCOLS.iter().any(|p| p.name() == c.protocol) {
            return Err(ExportError::Format("unknown connection protocol"));
        }
        let creds = c.credential_id.iter().chain(c.roles.values());
        if creds.into_iter().any(|id| !s.credentials.contains_key(id)) {
            return Err(ExportError::Format("connection credential missing"));
        }
    }
    for c in s.credentials.values() {
        if CredentialKind::parse(&c.kind).is_none() {
            return Err(ExportError::Format("unknown credential kind"));
        }
        for sealed in c.secrets.values() {
            serde_json::from_str::<Sealed>(sealed)
                .map_err(|_| ExportError::Format("sealed secret"))?;
        }
    }
    Ok(())
}

fn has_cycle(s: &Snapshot, start: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut cur = Some(start.to_owned());
    while let Some(id) = cur {
        if !seen.insert(id.clone()) {
            return true;
        }
        cur = s.folders.get(&id).and_then(|f| f.parent_id.clone());
    }
    false
}

/// Re-seal every secret of `snapshot` from `from` (the file's vault, unlocked with the source
/// master password) to `to` (ours). Record ids and secret names are unchanged. Any secret
/// that fails to open refuses the whole snapshot.
pub fn reseal_snapshot(
    snapshot: &mut Snapshot,
    from: &Vault,
    to: &Vault,
) -> Result<(), ExportError> {
    for c in snapshot.credentials.values_mut() {
        for (name, sealed) in &mut c.secrets {
            let s: Sealed =
                serde_json::from_str(sealed).map_err(|_| ExportError::Format("sealed secret"))?;
            let plain = from.open(&c.id, name, &s).map_err(|_| ExportError::Sealed)?;
            let out = to.seal(&c.id, name, &plain).map_err(|_| ExportError::Sealed)?;
            *sealed =
                serde_json::to_string(&out).map_err(|_| ExportError::Format("sealed secret"))?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ hostile-safe parsing

/// A map that refuses duplicate keys (serde's default silently keeps the last value).
fn checked_map<'de, D, V>(d: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: DeserializeOwned,
{
    struct MapVisitor<V>(std::marker::PhantomData<V>);
    impl<'de, V: DeserializeOwned> Visitor<'de> for MapVisitor<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map with unique keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((k, v)) = m.next_entry::<String, V>()? {
                if out.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom("duplicate key"));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(MapVisitor(std::marker::PhantomData))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    #[serde(deserialize_with = "checked_map")]
    connections: BTreeMap<String, ConnectionRow>,
    #[serde(deserialize_with = "checked_map")]
    credentials: BTreeMap<String, CredentialRow>,
    device_name: String,
    #[serde(deserialize_with = "checked_map")]
    folders: BTreeMap<String, FolderRow>,
    /// Parsed for shape (duplicate keys refused), then dropped: a backup never deletes.
    #[serde(default, rename = "tombstones", deserialize_with = "checked_map")]
    _tombstones: BTreeMap<String, Tombstone>,
    #[serde(deserialize_with = "checked_map")]
    trust: BTreeMap<String, BTreeSet<String>>,
    vault_id: Uuid,
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire {
    version: u32,
    header: Header,
    snapshot: SnapshotWire,
    exported_at: String,
    app_version: String,
}

impl DocumentWire {
    fn into_document(self) -> ExportDocument {
        let s = self.snapshot;
        let snapshot = Snapshot {
            connections: s.connections,
            credentials: s.credentials,
            device_name: s.device_name,
            folders: s.folders,
            // Ignored on purpose: a backup never deletes (ADR-0023 §2).
            tombstones: BTreeMap::new(),
            trust: s.trust,
            vault_id: s.vault_id,
            version: s.version,
        };
        ExportDocument {
            version: self.version,
            header: self.header,
            snapshot,
            exported_at: self.exported_at,
            app_version: self.app_version,
        }
    }
}

/// Parse a decrypted payload without the age layer: the fuzz entry (`export_document_json`).
/// Never panics.
pub fn parse_document_json(json: &[u8]) -> Result<ExportDocument, ExportError> {
    if json.len() > mooring_vault::MAX_EXPORT_BYTES {
        return Err(ExportError::TooLarge);
    }
    let wire: DocumentWire =
        serde_json::from_slice(json).map_err(|_| ExportError::Format("document"))?;
    let doc = wire.into_document();
    validate(&doc)?;
    Ok(doc)
}
