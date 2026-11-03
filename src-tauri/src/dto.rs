//! Wire DTOs (camelCase, ADR-0008) and the parsing helpers every command uses on untrusted
//! input. Nothing in this module carries secret material outward.

use mooring_core::{Connection, ConnectionId, CredentialId, Folder, FolderId, Protocol};
use mooring_store::{ConnectionHit, CredentialKind, CredentialMeta, Store};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{IpcError, IpcResult};

/// Longest id string accepted before parsing (a hyphenated UUID is 36).
const MAX_ID_LEN: usize = 64;

/// Every protocol the UI may name (`ProtocolName` in packages/ui).
const PROTOCOLS: [Protocol; 6] = [
    Protocol::Ssh,
    Protocol::Rdp,
    Protocol::Vnc,
    Protocol::Web,
    Protocol::Kubernetes,
    Protocol::VsphereConsole,
];

fn parse_uuid<T: std::str::FromStr>(field: &str, raw: &str) -> IpcResult<T> {
    if raw.len() > MAX_ID_LEN {
        return Err(IpcError::invalid(field, "not a UUID"));
    }
    raw.trim().parse().map_err(|_| IpcError::invalid(field, "not a UUID"))
}

/// Parse a folder id from IPC.
pub fn folder_id(field: &str, raw: &str) -> IpcResult<FolderId> {
    parse_uuid(field, raw)
}

/// Parse a connection id from IPC.
pub fn connection_id(field: &str, raw: &str) -> IpcResult<ConnectionId> {
    parse_uuid(field, raw)
}

/// Parse a credential id from IPC.
pub fn credential_id(field: &str, raw: &str) -> IpcResult<CredentialId> {
    parse_uuid(field, raw)
}

/// Parse an optional credential id.
pub fn opt_credential_id(field: &str, raw: Option<&str>) -> IpcResult<Option<CredentialId>> {
    raw.map(|r| credential_id(field, r)).transpose()
}

/// Parse a protocol by its stable name (`ssh`, `vsphere-console`, ...).
pub fn protocol(raw: &str) -> IpcResult<Protocol> {
    PROTOCOLS
        .into_iter()
        .find(|p| p.name() == raw)
        .ok_or_else(|| IpcError::invalid("protocol", "unknown protocol"))
}

/// Port from IPC: `null` = protocol default, else 1..=65535.
pub fn port(raw: Option<u32>) -> IpcResult<Option<u16>> {
    raw.map(|p| {
        u16::try_from(p)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| IpcError::invalid("port", "must be 1..=65535"))
    })
    .transpose()
}

/// Credential kind by its stable wire name (ADR-0009 §1).
pub fn credential_kind(raw: &str) -> IpcResult<CredentialKind> {
    CredentialKind::parse(raw).ok_or_else(|| IpcError::invalid("kind", "unknown credential kind"))
}

/// RFC 3339 UTC.
pub fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// `Folder` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderDto {
    /// Id.
    pub id: String,
    /// Parent, `null` for the root.
    pub parent_id: Option<String>,
    /// Name.
    pub name: String,
    /// Inherited credential.
    pub default_credential_id: Option<String>,
    /// Position in the store's sibling order (`sort`, then name).
    pub sort: i64,
}

fn folder_dto(f: &Folder, sort: usize) -> FolderDto {
    FolderDto {
        id: f.id.to_string(),
        parent_id: f.parent.map(|p| p.to_string()),
        name: f.name.clone(),
        default_credential_id: f.default_credential.map(|c| c.to_string()),
        sort: i64::try_from(sort).unwrap_or(i64::MAX),
    }
}

/// Every folder as DTOs, in store order.
pub fn folders(store: &Store) -> IpcResult<Vec<FolderDto>> {
    Ok(store.list_folders()?.iter().enumerate().map(|(i, f)| folder_dto(f, i)).collect())
}

/// One folder as a DTO (its `sort` is its position in the store order).
pub fn folder(store: &Store, id: FolderId) -> IpcResult<FolderDto> {
    let all = store.list_folders()?;
    all.iter()
        .enumerate()
        .find(|(_, f)| f.id == id)
        .map(|(i, f)| folder_dto(f, i))
        .ok_or_else(|| IpcError::new("tree.not_found", "folder not found"))
}

/// `ConnectionSummary` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDto {
    /// Id.
    pub id: String,
    /// Folder.
    pub folder_id: String,
    /// Name.
    pub name: String,
    /// Protocol name.
    pub protocol: &'static str,
    /// Host.
    pub host: String,
    /// Port, `null` = protocol default.
    pub port: Option<u16>,
    /// Own credential override.
    pub credential_id: Option<String>,
    /// Credential after inheritance.
    pub effective_credential_id: Option<String>,
    /// Replaces the effective credential's username for this connection.
    pub username_override: Option<String>,
    /// Replaces the effective credential's domain for this connection.
    pub domain_override: Option<String>,
    /// RD Gateway credential (`null` = same as the session credential).
    pub gateway_credential_id: Option<String>,
    /// Become (`sudo_become`) credential.
    pub become_credential_id: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Created.
    pub created_at: String,
    /// Last change. The store does not expose `updated_at` for connections yet, so this is
    /// `createdAt` (see handoff, Left open).
    pub updated_at: String,
}

/// One connection as a DTO, with its effective credential.
pub fn connection(store: &Store, c: &Connection) -> IpcResult<ConnectionDto> {
    let effective = store.effective_credential(c.id)?;
    Ok(ConnectionDto {
        id: c.id.to_string(),
        folder_id: c.folder.to_string(),
        name: c.name.clone(),
        protocol: c.protocol.name(),
        host: c.host.clone(),
        port: c.port,
        credential_id: c.credential.map(|x| x.to_string()),
        effective_credential_id: effective.map(|x| x.to_string()),
        username_override: c.username_override.clone(),
        domain_override: c.domain_override.clone(),
        gateway_credential_id: c.gateway_credential.map(|x| x.to_string()),
        become_credential_id: c.become_credential.map(|x| x.to_string()),
        tags: c.tags.clone(),
        created_at: ts(c.created_at),
        updated_at: ts(c.created_at),
    })
}

/// `{ folders, connections }`.
#[derive(Debug, Clone, Serialize)]
pub struct TreeDto {
    /// Folders.
    pub folders: Vec<FolderDto>,
    /// Connections.
    pub connections: Vec<ConnectionDto>,
}

/// `ConnectionHit` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HitDto {
    /// Id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Host.
    pub host: String,
    /// Folder.
    pub folder_id: String,
    /// Protocol name.
    pub protocol: &'static str,
}

impl From<&ConnectionHit> for HitDto {
    fn from(h: &ConnectionHit) -> Self {
        Self {
            id: h.id.to_string(),
            name: h.name.clone(),
            host: h.host.clone(),
            folder_id: h.folder.to_string(),
            protocol: h.protocol.name(),
        }
    }
}

/// `CredentialMeta` on the wire (ADR-0009 §6). `fields` is non-secret only; `secretNames`
/// reports presence, never content.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDto {
    /// Id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Kind wire name.
    pub kind: &'static str,
    /// Plain fields (`snake_case` keys, as in `KindSchema.fields`).
    pub fields: serde_json::Value,
    /// Stored secret names.
    pub secret_names: Vec<&'static str>,
    /// `SHA256:…` for `ssh_key` / `x509`.
    pub fingerprint: Option<String>,
    /// Created.
    pub created_at: String,
    /// Last change.
    pub updated_at: String,
}

impl From<&CredentialMeta> for CredentialDto {
    fn from(m: &CredentialMeta) -> Self {
        Self {
            id: m.id.to_string(),
            name: m.name.clone(),
            kind: m.kind.name(),
            fields: m.fields.to_value(),
            secret_names: m.secret_names.iter().map(|n| n.as_str()).collect(),
            fingerprint: m.fingerprint().map(str::to_owned),
            created_at: ts(m.created_at),
            updated_at: ts(m.updated_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_validated_without_echo() {
        let e = folder_id("id", "'; DROP TABLE folder; --").expect_err("bad");
        assert_eq!(e.code, "input.invalid");
        assert!(!e.message.contains("DROP"));
        assert!(folder_id("id", &"a".repeat(10_000)).is_err());
        let id = FolderId::new();
        assert_eq!(folder_id("id", &id.to_string()).expect("ok"), id);
    }

    #[test]
    fn protocols_ports_and_kinds() {
        for p in PROTOCOLS {
            assert_eq!(protocol(p.name()).expect("known"), p);
        }
        assert_eq!(protocol("vsphere-console").expect("ok"), Protocol::VsphereConsole);
        assert!(protocol("telnet").is_err());
        assert_eq!(port(None).expect("ok"), None);
        assert_eq!(port(Some(22)).expect("ok"), Some(22));
        assert!(port(Some(0)).is_err());
        assert!(port(Some(65_536)).is_err());
        assert_eq!(credential_kind("ssh_key").expect("ok"), CredentialKind::SshKey);
        assert!(credential_kind("password").is_err(), "legacy kind names are gone");
    }

    #[test]
    fn dtos_are_camel_case() {
        let f = Folder::new(None, "Root").expect("folder");
        let json = serde_json::to_string(&folder_dto(&f, 0)).expect("json");
        assert!(json.contains("\"parentId\":null") && json.contains("\"defaultCredentialId\""));
        let store = Store::open_in_memory().expect("store");
        let vault = mooring_vault::Vault::create(
            &secrecy::SecretString::from("test-only master pw".to_owned()),
            mooring_vault::KdfParams::TEST,
        )
        .expect("vault");
        let secrets = [(mooring_core::SecretName::Password, &b"test-only"[..])].into_iter().collect();
        let fields = serde_json::json!({"username": "ops"});
        let m = store
            .create_credential(&vault, "ops", CredentialKind::UserPassword, &fields, &secrets)
            .expect("meta");
        let json = serde_json::to_string(&CredentialDto::from(&m)).expect("json");
        assert!(json.contains("\"createdAt\"") && json.contains("\"secretNames\":[\"password\"]"), "{json}");
        assert!(json.contains("\"fields\":{\"username\":\"ops\"}") && json.contains("\"fingerprint\":null"));
        assert!(!json.contains("test-only"), "{json}");
    }
}
