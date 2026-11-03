//! Folders, connections and credential references.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{NexusError, Result};

macro_rules! id_type {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("Opaque identifier of a ", $kind, ".")]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh random id.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// The kind name used in error messages.
            #[must_use]
            pub const fn kind() -> &'static str {
                $kind
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = NexusError;
            fn from_str(s: &str) -> Result<Self> {
                Uuid::parse_str(s).map(Self).map_err(|_| NexusError::Invalid {
                    field: concat!($kind, " id"),
                    reason: "not a UUID".into(),
                })
            }
        }
    };
}

id_type!(FolderId, "folder");
id_type!(ConnectionId, "connection");
id_type!(CredentialId, "credential");

/// Which protocol a connection speaks. Each variant maps to one `nexus-proto-*` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Secure Shell (and SFTP).
    Ssh,
    /// Microsoft Remote Desktop Protocol.
    Rdp,
    /// RFB / VNC.
    Vnc,
    /// An HTTPS page opened in an isolated `WebView`.
    Web,
    /// `kubectl exec` / port-forward into a pod.
    Kubernetes,
    /// vSphere `WebMKS` console.
    VsphereConsole,
}

impl Protocol {
    /// Default TCP port for the protocol, when one exists.
    #[must_use]
    pub const fn default_port(self) -> Option<u16> {
        match self {
            Self::Ssh => Some(22),
            Self::Rdp => Some(3389),
            Self::Vnc => Some(5900),
            Self::Web => Some(443),
            Self::Kubernetes | Self::VsphereConsole => None,
        }
    }

    /// Stable lowercase name, also used as the audit `protocol` field.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Web => "web",
            Self::Kubernetes => "kubernetes",
            Self::VsphereConsole => "vsphere-console",
        }
    }
}

/// A folder in the connection tree. `parent == None` means the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    /// Folder id.
    pub id: FolderId,
    /// Parent folder, `None` for the root.
    pub parent: Option<FolderId>,
    /// Display name, 1..=120 chars.
    pub name: String,
    /// Credential inherited by children that set none of their own.
    pub default_credential: Option<CredentialId>,
}

/// A connection. Never holds secret material — only a [`CredentialId`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// Connection id.
    pub id: ConnectionId,
    /// Folder that contains it.
    pub folder: FolderId,
    /// Display name, 1..=120 chars.
    pub name: String,
    /// Protocol.
    pub protocol: Protocol,
    /// Host name or IP. For `Web` the full URL; for `Kubernetes` the context name.
    pub host: String,
    /// Port, `None` = protocol default.
    pub port: Option<u16>,
    /// Credential override; `None` inherits from the folder chain.
    pub credential: Option<CredentialId>,
    /// Free-form tags for search and grouping.
    pub tags: Vec<String>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Maximum display-name length (characters, after trimming).
pub const MAX_NAME: usize = 120;
/// Maximum host length (bytes, after trimming).
pub const MAX_HOST: usize = 2048;
/// Maximum tag length (characters, after trimming).
pub const MAX_TAG: usize = 64;
/// Maximum number of tags per connection.
pub const MAX_TAGS: usize = 50;

fn invalid(field: &'static str, reason: String) -> NexusError {
    NexusError::Invalid { field, reason }
}

/// Validate a display name (folder, connection, credential) and return it trimmed:
/// 1..=[`MAX_NAME`] characters, no control characters. The error never echoes the input.
pub fn validate_name(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME {
        return Err(invalid("name", format!("must be 1..={MAX_NAME} characters")));
    }
    if n.chars().any(char::is_control) {
        return Err(invalid("name", "contains control characters".into()));
    }
    Ok(n.to_owned())
}

/// Validate a host (name, IP, URL or context) and return it trimmed: 1..=[`MAX_HOST`] bytes,
/// no whitespace or control characters.
pub fn validate_host(host: &str) -> Result<String> {
    let h = host.trim();
    if h.is_empty() || h.len() > MAX_HOST || h.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid(
            "host",
            format!("empty, longer than {MAX_HOST} bytes or has spaces/control characters"),
        ));
    }
    Ok(h.to_owned())
}

/// Validate one tag and return it trimmed: 1..=[`MAX_TAG`] characters, no control characters.
/// The count limit [`MAX_TAGS`] applies to the list and is checked by the caller.
pub fn validate_tag(tag: &str) -> Result<String> {
    let t = tag.trim();
    if t.is_empty() || t.chars().count() > MAX_TAG {
        return Err(invalid("tag", format!("must be 1..={MAX_TAG} characters")));
    }
    if t.chars().any(char::is_control) {
        return Err(invalid("tag", "contains control characters".into()));
    }
    Ok(t.to_owned())
}

impl Folder {
    /// Build a validated folder.
    pub fn new(parent: Option<FolderId>, name: impl Into<String>) -> Result<Self> {
        let name = validate_name(&name.into())?;
        Ok(Self { id: FolderId::new(), parent, name, default_credential: None })
    }
}

impl Connection {
    /// Build a validated connection.
    pub fn new(
        folder: FolderId,
        name: impl Into<String>,
        protocol: Protocol,
        host: impl Into<String>,
    ) -> Result<Self> {
        let name = validate_name(&name.into())?;
        let host = validate_host(&host.into())?;
        Ok(Self {
            id: ConnectionId::new(),
            folder,
            name,
            protocol,
            host,
            port: None,
            credential: None,
            tags: Vec::new(),
            created_at: OffsetDateTime::now_utc(),
        })
    }

    /// Effective port.
    #[must_use]
    pub fn effective_port(&self) -> Option<u16> {
        self.port.or_else(|| self.protocol.default_port())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_names_and_hosts() {
        assert!(Folder::new(None, "   ").is_err());
        assert!(Folder::new(None, "a\u{7}b").is_err());
        let root = Folder::new(None, "Lab").expect("valid");
        assert!(Connection::new(root.id, "x", Protocol::Ssh, "bad host").is_err());
        let c = Connection::new(root.id, " xinfra01 ", Protocol::Ssh, "10.10.20.5").expect("valid");
        assert_eq!(c.name, "xinfra01");
        assert_eq!(c.effective_port(), Some(22));
    }

    #[test]
    fn public_validators() {
        assert_eq!(validate_name("  a ").expect("ok"), "a");
        assert_eq!(validate_name(&"x".repeat(MAX_NAME)).expect("max").chars().count(), MAX_NAME);
        assert!(validate_name(&"x".repeat(MAX_NAME + 1)).is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("a\nb").is_err());

        assert_eq!(validate_host(" 10.10.20.5 ").expect("ok"), "10.10.20.5");
        assert!(validate_host(&"h".repeat(MAX_HOST)).is_ok());
        assert!(validate_host(&"h".repeat(MAX_HOST + 1)).is_err());
        assert!(validate_host("a b").is_err());
        assert!(validate_host("a\u{0}b").is_err());
        assert!(validate_host("").is_err());

        assert_eq!(validate_tag(" infra ").expect("ok"), "infra");
        assert!(validate_tag(&"t".repeat(MAX_TAG)).is_ok());
        assert!(validate_tag(&"t".repeat(MAX_TAG + 1)).is_err());
        assert!(validate_tag(" ").is_err());
        assert!(validate_tag("a\u{7}").is_err());

        // errors never echo the rejected value
        let e = validate_host("secret-looking host").expect_err("spaces");
        assert!(!e.to_string().contains("secret-looking"));
    }

    #[test]
    fn connection_new_refuses_control_chars_in_host() {
        let root = Folder::new(None, "Lab").expect("valid");
        assert!(Connection::new(root.id, "x", Protocol::Ssh, "host\u{1b}[31m").is_err());
    }

    #[test]
    fn ids_round_trip_through_strings() {
        let id = ConnectionId::new();
        let parsed: ConnectionId = id.to_string().parse().expect("parse");
        assert_eq!(id, parsed);
        assert!("nope".parse::<ConnectionId>().is_err());
    }
}
