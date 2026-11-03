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

const MAX_NAME: usize = 120;
const MAX_HOST: usize = 2048;

fn check_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME {
        return Err(NexusError::Invalid { field: "name", reason: format!("1..={MAX_NAME} chars") });
    }
    if n.chars().any(char::is_control) {
        return Err(NexusError::Invalid { field: "name", reason: "control characters".into() });
    }
    Ok(())
}

impl Folder {
    /// Build a validated folder.
    pub fn new(parent: Option<FolderId>, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        check_name(&name)?;
        Ok(Self {
            id: FolderId::new(),
            parent,
            name: name.trim().to_owned(),
            default_credential: None,
        })
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
        let name = name.into();
        let host = host.into();
        check_name(&name)?;
        let h = host.trim();
        if h.is_empty() || h.len() > MAX_HOST || h.chars().any(char::is_whitespace) {
            return Err(NexusError::Invalid {
                field: "host",
                reason: "empty, too long or has spaces".into(),
            });
        }
        Ok(Self {
            id: ConnectionId::new(),
            folder,
            name: name.trim().to_owned(),
            protocol,
            host: h.to_owned(),
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
    fn ids_round_trip_through_strings() {
        let id = ConnectionId::new();
        let parsed: ConnectionId = id.to_string().parse().expect("parse");
        assert_eq!(id, parsed);
        assert!("nope".parse::<ConnectionId>().is_err());
    }
}
