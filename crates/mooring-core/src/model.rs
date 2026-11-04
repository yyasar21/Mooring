//! Folders, connections and credential references.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{MooringError, Result};

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
            type Err = MooringError;
            fn from_str(s: &str) -> Result<Self> {
                Uuid::parse_str(s).map(Self).map_err(|_| MooringError::Invalid {
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

/// Which protocol a connection speaks. Each variant maps to one `mooring-proto-*` crate.
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
    /// Replaces the effective credential's username / user for this connection (ADR-0009 §3).
    #[serde(default)]
    pub username_override: Option<String>,
    /// Replaces the effective credential's domain for this connection.
    #[serde(default)]
    pub domain_override: Option<String>,
    /// RD Gateway credential (per connection; `None` = same as the session credential).
    #[serde(default)]
    pub gateway_credential: Option<CredentialId>,
    /// `sudo_become` credential (per connection).
    #[serde(default)]
    pub become_credential: Option<CredentialId>,
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

fn invalid(field: &'static str, reason: String) -> MooringError {
    MooringError::Invalid { field, reason }
}

/// Unicode bidi controls (Trojan Source class, CVE-2021-42574) and every other format
/// character (general category `Cf`, Unicode 15.1: zero-width, soft hyphen, interlinear
/// annotation, tag characters, ...): they make a stored value render differently from what it
/// is (review 4, N-16).
#[must_use]
pub const fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Control characters plus [`is_bidi_or_invisible`]: never allowed in names, hosts or tags.
fn is_forbidden(c: char) -> bool {
    c.is_control() || is_bidi_or_invisible(c)
}

/// Validate a display name (folder, connection, credential) and return it trimmed:
/// 1..=[`MAX_NAME`] characters, no control, bidi or invisible format characters. The error never echoes the input.
pub fn validate_name(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME {
        return Err(invalid("name", format!("must be 1..={MAX_NAME} characters")));
    }
    if n.chars().any(is_forbidden) {
        return Err(invalid("name", "contains control or invisible formatting characters".into()));
    }
    Ok(n.to_owned())
}

/// Validate a host (name, IP, URL or context) and return it trimmed: 1..=[`MAX_HOST`] bytes,
/// no whitespace or control characters.
pub fn validate_host(host: &str) -> Result<String> {
    let h = host.trim();
    if h.is_empty() || h.len() > MAX_HOST || h.chars().any(|c| c.is_whitespace() || is_forbidden(c))
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
    if t.chars().any(is_forbidden) {
        return Err(invalid("tag", "contains control or invisible formatting characters".into()));
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
            username_override: None,
            domain_override: None,
            gateway_credential: None,
            become_credential: None,
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
        let c = Connection::new(root.id, " web01 ", Protocol::Ssh, "192.0.2.5").expect("valid");
        assert_eq!(c.name, "web01");
        assert_eq!(c.effective_port(), Some(22));
    }

    #[test]
    fn public_validators() {
        assert_eq!(validate_name("  a ").expect("ok"), "a");
        assert_eq!(validate_name(&"x".repeat(MAX_NAME)).expect("max").chars().count(), MAX_NAME);
        assert!(validate_name(&"x".repeat(MAX_NAME + 1)).is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("a\nb").is_err());

        assert_eq!(validate_host(" 192.0.2.5 ").expect("ok"), "192.0.2.5");
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
    fn bidi_and_invisible_format_characters_are_refused() {
        let bad = [
            '\u{00AD}',
            '\u{061C}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2060}',
            '\u{2061}',
            '\u{2062}',
            '\u{2063}',
            '\u{2064}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{FEFF}',
            // the rest of Unicode `Cf` (N-16)
            '\u{0600}',
            '\u{0605}',
            '\u{06DD}',
            '\u{070F}',
            '\u{0890}',
            '\u{08E2}',
            '\u{180E}',
            '\u{206A}',
            '\u{206F}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{110BD}',
            '\u{110CD}',
            '\u{13430}',
            '\u{1343F}',
            '\u{1BCA0}',
            '\u{1D173}',
            '\u{1D17A}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
        ];
        for c in bad {
            let v = format!("db{c}x");
            assert!(validate_name(&v).is_err(), "name U+{:04X}", u32::from(c));
            assert!(validate_host(&v).is_err(), "host U+{:04X}", u32::from(c));
            assert!(validate_tag(&v).is_err(), "tag U+{:04X}", u32::from(c));
        }
        // neighbours and ordinary non-ASCII text stay accepted
        for ok in
            ["Sunucu \u{0130}stanbul", "\u{00E9}t\u{00E9}", "\u{2065}x", "a\u{2070}", "\u{202F}n"]
        {
            assert!(validate_name(ok).is_ok(), "{ok:?}");
        }
        assert!(validate_tag("\u{0130}zmir").is_ok());
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
