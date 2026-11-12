//! Per-protocol connection options (`connection.options_json`, migration 0005; ADR-0011 §IPC,
//! ADR-0012 §IPC, ADR-0013).
//!
//! The JSON object is the **inner** options struct, camelCase, `deny_unknown_fields`. Which
//! struct applies is decided by the connection's protocol, never by the JSON itself, so there
//! is no tag: parse with [`ProtocolOptions::from_value`] / [`ProtocolOptions::from_json`] and the
//! protocol at hand. Every field has a default, so `{}` (the migration default) is a valid RDP,
//! VNC, Kubernetes (ADR-0014) or vSphere (ADR-0015) options object; SSH has no options and
//! accepts only `{}`. Existing Kubernetes rows (`{}`) therefore need no migration.
//! Values are validated on write *and* re-validated on read (the database is not trusted
//! more than the UI). The text is capped at [`MAX_OPTIONS_JSON`].

mod conn;
mod gateway;
mod vsphere;

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use conn::{
    is_localhost_subdomain, ExecCommand, KubeConnOptions, RdpConnOptions, RelayConnOptions,
    VncConnOptions, VncSecurity, WebConnOptions, DEFAULT_KEYBOARD_LAYOUT, KEYBOARD_LAYOUTS,
    LOG_TAIL_LINES, MAX_ALLOWED_NAMESPACES, MAX_ALLOWED_ORIGINS, MAX_LOG_BYTES, MAX_URL,
};
pub use gateway::{GatewayUsage, RdGatewayOptions, MAX_GATEWAY_HOST};
pub use vsphere::{
    VsphereConnOptions, DEFAULT_REFRESH_MINUTES, MAX_REFRESH_MINUTES, MIN_REFRESH_MINUTES,
};

use crate::error::{MooringError, Result};
use crate::model::Protocol;

/// Largest `options_json` text, in bytes (ADR-0011: ≤ 128 KiB).
pub const MAX_OPTIONS_JSON: usize = 128 * 1024;

pub(crate) fn invalid(reason: impl Into<String>) -> MooringError {
    MooringError::Invalid { field: "options", reason: reason.into() }
}

/// Clipboard direction policy (`off | to_remote | from_remote | both`, default `both`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardPolicy {
    /// No clipboard channel.
    Off,
    /// Local → remote only.
    ToRemote,
    /// Remote → local only.
    FromRemote,
    /// Both directions.
    #[default]
    Both,
}

impl ClipboardPolicy {
    /// Whether local text may be offered to the remote side.
    pub const fn allows_to_remote(self) -> bool {
        matches!(self, Self::ToRemote | Self::Both)
    }

    /// Whether remote text may land on the local clipboard.
    pub const fn allows_from_remote(self) -> bool {
        matches!(self, Self::FromRemote | Self::Both)
    }
}

/// Frame pump rate: the JSON number `30` or `60` (default 30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MaxFps {
    /// 30 frames per second.
    #[default]
    Thirty,
    /// 60 frames per second.
    Sixty,
}

impl MaxFps {
    /// Frames per second.
    pub const fn fps(self) -> u32 {
        match self {
            Self::Thirty => 30,
            Self::Sixty => 60,
        }
    }

    /// Pump tick, `1000 / maxFps` ms.
    pub const fn interval(self) -> Duration {
        Duration::from_millis(1000 / self.fps() as u64)
    }
}

impl Serialize for MaxFps {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_u32(self.fps())
    }
}

impl<'de> Deserialize<'de> for MaxFps {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        match u32::deserialize(d)? {
            30 => Ok(Self::Thirty),
            60 => Ok(Self::Sixty),
            _ => Err(serde::de::Error::custom("maxFps must be 30 or 60")),
        }
    }
}

/// Options of a protocol that has none: only `{}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoOptions {}

/// The options of one connection, typed by its protocol. Serialises as the inner object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ProtocolOptions {
    /// RDP (ADR-0011).
    Rdp(RdpConnOptions),
    /// VNC (ADR-0012).
    Vnc(VncConnOptions),
    /// Web (ADR-0013).
    Web(WebConnOptions),
    /// Kubernetes (ADR-0014).
    Kube(KubeConnOptions),
    /// vCenter / synced VM rows (ADR-0015).
    Vsphere(VsphereConnOptions),
    /// SSH: `{}`.
    None(NoOptions),
    /// Relay (ADR-0029).
    Relay(RelayConnOptions),
}

impl ProtocolOptions {
    /// Defaults for a protocol. For `Web` the URL is empty and must be set before it
    /// validates.
    pub fn default_for(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Rdp => Self::Rdp(RdpConnOptions::default()),
            Protocol::Vnc => Self::Vnc(VncConnOptions::default()),
            Protocol::Web => Self::Web(WebConnOptions::default()),
            Protocol::Kubernetes => Self::Kube(KubeConnOptions::default()),
            Protocol::VsphereConsole => Self::Vsphere(VsphereConnOptions::default()),
            Protocol::Ssh => Self::None(NoOptions {}),
            Protocol::Relay => Self::Relay(RelayConnOptions::default()),
        }
    }

    /// Parse and validate a JSON value for `protocol` (IPC `connection_create/update`).
    pub fn from_value(protocol: Protocol, value: serde_json::Value) -> Result<Self> {
        if !value.is_object() {
            return Err(invalid("must be a JSON object"));
        }
        let parsed = match protocol {
            Protocol::Rdp => serde_json::from_value(value).map(Self::Rdp),
            Protocol::Vnc => serde_json::from_value(value).map(Self::Vnc),
            Protocol::Web => serde_json::from_value(value).map(Self::Web),
            Protocol::Kubernetes => serde_json::from_value(value).map(Self::Kube),
            Protocol::VsphereConsole => serde_json::from_value(value).map(Self::Vsphere),
            Protocol::Ssh => serde_json::from_value(value).map(Self::None),
            Protocol::Relay => serde_json::from_value(value).map(Self::Relay),
        }
        .map_err(|e| invalid(serde_reason(&e)))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Parse and validate stored text (≤ 128 KiB) for `protocol`.
    pub fn from_json(protocol: Protocol, json: &str) -> Result<Self> {
        if json.len() > MAX_OPTIONS_JSON {
            return Err(invalid("larger than 128 KiB"));
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| invalid("not valid JSON"))?;
        Self::from_value(protocol, value)
    }

    /// Canonical JSON text for `connection.options_json`.
    pub fn to_json(&self) -> Result<String> {
        let s = serde_json::to_string(self).map_err(|_| invalid("could not be serialised"))?;
        if s.len() > MAX_OPTIONS_JSON {
            return Err(invalid("larger than 128 KiB"));
        }
        Ok(s)
    }

    /// Whether these options belong to `protocol`.
    pub fn fits(&self, protocol: Protocol) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(&Self::default_for(protocol))
    }

    /// Validate every field (closed lists, caps, URL rules, CA PEM rule B-3).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Rdp(o) => o.validate(),
            Self::Vnc(o) => o.validate(),
            Self::Web(o) => o.validate(),
            Self::Kube(o) => o.validate(),
            Self::Vsphere(o) => o.validate(),
            Self::None(_) => Ok(()),
            Self::Relay(o) => o.validate(),
        }
    }
}

/// Serde error text without the offending value (serde quotes unknown variants and fields,
/// which are UI- or database-supplied; field *names* are fine, values may not be).
fn serde_reason(e: &serde_json::Error) -> String {
    let msg = e.to_string();
    if msg.starts_with("unknown field") {
        let name = msg.split('`').nth(1).unwrap_or("?");
        if name.len() <= 32 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return format!("unknown field {name}");
        }
        return "unknown field".to_owned();
    }
    if msg.contains("maxFps") {
        return "maxFps must be 30 or 60".to_owned();
    }
    "invalid value or type".to_owned()
}

/// `caPem`: certificate PEM blocks only (no private key may ride along, review 3 B-3),
/// ≤ 64 KiB, and the first block must decode as a DER certificate.
pub(crate) fn check_ca_pem(pem: Option<&String>) -> Result<()> {
    let Some(pem) = pem else {
        return Ok(());
    };
    crate::credential::fingerprint::x509_pem(pem).map(|_| ()).map_err(|e| MooringError::Invalid {
        field: "caPem",
        reason: e.to_string().replace("cert_pem", "caPem"),
    })
}

#[cfg(test)]
mod kube_tests;
#[cfg(test)]
mod tests;
