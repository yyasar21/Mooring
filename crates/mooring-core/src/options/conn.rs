//! The RDP, VNC and web option structs.

use serde::{Deserialize, Serialize};

use super::{check_ca_pem, invalid, ClipboardPolicy, MaxFps};
use crate::error::Result;

/// Keyboard layouts (KLID) accepted for RDP (ADR-0011 closed list): en-US, tr-TR Q, tr-TR F,
/// de-DE, fr-FR, en-GB, it-IT, es-ES, ru-RU.
pub const KEYBOARD_LAYOUTS: [u32; 9] =
    [0x0409, 0x041F, 0x1_041F, 0x0407, 0x040C, 0x0809, 0x0410, 0x040A, 0x0419];
/// en-US.
pub const DEFAULT_KEYBOARD_LAYOUT: u32 = 0x0409;
/// Most extra origins a web connection may navigate to (ADR-0013).
pub const MAX_ALLOWED_ORIGINS: usize = 16;
/// Longest web URL or origin, in bytes.
pub const MAX_URL: usize = 2048;

const fn default_layout() -> u32 {
    DEFAULT_KEYBOARD_LAYOUT
}

const fn yes() -> bool {
    true
}

/// `RdpConnOptions = { keyboardLayout, clipboard, allowTlsWithoutNla, caPem|null, maxFps }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RdpConnOptions {
    /// KLID from [`KEYBOARD_LAYOUTS`], JSON number (default `0x0409` = 1033).
    #[serde(default = "default_layout")]
    pub keyboard_layout: u32,
    /// Clipboard policy (default `both`).
    #[serde(default)]
    pub clipboard: ClipboardPolicy,
    /// Offer TLS without NLA for legacy hosts (default `false`; audited on every connect).
    #[serde(default)]
    pub allow_tls_without_nla: bool,
    /// Extra CA certificates (PEM, certificates only, ≤ 64 KiB).
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Frame rate cap (default 30).
    #[serde(default)]
    pub max_fps: MaxFps,
}

impl Default for RdpConnOptions {
    fn default() -> Self {
        Self {
            keyboard_layout: DEFAULT_KEYBOARD_LAYOUT,
            clipboard: ClipboardPolicy::Both,
            allow_tls_without_nla: false,
            ca_pem: None,
            max_fps: MaxFps::Thirty,
        }
    }
}

impl RdpConnOptions {
    /// Closed KLID list and the CA PEM rule.
    pub fn validate(&self) -> Result<()> {
        if !KEYBOARD_LAYOUTS.contains(&self.keyboard_layout) {
            return Err(invalid("keyboardLayout is not a supported layout"));
        }
        check_ca_pem(self.ca_pem.as_ref())
    }
}

/// VNC transport security policy (default `prefer_tls`, owner decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VncSecurity {
    /// `VeNCrypt` X509 only.
    RequireTls,
    /// `VeNCrypt` when offered, else VNC auth / None with an "unencrypted" badge. Behaves as
    /// `require_tls` once `known_vnc_certs` holds a pin for the host (downgrade guard).
    #[default]
    PreferTls,
    /// Plaintext allowed without preference.
    AllowPlaintext,
}

/// `VncConnOptions = { security, viewOnly, shared, clipboard, caPem|null, maxFps, allowNoAuth }`. Tight JPEG
/// is not an option: it is never requested in A2 (owner decision 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VncConnOptions {
    /// Default `prefer_tls`.
    #[serde(default)]
    pub security: VncSecurity,
    /// Drop all input in Rust (default `false`).
    #[serde(default)]
    pub view_only: bool,
    /// `ClientInit.shared` (default `true`).
    #[serde(default = "yes")]
    pub shared: bool,
    /// Clipboard policy (default `both`).
    #[serde(default)]
    pub clipboard: ClipboardPolicy,
    /// Extra CA certificates for `VeNCrypt` X509.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Frame rate cap (default 30).
    #[serde(default)]
    pub max_fps: MaxFps,
    /// Accept a server that offers only None (type 1) although a password credential is
    /// configured (review 5 L-27; default `false`, audited when used).
    #[serde(default)]
    pub allow_no_auth: bool,
}

impl Default for VncConnOptions {
    fn default() -> Self {
        Self {
            security: VncSecurity::PreferTls,
            view_only: false,
            shared: true,
            clipboard: ClipboardPolicy::Both,
            ca_pem: None,
            max_fps: MaxFps::Thirty,
            allow_no_auth: false,
        }
    }
}

impl VncConnOptions {
    /// The CA PEM rule.
    pub fn validate(&self) -> Result<()> {
        check_ca_pem(self.ca_pem.as_ref())
    }
}

/// `WebConnOptions = { url, allowedOrigins, persistent, allowHttp }`. Storage is ephemeral by
/// default (owner decision 7); `persistent` is an explicit opt-in.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebConnOptions {
    /// Start URL, `https://` (or `http://` with `allowHttp`), no `user:pass@`. Required: the
    /// migration default `{}` does not validate for a web connection.
    #[serde(default)]
    pub url: String,
    /// Extra exact origins (`scheme://host[:port]`, ≤ 16, no wildcards).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Keep cookies on disk per connection (default `false` = ephemeral).
    #[serde(default)]
    pub persistent: bool,
    /// Allow `http://` (default `false`; audited).
    #[serde(default)]
    pub allow_http: bool,
}

impl WebConnOptions {
    /// URL and origin rules of ADR-0013.
    pub fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            return Err(invalid("url is required for a web connection"));
        }
        check_url(&self.url, self.allow_http, false)?;
        if self.allowed_origins.len() > MAX_ALLOWED_ORIGINS {
            return Err(invalid("allowedOrigins holds at most 16 origins"));
        }
        for o in &self.allowed_origins {
            check_url(o, self.allow_http, true)?;
        }
        Ok(())
    }

    /// `scheme://host[:port]` of [`Self::url`] (lowercased), for the navigation allow-list.
    pub fn origin(&self) -> Option<String> {
        split_url(&self.url).map(|(scheme, authority, _)| {
            format!("{}://{}", scheme.to_ascii_lowercase(), authority.to_ascii_lowercase())
        })
    }
}

/// `(scheme, authority, rest)` of an absolute `scheme://authority[rest]` URL.
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, after) = url.split_once("://")?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    Some((scheme, &after[..end], &after[end..]))
}

/// `(host, port)` of `host[:port]` or `[v6][:port]`.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6.split_once(']')?;
        let port = if tail.is_empty() { None } else { Some(tail.strip_prefix(':')?) };
        return Some((host, port));
    }
    Some(match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    })
}

fn check_url(url: &str, allow_http: bool, origin_only: bool) -> Result<()> {
    let what = if origin_only { "allowedOrigins entry" } else { "url" };
    if url.len() > MAX_URL {
        return Err(invalid(format!("{what} is too long")));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(format!("{what} contains whitespace or control characters")));
    }
    let Some((scheme, authority, rest)) = split_url(url) else {
        return Err(invalid(format!("{what} must be an absolute https:// URL")));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "https" => {}
        "http" if allow_http => {}
        "http" => return Err(invalid(format!("{what}: http:// needs allowHttp"))),
        _ => return Err(invalid(format!("{what} must use https://"))),
    }
    if authority.contains('@') {
        return Err(invalid(format!("{what} must not carry credentials")));
    }
    if authority.contains('*') {
        return Err(invalid(format!("{what} must not contain wildcards")));
    }
    let Some((host, port)) = split_authority(authority) else {
        return Err(invalid(format!("{what} has an invalid host or port")));
    };
    if host.is_empty() || port.is_some_and(|p| p.parse::<u16>().map_or(true, |p| p == 0)) {
        return Err(invalid(format!("{what} has an invalid host or port")));
    }
    if origin_only && !rest.is_empty() && rest != "/" {
        return Err(invalid("allowedOrigins entries are origins, without a path"));
    }
    Ok(())
}
