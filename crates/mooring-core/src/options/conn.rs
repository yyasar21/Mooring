//! The RDP, VNC, web and Kubernetes option structs.

use serde::{Deserialize, Serialize};

use super::{check_ca_pem, invalid, ClipboardPolicy, MaxFps};
use crate::credential::is_forbidden;
use crate::credential::kubeconfig::{is_dns_label, is_dns_subdomain, KubeServer, MAX_CONTEXT_NAME};
use crate::error::Result;
use crate::CredentialKind;

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

/// Whether `host` is a sub-name of the RFC 6761 `localhost.` zone (`tauri.localhost`,
/// `ipc.localhost`, `a.b.localhost`, with or without a trailing dot). Tauri serves every
/// custom protocol there on Windows, so a web connection never lists one (review 5 N-31).
/// Plain `localhost` is not a sub-name and stays allowed.
pub fn is_localhost_subdomain(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.len() > ".localhost".len() && host.to_ascii_lowercase().ends_with(".localhost")
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
    if is_localhost_subdomain(host) {
        return Err(invalid(format!("{what}: *.localhost names are reserved for the app")));
    }
    if origin_only && !rest.is_empty() && rest != "/" {
        return Err(invalid("allowedOrigins entries are origins, without a path"));
    }
    Ok(())
}

/// Most extra namespaces a Kubernetes connection lists when `list namespaces` is denied.
pub const MAX_ALLOWED_NAMESPACES: usize = 64;
/// `logTailLines` range (default 1000).
pub const LOG_TAIL_LINES: std::ops::RangeInclusive<u32> = 1..=100_000;
/// `maxLogBytes` range (default 8 MiB, ADR-0014 §5).
pub const MAX_LOG_BYTES: std::ops::RangeInclusive<u64> = 1..=64 * 1024 * 1024;
const DEFAULT_LOG_TAIL_LINES: u32 = 1000;
const DEFAULT_MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

const fn default_tail() -> u32 {
    DEFAULT_LOG_TAIL_LINES
}

const fn default_log_bytes() -> u64 {
    DEFAULT_MAX_LOG_BYTES
}

/// The fixed `exec` command allow-list (ADR-0014 owner decision 3; no custom argv in A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum ExecCommand {
    /// `/bin/sh` (default).
    #[default]
    #[serde(rename = "/bin/sh")]
    BinSh,
    /// `/bin/bash`.
    #[serde(rename = "/bin/bash")]
    BinBash,
    /// `/bin/ash` (Alpine / `BusyBox`).
    #[serde(rename = "/bin/ash")]
    BinAsh,
    /// `sh` from the container's `PATH`.
    #[serde(rename = "sh")]
    Sh,
    /// `bash` from the container's `PATH`.
    #[serde(rename = "bash")]
    Bash,
}

impl ExecCommand {
    /// Every allowed command, in UI order.
    pub const ALL: [Self; 5] = [Self::BinSh, Self::BinBash, Self::BinAsh, Self::Sh, Self::Bash];

    /// The single argv element sent as `command=` (also `argv0` in the audit event).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinSh => "/bin/sh",
            Self::BinBash => "/bin/bash",
            Self::BinAsh => "/bin/ash",
            Self::Sh => "sh",
            Self::Bash => "bash",
        }
    }

    /// Parse a wire name (closed list).
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// `KubeConnOptions = { context|null, server|null, caPem|null, tlsServerName|null,
/// namespace|null, allowedNamespaces, execCommand, logTailLines, maxLogBytes,
/// portForwardEnabled }` (ADR-0014 §3). `server` / `caPem` are for `kube_token` credentials
/// (owner decision 2); see [`Self::check_credential`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeConnOptions {
    /// Kubeconfig context, `null` = `current-context`.
    #[serde(default)]
    pub context: Option<String>,
    /// API server (`https://…`), `kube_token` only.
    #[serde(default)]
    pub server: Option<String>,
    /// Cluster CA (certificate PEM only, ≤ 64 KiB), `kube_token` only.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// TLS verification name override (lower-case DNS name).
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// Default namespace (RFC 1123 label); overrides the context namespace.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Namespaces offered when `list namespaces` is denied (≤ 64, unique labels).
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
    /// Shell for `exec` (default `/bin/sh`).
    #[serde(default)]
    pub exec_command: ExecCommand,
    /// Default `tailLines` for the logs view (1..=100 000, default 1000).
    #[serde(default = "default_tail")]
    pub log_tail_lines: u32,
    /// `limitBytes` per log stream (1 B..=64 MiB, default 8 MiB).
    #[serde(default = "default_log_bytes")]
    pub max_log_bytes: u64,
    /// Whether pod port-forwards may be opened (default `true`; loopback, ADR-0010).
    #[serde(default = "yes")]
    pub port_forward_enabled: bool,
}

impl Default for KubeConnOptions {
    fn default() -> Self {
        Self {
            context: None,
            server: None,
            ca_pem: None,
            tls_server_name: None,
            namespace: None,
            allowed_namespaces: Vec::new(),
            exec_command: ExecCommand::BinSh,
            log_tail_lines: DEFAULT_LOG_TAIL_LINES,
            max_log_bytes: DEFAULT_MAX_LOG_BYTES,
            port_forward_enabled: true,
        }
    }
}

impl KubeConnOptions {
    /// Shape rules that hold for every credential kind.
    pub fn validate(&self) -> Result<()> {
        if let Some(c) = &self.context {
            if c.is_empty() || c.len() > MAX_CONTEXT_NAME || c.chars().any(is_forbidden) {
                return Err(invalid("context is empty, too long or has control characters"));
            }
        }
        if let Some(s) = &self.server {
            KubeServer::parse(s).map_err(invalid)?;
        }
        check_ca_pem(self.ca_pem.as_ref())?;
        if self.tls_server_name.as_deref().is_some_and(|n| !is_dns_subdomain(n)) {
            return Err(invalid("tlsServerName must be a lower-case DNS name"));
        }
        if self.namespace.as_deref().is_some_and(|n| !is_dns_label(n)) {
            return Err(invalid("namespace must be a lower-case RFC 1123 label"));
        }
        if self.allowed_namespaces.len() > MAX_ALLOWED_NAMESPACES {
            return Err(invalid("allowedNamespaces holds at most 64 namespaces"));
        }
        let mut seen = std::collections::HashSet::new();
        for ns in &self.allowed_namespaces {
            if !is_dns_label(ns) || !seen.insert(ns.as_str()) {
                return Err(invalid("allowedNamespaces entries must be unique RFC 1123 labels"));
            }
        }
        if !LOG_TAIL_LINES.contains(&self.log_tail_lines) {
            return Err(invalid("logTailLines must be between 1 and 100000"));
        }
        if !MAX_LOG_BYTES.contains(&self.max_log_bytes) {
            return Err(invalid("maxLogBytes must be between 1 byte and 64 MiB"));
        }
        Ok(())
    }

    /// Rules that depend on the connection's credential kind (ADR-0014 §3): `kube_token`
    /// needs `server` and `caPem` and has no `context`; `kubeconfig` takes both from the file
    /// and refuses them here. Call after [`Self::validate`] once the credential is known.
    pub fn check_credential(&self, kind: CredentialKind) -> Result<()> {
        match kind {
            CredentialKind::KubeToken if self.server.is_none() || self.ca_pem.is_none() => {
                Err(invalid("a kube_token connection needs server and caPem"))
            }
            CredentialKind::KubeToken if self.context.is_some() => {
                Err(invalid("context applies to kubeconfig credentials only"))
            }
            CredentialKind::Kubeconfig if self.server.is_some() || self.ca_pem.is_some() => {
                Err(invalid("server and caPem come from the kubeconfig; leave them empty"))
            }
            _ => Ok(()),
        }
    }

    /// The validated [`Self::server`].
    pub fn server_url(&self) -> Option<KubeServer> {
        self.server.as_deref().and_then(|s| KubeServer::parse(s).ok())
    }
}
