//! Secret sources (ADR-0016 §1, ADR-0026 §3–§4): a Vault / `OpenBao` server, a 1Password
//! Connect server or a Bitwarden Secrets Manager (`bws`) that `external_ref` credentials
//! resolve from. A source holds no secret material, only the id of the credential that logs in
//! (`api_token` for `token`, `vault_approle` for `approle`) or the OIDC role.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::credential::{CredentialKind, MAX_SECRET_BYTES};
use crate::error::{MooringError, Result};
use crate::model::{is_bidi_or_invisible, validate_name, CredentialId, SecretSourceId};

/// Longest `address`.
pub const MAX_ADDRESS: usize = 2048;
/// Longest `namespace` / `auth_mount` / `oidc_role`.
pub const MAX_PATHLIKE: usize = 256;
/// Most `allowedOrigins` entries (ADR-0016 §4).
pub const MAX_ALLOWED_ORIGINS: usize = 16;
/// Longest `caPem`.
pub const MAX_CA_PEM: usize = 64 * 1024;
/// The OIDC `redirect_uri` (Vault CLI convention; never listened on, ADR-0016 §4).
pub const OIDC_REDIRECT_URI: &str = "http://localhost:8250/oidc/callback";

fn invalid(field: &'static str, reason: impl Into<String>) -> MooringError {
    MooringError::Invalid { field, reason: reason.into() }
}

/// The fixed `bws` locations (ADR-0026 §4, ADR-0020 §3 pattern). `%VAR%` is expanded from
/// the environment of this process at run time; nothing else is ever executed.
pub const BWS_PATHS: [&str; 4] = [
    "/usr/local/bin/bws",
    "/opt/homebrew/bin/bws",
    "%LOCALAPPDATA%\\Programs\\bws\\bws.exe",
    "%ProgramFiles%\\bws\\bws.exe",
];

/// Source kind (`kind CHECK (kind IN ('vault', 'onepassword', 'bitwarden'))`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// `HashiCorp` Vault or `OpenBao` (`OpenBao` speaks the same API).
    #[default]
    Vault,
    /// A self-hosted 1Password Connect server (ADR-0026 §3).
    Onepassword,
    /// Bitwarden Secrets Manager through the `bws` CLI (ADR-0026 §4).
    Bitwarden,
}

impl SourceKind {
    /// Wire / database name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Onepassword => "onepassword",
            Self::Bitwarden => "bitwarden",
        }
    }

    /// Parse a wire name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Vault, Self::Onepassword, Self::Bitwarden].into_iter().find(|k| k.name() == s)
    }

    /// The `external_ref.provider` this source serves.
    #[must_use]
    pub const fn provider(self) -> crate::credential::RefProvider {
        match self {
            Self::Vault => crate::credential::RefProvider::Vault,
            Self::Onepassword => crate::credential::RefProvider::Onepassword,
            Self::Bitwarden => crate::credential::RefProvider::Bitwarden,
        }
    }

    /// The credential kind of the login of `method` on this kind of source.
    #[must_use]
    pub const fn login_kind(self, method: SourceAuthMethod) -> Option<CredentialKind> {
        match (self, method) {
            (Self::Vault, m) => m.credential_kind(),
            (Self::Onepassword, SourceAuthMethod::Token) => Some(CredentialKind::ApiToken),
            (Self::Bitwarden, SourceAuthMethod::Token) => {
                Some(CredentialKind::BitwardenAccessToken)
            }
            _ => None,
        }
    }
}

/// How Mooring logs in to a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthMethod {
    /// A stored Vault token (`api_token` credential).
    Token,
    /// `AppRole` (`vault_approle` credential).
    Approle,
    /// OIDC in an isolated window; nothing stored.
    Oidc,
}

impl SourceAuthMethod {
    /// Wire / database name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Approle => "approle",
            Self::Oidc => "oidc",
        }
    }

    /// Parse a wire name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Token, Self::Approle, Self::Oidc].into_iter().find(|m| m.name() == s)
    }

    /// Default auth mount (`token`, `approle`, `oidc`).
    #[must_use]
    pub const fn default_mount(self) -> &'static str {
        self.name()
    }

    /// The credential kind that holds the login material, if any.
    #[must_use]
    pub const fn credential_kind(self) -> Option<CredentialKind> {
        match self {
            Self::Token => Some(CredentialKind::ApiToken),
            Self::Approle => Some(CredentialKind::VaultApprole),
            Self::Oidc => None,
        }
    }
}

/// The validated login of a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSourceAuth {
    /// Stored token (`api_token` credential, `token` secret).
    Token {
        /// Credential id.
        credential_id: CredentialId,
    },
    /// `AppRole` at `mount`.
    AppRole {
        /// Auth mount (`approle`).
        mount: String,
        /// `vault_approle` credential id.
        credential_id: CredentialId,
    },
    /// OIDC at `mount` with `role`.
    Oidc {
        /// Auth mount (`oidc`).
        mount: String,
        /// Vault role (must allow [`OIDC_REDIRECT_URI`]).
        role: String,
    },
}

impl SecretSourceAuth {
    /// The method.
    #[must_use]
    pub const fn method(&self) -> SourceAuthMethod {
        match self {
            Self::Token { .. } => SourceAuthMethod::Token,
            Self::AppRole { .. } => SourceAuthMethod::Approle,
            Self::Oidc { .. } => SourceAuthMethod::Oidc,
        }
    }

    /// The login credential, if the method has one.
    #[must_use]
    pub const fn credential_id(&self) -> Option<CredentialId> {
        match self {
            Self::Token { credential_id } | Self::AppRole { credential_id, .. } => {
                Some(*credential_id)
            }
            Self::Oidc { .. } => None,
        }
    }

    /// Auth mount (`token` for the token method).
    #[must_use]
    pub fn mount(&self) -> &str {
        match self {
            Self::Token { .. } => "token",
            Self::AppRole { mount, .. } | Self::Oidc { mount, .. } => mount,
        }
    }
}

/// `options_json` of a source (camelCase on the wire and in the table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceOptions {
    /// Extra PEM roots for a private CA (certificates only).
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Permit `http://` to `127.0.0.1` / `[::1]` only (audited).
    #[serde(default)]
    pub allow_http: bool,
    /// Extra navigation origins of the OIDC window (`https://host[:port]`).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Bitwarden: one of [`BWS_PATHS`] (`None` = the first that exists).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bws_path: Option<String>,
}

/// A stored secret source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSource {
    /// Id.
    pub id: SecretSourceId,
    /// Display name.
    pub name: String,
    /// Kind.
    pub kind: SourceKind,
    /// `https://host[:port][/prefix]`, without a trailing slash.
    pub address: String,
    /// `X-Vault-Namespace` (Enterprise / `OpenBao` namespaces).
    pub namespace: Option<String>,
    /// Login.
    pub auth: SecretSourceAuth,
    /// Options.
    pub options: SourceOptions,
    /// Created (UTC).
    pub created_at: OffsetDateTime,
    /// Updated (UTC).
    pub updated_at: OffsetDateTime,
}

/// Create / update input, as IPC sends it (ADR-0016 §7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSourceInput {
    /// Kind (`vault` when absent: the A3 payload).
    #[serde(default)]
    pub kind: SourceKind,
    /// Display name.
    pub name: String,
    /// Server address.
    pub address: String,
    /// Namespace.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Method.
    pub auth_method: SourceAuthMethod,
    /// Auth mount (default per method).
    #[serde(default)]
    pub auth_mount: Option<String>,
    /// Login credential (`token`, `approle`).
    #[serde(default)]
    pub credential_id: Option<CredentialId>,
    /// OIDC role.
    #[serde(default)]
    pub oidc_role: Option<String>,
    /// Options.
    #[serde(default)]
    pub options: SourceOptions,
}

/// The validated, normalised parts of a source (everything but id and timestamps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidSource {
    /// Kind.
    pub kind: SourceKind,
    /// Name.
    pub name: String,
    /// Address.
    pub address: String,
    /// Namespace.
    pub namespace: Option<String>,
    /// Login.
    pub auth: SecretSourceAuth,
    /// Options.
    pub options: SourceOptions,
}

impl SecretSourceInput {
    /// Validate everything. The login credential's kind is checked by the store (it needs the
    /// row).
    pub fn validate(&self) -> Result<ValidSource> {
        let name = validate_name(&self.name)?;
        let options = validate_options(&self.options)?;
        let address = validate_address(&self.address, options.allow_http)?;
        let namespace = match self.namespace.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(ns) => Some(validate_pathlike("namespace", ns.trim_matches('/'))?),
        };
        let mount = match self.auth_mount.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => self.auth_method.default_mount().to_owned(),
            Some(m) => validate_pathlike("authMount", m.trim_matches('/'))?,
        };
        let role = self.oidc_role.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let auth = match (self.auth_method, self.credential_id, role) {
            (SourceAuthMethod::Token, Some(credential_id), None) => {
                if mount != "token" {
                    return Err(invalid("authMount", "the token method uses the token mount"));
                }
                SecretSourceAuth::Token { credential_id }
            }
            (SourceAuthMethod::Approle, Some(credential_id), None) => {
                SecretSourceAuth::AppRole { mount, credential_id }
            }
            (SourceAuthMethod::Oidc, None, Some(r)) => {
                SecretSourceAuth::Oidc { mount, role: validate_pathlike("oidcRole", r)? }
            }
            (SourceAuthMethod::Oidc, _, _) => {
                return Err(invalid("oidcRole", "OIDC needs a role and no credential"))
            }
            (_, _, _) => {
                return Err(invalid(
                    "credentialId",
                    "token and approle need a credential and no OIDC role",
                ))
            }
        };
        if auth.method() != SourceAuthMethod::Oidc && !options.allowed_origins.is_empty() {
            return Err(invalid("allowedOrigins", "only OIDC sources open a window"));
        }
        check_kind(self.kind, &auth, namespace.as_ref(), &options)?;
        Ok(ValidSource { kind: self.kind, name, address, namespace, auth, options })
    }
}

/// ADR-0026: 1Password Connect and Bitwarden log in with a token credential only, have no
/// namespace; `bwsPath` is Bitwarden's and must be one of [`BWS_PATHS`]; `bws` runs its own
/// TLS, so a `caPem` could not apply there and is refused.
fn check_kind(
    kind: SourceKind,
    auth: &SecretSourceAuth,
    namespace: Option<&String>,
    options: &SourceOptions,
) -> Result<()> {
    if kind != SourceKind::Vault {
        if auth.method() != SourceAuthMethod::Token {
            return Err(invalid("authMethod", "1Password and Bitwarden sources use a token"));
        }
        if namespace.is_some() {
            return Err(invalid("namespace", "only Vault sources have a namespace"));
        }
    }
    if kind != SourceKind::Bitwarden && options.bws_path.is_some() {
        return Err(invalid("bwsPath", "only Bitwarden sources run bws"));
    }
    if kind == SourceKind::Bitwarden {
        if options.ca_pem.is_some() {
            return Err(invalid("caPem", "bws uses its own TLS; a CA cannot be pinned for it"));
        }
        if options.bws_path.as_deref().is_some_and(|p| !BWS_PATHS.contains(&p)) {
            return Err(invalid("bwsPath", "must be one of the fixed bws locations"));
        }
    }
    Ok(())
}

/// `[A-Za-z0-9._-]+` segments joined by `/` (namespace, mount, role), ≤ 256 bytes.
pub fn validate_pathlike(field: &'static str, v: &str) -> Result<String> {
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    if v.is_empty() || v.len() > MAX_PATHLIKE || !v.split('/').all(seg_ok) {
        return Err(invalid(field, "must be [A-Za-z0-9._-] segments separated by /, ≤ 256 bytes"));
    }
    Ok(v.to_owned())
}

fn is_loopback_literal(host: &str) -> bool {
    host == "127.0.0.1" || host == "[::1]"
}

fn host_ok(host: &str) -> bool {
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// Split `scheme://host[:port]rest` strictly; host lower-cased.
fn split(url: &str) -> Option<(String, String, Option<u16>, &str)> {
    let (scheme, after) = url.split_once("://")?;
    let end = after.find('/').unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let (h, tail) = authority.split_at(close + 1);
        match tail {
            "" => (h, None),
            t => (h, Some(t.strip_prefix(':')?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.len() <= 5 => {
            Some(p.parse::<u16>().ok().filter(|p| *p != 0)?)
        }
        Some(_) => return None,
    };
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase(), port, rest))
}

fn bad_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_whitespace() || c.is_control() || is_bidi_or_invisible(c))
        || s.contains(['@', '?', '#', '\\', '%'])
}

/// `https://host[:port][/prefix]` (http only to a loopback literal with `allow_http`); no
/// credentials, query, fragment or percent escapes. Returns it without a trailing `/`.
pub fn validate_address(address: &str, allow_http: bool) -> Result<String> {
    let a = address.trim();
    if a.is_empty() || a.len() > MAX_ADDRESS || bad_chars(a) {
        return Err(invalid("address", "must be https://host[:port][/path] without credentials"));
    }
    let Some((scheme, host, port, rest)) = split(a) else {
        return Err(invalid("address", "must be https://host[:port][/path]"));
    };
    if !host_ok(&host) {
        return Err(invalid("address", "has an invalid host"));
    }
    match scheme.as_str() {
        "https" => {}
        "http" if allow_http && is_loopback_literal(&host) => {}
        "http" => return Err(invalid("address", "http:// is only allowed to 127.0.0.1 or [::1]")),
        _ => return Err(invalid("address", "must use https://")),
    }
    let prefix = rest.trim_end_matches('/');
    if !prefix.is_empty() {
        validate_pathlike("address", &prefix[1..])
            .map_err(|_| invalid("address", "path segments must be [A-Za-z0-9._-]"))?;
    }
    let port = port.map(|p| format!(":{p}")).unwrap_or_default();
    Ok(format!("{scheme}://{host}{port}{prefix}"))
}

/// `https://host[:port]` origin of the OIDC window.
pub fn validate_origin(origin: &str) -> Result<String> {
    let a = origin.trim().trim_end_matches('/');
    let ok = !bad_chars(a) && a.len() <= MAX_ADDRESS;
    match split(a) {
        Some((scheme, host, port, "")) if ok && scheme == "https" && host_ok(&host) => {
            let port = port.map(|p| format!(":{p}")).unwrap_or_default();
            Ok(format!("https://{host}{port}"))
        }
        _ => Err(invalid("allowedOrigins", "entries must be https://host[:port]")),
    }
}

fn validate_options(o: &SourceOptions) -> Result<SourceOptions> {
    let ca_pem = match o.ca_pem.as_deref().filter(|p| !p.trim().is_empty()) {
        None => None,
        Some(pem) if pem.len() > MAX_CA_PEM || pem.len() > MAX_SECRET_BYTES => {
            return Err(invalid("caPem", "larger than 64 KiB"))
        }
        Some(pem) => {
            crate::credential::fingerprint::x509_pem(pem)
                .map_err(|_| invalid("caPem", "must be PEM certificates"))?;
            Some(pem.to_owned())
        }
    };
    if o.allowed_origins.len() > MAX_ALLOWED_ORIGINS {
        return Err(invalid("allowedOrigins", "at most 16 entries"));
    }
    let mut origins = Vec::with_capacity(o.allowed_origins.len());
    for origin in &o.allowed_origins {
        let v = validate_origin(origin)?;
        if !origins.contains(&v) {
            origins.push(v);
        }
    }
    let bws_path =
        o.bws_path.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(str::to_owned);
    Ok(SourceOptions { ca_pem, allow_http: o.allow_http, allowed_origins: origins, bws_path })
}

#[cfg(test)]
#[path = "secret_source_tests.rs"]
mod tests;
