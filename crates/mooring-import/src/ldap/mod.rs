//! LDAPS directory importer (ADR-0019 §4, feature `directory`): bind with a vault credential
//! over `ldaps://` only (our rustls verifier from `mooring-http`, `known_ldap_certs`), run a
//! read-only paged search for computers (AD) or hosts / devices (`OpenLDAP`) under a base DN,
//! and map the entries to an [`ImportPlan`] whose folders mirror the OU path.
//!
//! * Every user-supplied filter value is RFC 4515-escaped ([`filter::escape_value`], fuzzed);
//!   the base DN is parsed per RFC 4514 and re-serialised, never interpolated.
//! * [`client`] is the only module that talks to the server; [`wire`] holds the only four
//!   requests it can send: bind, search, abandon, unbind (a test greps for the write
//!   operations). The transport is ours (tokio-rustls + `lber` for BER), not `ldap3`'s: its
//!   codec recurses per nesting level and `expect`s on malformed frames, so a few KiB of
//!   nested SEQUENCEs from a hostile server would overflow the stack (see
//!   `docs/handoff/a4-rust-core-i2.md`).
//! * Responses are hostile: every frame passes the iterative [`frame::scan`] (≤ 256 KiB,
//!   depth ≤ 32) before the recursive parser; entries are walked by [`entry::extract`]
//!   (caps, no panics); the run is one task under a deadline, so even a panic becomes
//!   [`LdapError::Response`]; size, page and time caps bound the run.

mod client;
pub mod entry;
pub mod filter;
pub mod frame;
pub mod fuzz;
mod plan;
pub mod wire;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use client::{bind_only, fetch, DirectoryReader};
pub use entry::{EntryLimits, RawEntry, ATTRIBUTES};
pub use filter::{escape_value, search_filter, Dn, LdapTarget};
pub use plan::{build_plan, is_windows, PlanOptions, MAX_DEPTH};

use crate::ImportPlan;

/// Which attribute conventions the directory follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryKind {
    /// Active Directory: `(objectClass=computer)`, `dNSHostName`, `operatingSystem`.
    Ad,
    /// `OpenLDAP`: `ipHost` / `device` objects, `cn` or `ipHostNumber` as the host.
    #[serde(rename = "openldap")]
    OpenLdap,
}

/// Search scope (RFC 4511 §4.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchScope {
    /// The base entry only.
    Base,
    /// Its immediate children.
    One,
    /// The whole subtree (default).
    Sub,
}

/// Caps of one directory run (ADR-0019 §4 as decided for I2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapLimits {
    /// Most entries accepted (also the server `sizeLimit`).
    pub max_entries: usize,
    /// Entries per page (RFC 2696).
    pub page_size: usize,
    /// Most pages fetched.
    pub max_pages: usize,
    /// Server `timeLimit` (seconds) and the client deadline for the whole run.
    pub deadline: Duration,
    /// TCP connect + TLS handshake.
    pub connect_timeout: Duration,
    /// Per-entry caps.
    pub entry: EntryLimits,
}

impl LdapLimits {
    /// ≤ 5 000 entries, 500 per page, 30 s.
    pub const DEFAULT: Self = Self {
        max_entries: 5_000,
        page_size: 500,
        max_pages: 12,
        deadline: Duration::from_secs(30),
        connect_timeout: Duration::from_secs(10),
        entry: EntryLimits { max_dn: 1024, max_value: 1024, max_values: 16, max_attrs: 64 },
    };
}

impl Default for LdapLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One directory query as the UI states it (validated by [`LdapQuery::prepare`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapQuery {
    /// `ldaps://host[:636]`.
    pub url: String,
    /// Search base.
    pub base_dn: String,
    /// Scope.
    pub scope: SearchScope,
    /// Attribute conventions.
    pub kind: DirectoryKind,
    /// Optional substring the `cn` or `dNSHostName` must contain (escaped).
    pub name_contains: Option<String>,
    /// Entry cap requested by the user (clamped to the limits).
    pub size_limit: Option<usize>,
}

/// A validated query: everything that goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// Server.
    pub target: LdapTarget,
    /// Base DN (parsed).
    pub base: Dn,
    /// Scope.
    pub scope: SearchScope,
    /// Kind.
    pub kind: DirectoryKind,
    /// The complete filter in text form (display and audit; the wire form is BER).
    pub filter: String,
    /// The trimmed substring value, if any (the BER filter is built from it).
    pub name_contains: Option<String>,
    /// Effective entry cap.
    pub size_limit: usize,
}

impl LdapQuery {
    /// Validate and escape; `ldap.insecure` for `ldap://`, `ldap.invalid` / `ldap.dn_invalid`
    /// for the rest.
    pub fn prepare(&self, limits: &LdapLimits) -> Result<Prepared, LdapError> {
        let target = LdapTarget::parse(&self.url)?;
        let base = Dn::parse(&self.base_dn)?;
        let filter = search_filter(self.kind, self.name_contains.as_deref())?;
        let name_contains = self
            .name_contains
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let size_limit = match self.size_limit {
            Some(0) => return Err(LdapError::Invalid("sizeLimit must be positive")),
            Some(n) => n.min(limits.max_entries),
            None => limits.max_entries,
        };
        Ok(Prepared {
            target,
            base,
            scope: self.scope,
            kind: self.kind,
            filter,
            name_contains,
            size_limit,
        })
    }
}

/// How far a run got with its bind (A4 F1): lets the caller audit `ldap_bind` for a run
/// that dies after the server accepted the bind (bind → refused), and a failed bind as
/// `success: false` without counting a transport or trust failure as a bind attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindPhase {
    /// No bind request left the client (query, connect, TLS or trust failure).
    #[default]
    NotAttempted,
    /// The bind request was sent and the server did not accept it (refused, bad reply,
    /// dropped connection or deadline).
    Attempted,
    /// The server accepted the bind.
    Bound,
}

/// Shared progress marker of one run, set by the client as the bind advances.
#[derive(Debug, Clone, Default)]
pub struct BindSignal(std::sync::Arc<std::sync::atomic::AtomicU8>);

impl BindSignal {
    /// Where the bind got to so far.
    pub fn phase(&self) -> BindPhase {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            0 => BindPhase::NotAttempted,
            1 => BindPhase::Attempted,
            _ => BindPhase::Bound,
        }
    }

    pub(crate) fn set(&self, phase: BindPhase) {
        let v = match phase {
            BindPhase::NotAttempted => 0,
            BindPhase::Attempted => 1,
            BindPhase::Bound => 2,
        };
        self.0.store(v, std::sync::atomic::Ordering::Release);
    }
}

/// The simple-bind identity: a DN, a UPN or `DOMAIN\user` plus the password from the vault.
/// `Debug` prints the name only.
pub struct BindCredential {
    /// Bind name.
    pub name: String,
    /// Password (zeroized on drop; copied once into the bind frame, R-LDAP-STR).
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for BindCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindCredential").field("name", &self.name).finish_non_exhaustive()
    }
}

/// Why a directory run failed. Messages never carry a DN, host or value from the server.
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// `ldap://` or `StartTLS`.
    #[error("only ldaps:// is supported")]
    Insecure,
    /// A malformed URL, filter value or option.
    #[error("invalid directory query: {0}")]
    Invalid(&'static str),
    /// The base DN does not parse, or the server has no such object.
    #[error("invalid base DN: {0}")]
    DnInvalid(&'static str),
    /// The server refused the bind (`invalidCredentials` or another bind result).
    #[error("the directory refused the bind (result code {0})")]
    Bind(u32),
    /// More entries than allowed (server `sizeLimitExceeded` or the client cap).
    #[error(
        "the search returned more entries than the limit allows; narrow the base DN or filter"
    )]
    SizeLimit,
    /// Deadline or server `timeLimitExceeded`.
    #[error("the directory did not answer in time")]
    Timeout,
    /// Connect failure or an unexpected result code.
    #[error("the directory is unavailable: {0}")]
    Unavailable(String),
    /// A response the client could not make sense of.
    #[error("the directory sent a malformed response ({0})")]
    Response(&'static str),
    /// The TLS trust decision (`http.trust_*`) or another TLS failure.
    #[error("{0}")]
    Tls(#[source] mooring_http::HttpError),
}

impl LdapError {
    /// Stable IPC code (`http.*` for the TLS layer).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Insecure => "ldap.insecure",
            Self::Invalid(_) => "ldap.invalid",
            Self::DnInvalid(_) => "ldap.dn_invalid",
            Self::Bind(_) => "ldap.bind",
            Self::SizeLimit => "ldap.size_limit",
            Self::Timeout => "ldap.timeout",
            Self::Unavailable(_) => "ldap.unavailable",
            Self::Response(_) => "ldap.response",
            Self::Tls(e) => e.code(),
        }
    }
}

/// Bind, search and map: the whole preview (`tls` is one [`mooring_http::TlsClient`] built
/// for the target by the caller, so the trust prompt stays in the Tauri layer).
pub async fn preview(
    query: &Prepared,
    cred: &BindCredential,
    tls: mooring_http::TlsClient,
    limits: &LdapLimits,
    bind: &BindSignal,
) -> Result<ImportPlan, LdapError> {
    let entries = fetch(query, cred, tls, limits, bind).await?;
    let opts = PlanOptions {
        kind: query.kind,
        base: query.base.clone(),
        max_depth: MAX_DEPTH,
        limits: crate::Limits::DEFAULT,
    };
    build_plan(&entries, &opts).map_err(|e| LdapError::Unavailable(e.to_string()))
}

#[cfg(test)]
#[path = "mock_tests.rs"]
mod mock_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
