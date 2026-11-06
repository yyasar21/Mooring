//! Directory entries → [`ImportPlan`] (ADR-0019 §4): OUs between the entry and the base DN
//! become folders (depth cap), `cn` the name, `dNSHostName` the host, the OS hint picks RDP
//! or SSH, and one shared `prompt` credential (no password ever comes from a directory).

use mooring_core::{CredentialKind, Protocol};
use serde_json::json;

use super::entry::RawEntry;
use super::filter::Dn;
use super::DirectoryKind;
use crate::plan::{NewConnection, NewCredential, PlanBuilder, SkipReason, WarningCode};
use crate::{ImportPlan, Limits, Result};

/// Deepest OU path mirrored as folders; deeper entries land at this depth with a warning.
pub const MAX_DEPTH: usize = 8;

/// What the mapping needs besides the entries.
#[derive(Debug, Clone)]
pub struct PlanOptions {
    /// AD or `OpenLDAP` attribute conventions.
    pub kind: DirectoryKind,
    /// The search base: entries outside it are skipped.
    pub base: Dn,
    /// Folder depth cap.
    pub max_depth: usize,
    /// Plan caps.
    pub limits: Limits,
}

impl PlanOptions {
    /// Defaults for `kind` under `base`.
    #[must_use]
    pub fn new(kind: DirectoryKind, base: Dn) -> Self {
        Self { kind, base, max_depth: MAX_DEPTH, limits: Limits::DEFAULT }
    }
}

/// The one credential every imported connection points at: ask at connect, domain
/// pre-filled from the base DN's `dc` components for AD.
fn prompt_credential(opts: &PlanOptions) -> NewCredential {
    let domain = match opts.kind {
        DirectoryKind::Ad => opts.base.domain(),
        DirectoryKind::OpenLdap => None,
    };
    let (name, fields) = match &domain {
        Some(d) => (format!("Directory account ({d})"), json!({ "domain": d })),
        None => ("Directory account".to_owned(), json!({})),
    };
    NewCredential { name, kind: CredentialKind::Prompt, fields, secrets: None, key_file: None }
}

/// Whether the OS hint names Windows (owner decision: Windows → RDP, everything else SSH).
#[must_use]
pub fn is_windows(os: Option<&str>) -> bool {
    os.is_some_and(|s| s.to_ascii_lowercase().contains("windows"))
}

/// Map `entries` to a plan. Entry order is kept; `source_ref` is the entry ordinal.
pub fn build_plan(entries: &[RawEntry], opts: &PlanOptions) -> Result<ImportPlan> {
    let mut b = PlanBuilder::new(&opts.limits);
    let mut credential: Option<String> = None;
    for (i, e) in entries.iter().enumerate() {
        let source_ref = format!("entry {}", i + 1);
        let Ok(dn) = Dn::parse(&e.dn) else {
            b.skip(source_ref, SkipReason::Invalid);
            continue;
        };
        let Some(rel) = dn.relative_to(&opts.base) else {
            b.skip(source_ref, SkipReason::Invalid);
            continue;
        };
        let (own, parents) = match rel.split_first() {
            Some((own, parents)) => (Some(own), parents),
            None => (None, &[][..]),
        };
        let mut path: Vec<&str> = parents.iter().rev().map(super::filter::Rdn::display).collect();
        if path.len() > opts.max_depth {
            path.truncate(opts.max_depth);
            b.warn(WarningCode::PathTruncated, &source_ref);
        }
        let folder = b.folder_path(path, &source_ref)?;
        let name = e
            .first("cn")
            .or_else(|| own.map(super::filter::Rdn::display))
            .or_else(|| dn.rdns.first().map(super::filter::Rdn::display))
            .unwrap_or_default()
            .to_owned();
        let host = match opts.kind {
            DirectoryKind::Ad => e.first("dnshostname"),
            DirectoryKind::OpenLdap => {
                e.first("dnshostname").or_else(|| e.first("iphostnumber")).or_else(|| e.first("cn"))
            }
        };
        let Some(host) = host else {
            b.skip(source_ref, SkipReason::Invalid);
            continue;
        };
        let protocol =
            if is_windows(e.first("operatingsystem")) { Protocol::Rdp } else { Protocol::Ssh };
        if credential.is_none() {
            credential = b.credential(prompt_credential(opts), "directory")?;
        }
        b.connection(
            NewConnection {
                name,
                protocol: Some(protocol),
                host: host.to_owned(),
                port: None,
                user: None,
                domain: None,
                folder,
                credential: credential.clone(),
                tags: Vec::new(),
            },
            &source_ref,
        )?;
    }
    Ok(b.finish())
}
