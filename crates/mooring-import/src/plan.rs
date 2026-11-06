//! The dry-run [`ImportPlan`] (ADR-0019 §1) and the [`PlanBuilder`] every importer fills.
//! The builder runs the `mooring-core` validators on every item, de-duplicates folders and
//! credentials, enforces the item caps and keeps plaintext secrets in a [`SecretBundle`].

use std::collections::HashMap;

use mooring_core::credential::{validate_secret, CredentialFields};
use mooring_core::{
    validate_host, validate_name, validate_tag, CredentialKind, Protocol, MAX_TAGS,
};
use serde::Serialize;

use crate::error::{ImportError, Result};
use crate::limits::Limits;
pub use crate::plan_input::{NewConnection, NewCredential, SecretBundle};

/// Longest username (bytes), as the credential schema allows.
pub const MAX_USER: usize = 256;
/// Longest domain (bytes).
pub const MAX_DOMAIN: usize = 253;

/// A folder of the plan. `parent == None` is the import root the apply creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanFolder {
    /// Plan-local key (`f<n>`).
    pub key: String,
    /// Parent folder key.
    pub parent: Option<String>,
    /// Validated name.
    pub name: String,
}

/// A connection of the plan (names only; a credential is a plan key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanConnection {
    /// Plan-local key (`c<n>`).
    pub key: String,
    /// Folder key, `None` for the import root.
    pub folder: Option<String>,
    /// Validated name.
    pub name: String,
    /// Protocol.
    pub protocol: Protocol,
    /// Validated host (URL for `web`).
    pub host: String,
    /// Port, `None` = protocol default.
    pub port: Option<u16>,
    /// Username named by the source (also inside the credential).
    pub user: Option<String>,
    /// Domain named by the source.
    pub domain: Option<String>,
    /// Credential key.
    pub credential: Option<String>,
    /// Validated, de-duplicated tags.
    pub tags: Vec<String>,
}

/// A credential of the plan.
#[derive(Debug)]
pub struct PlanCredential {
    /// Plan-local key (`k<n>`).
    pub key: String,
    /// Validated display name.
    pub name: String,
    /// Kind.
    pub kind: CredentialKind,
    /// Validated plaintext fields (what `credential_create` takes).
    pub fields: serde_json::Value,
    /// Plaintext secrets, see [`SecretBundle`].
    pub secrets: Option<SecretBundle>,
    /// OpenSSH `IdentityFile` as written in the config (a path, never read here; ADR-0019 §3
    /// opt-in happens in `src-tauri`).
    pub key_file: Option<String>,
}

impl PlanCredential {
    /// Whether a plaintext secret rides with the credential.
    #[must_use]
    pub fn has_secret(&self) -> bool {
        self.secrets.as_ref().is_some_and(|s| !s.is_empty())
    }
}

/// Why an item is left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Protocol or object type Mooring has no model for.
    Unsupported,
    /// Failed the core validators (name, host, port).
    Invalid,
    /// An encrypted value or document part.
    Encrypted,
    /// A referenced key file could not be read (set by `src-tauri`).
    KeyUnreadable,
    /// Already in the store (set by `src-tauri` at preview).
    Duplicate,
    /// Dropped because an item cap was hit.
    Limit,
}

/// A skipped item: a positional reference (line, element ordinal), never file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    /// Where in the source.
    pub source_ref: String,
    /// Why.
    pub reason: SkipReason,
}

/// Something imported with a caveat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// OpenSSH `Host` with wildcards or negation.
    HostPattern,
    /// OpenSSH `Match` block ignored.
    MatchBlock,
    /// OpenSSH `Include` not followed.
    IncludeIgnored,
    /// `ProxyJump` kept as a `jump:` tag only.
    ProxyJump,
    /// `PuTTY` PPK key file referenced, not read.
    PpkKey,
    /// A password the source held was not imported (mRemoteNG, or opt-in off).
    PasswordDropped,
    /// An encrypted or obfuscated value was left behind.
    SecretEncrypted,
    /// More than `MAX_TAGS` tags; the rest were dropped.
    TagsTruncated,
    /// A port that is not 1..=65535; the protocol default is used.
    PortIgnored,
    /// A username or domain that failed validation was dropped.
    UserIgnored,
    /// The skipped / warning lists hit their cap; further notes were counted only.
    NotesTruncated,
}

/// A warning entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    /// Code.
    pub code: WarningCode,
    /// Where in the source.
    pub source_ref: String,
}

/// Counts of a plan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// Folders.
    pub folders: usize,
    /// Connections.
    pub connections: usize,
    /// Credentials.
    pub credentials: usize,
    /// Credentials carrying a plaintext secret.
    pub secrets: usize,
    /// Skipped items (including the ones past the notes cap).
    pub skipped: usize,
    /// Warnings (including the ones past the notes cap).
    pub warnings: usize,
}

/// The dry run: nothing here has touched the store.
#[derive(Debug, Default)]
pub struct ImportPlan {
    /// Folders, parents before children.
    pub folders: Vec<PlanFolder>,
    /// Connections.
    pub connections: Vec<PlanConnection>,
    /// Credentials.
    pub credentials: Vec<PlanCredential>,
    /// Skipped items.
    pub skipped: Vec<Skipped>,
    /// Warnings.
    pub warnings: Vec<Warning>,
    /// Skipped items past the notes cap.
    pub skipped_more: usize,
    /// Warnings past the notes cap.
    pub warnings_more: usize,
}

impl ImportPlan {
    /// Counts.
    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            folders: self.folders.len(),
            connections: self.connections.len(),
            credentials: self.credentials.len(),
            secrets: self.credentials.iter().filter(|c| c.has_secret()).count(),
            skipped: self.skipped.len() + self.skipped_more,
            warnings: self.warnings.len() + self.warnings_more,
        }
    }

    /// Whether every connection's folder and credential keys resolve (the fuzz oracle).
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let folder_ok = |k: &Option<String>| {
            k.as_ref().is_none_or(|k| self.folders.iter().any(|f| &f.key == k))
        };
        self.folders.iter().all(|f| folder_ok(&f.parent))
            && self.connections.iter().all(|c| {
                folder_ok(&c.folder)
                    && c.credential
                        .as_ref()
                        .is_none_or(|k| self.credentials.iter().any(|x| &x.key == k))
            })
    }
}

/// Fills an [`ImportPlan`] under the caps.
#[derive(Debug)]
pub struct PlanBuilder {
    limits: Limits,
    plan: ImportPlan,
    folder_keys: HashMap<(Option<String>, String), String>,
    cred_index: HashMap<(CredentialKind, String), Vec<usize>>,
    next: usize,
}

impl PlanBuilder {
    /// An empty plan.
    #[must_use]
    pub fn new(limits: &Limits) -> Self {
        Self {
            limits: *limits,
            plan: ImportPlan::default(),
            folder_keys: HashMap::new(),
            cred_index: HashMap::new(),
            next: 0,
        }
    }

    fn key(&mut self, prefix: char) -> String {
        self.next += 1;
        format!("{prefix}{}", self.next)
    }

    /// Record a skipped item.
    pub fn skip(&mut self, source_ref: impl Into<String>, reason: SkipReason) {
        if self.plan.skipped.len() < self.limits.max_notes {
            self.plan.skipped.push(Skipped { source_ref: source_ref.into(), reason });
        } else {
            self.note_overflow();
            self.plan.skipped_more += 1;
        }
    }

    /// Record a warning.
    pub fn warn(&mut self, code: WarningCode, source_ref: impl Into<String>) {
        if self.plan.warnings.len() < self.limits.max_notes {
            self.plan.warnings.push(Warning { code, source_ref: source_ref.into() });
        } else {
            self.note_overflow();
            self.plan.warnings_more += 1;
        }
    }

    fn note_overflow(&mut self) {
        let already = self.plan.warnings.iter().any(|w| w.code == WarningCode::NotesTruncated);
        if !already {
            if let Some(last) = self.plan.warnings.last_mut() {
                *last = Warning { code: WarningCode::NotesTruncated, source_ref: "plan".into() };
            }
        }
    }

    /// Parse a port text; out-of-range values warn and fall back to the default.
    pub fn port(&mut self, raw: Option<&str>, source_ref: &str) -> Option<u16> {
        let raw = raw.map(str::trim).filter(|s| !s.is_empty())?;
        match raw.parse::<u16>() {
            Ok(p) if p > 0 => Some(p),
            _ => {
                self.warn(WarningCode::PortIgnored, source_ref);
                None
            }
        }
    }

    /// A folder under `parent` (`None` = import root); the same name under the same parent
    /// returns the existing key. An invalid name is skipped and returns `None`.
    pub fn folder(
        &mut self,
        parent: Option<&str>,
        name: &str,
        source_ref: &str,
    ) -> Result<Option<String>> {
        let Ok(name) = validate_name(name) else {
            self.skip(source_ref, SkipReason::Invalid);
            return Ok(None);
        };
        let id = (parent.map(str::to_owned), name.clone());
        if let Some(k) = self.folder_keys.get(&id) {
            return Ok(Some(k.clone()));
        }
        if self.plan.folders.len() >= self.limits.max_folders {
            return Err(ImportError::limits("folders"));
        }
        let key = self.key('f');
        self.plan.folders.push(PlanFolder { key: key.clone(), parent: id.0.clone(), name });
        self.folder_keys.insert(id, key.clone());
        Ok(Some(key))
    }

    /// A nested folder path (`A\B\C` already split); empty segments are ignored. An invalid
    /// segment stops the descent at the last valid one.
    pub fn folder_path<'a>(
        &mut self,
        segments: impl IntoIterator<Item = &'a str>,
        source_ref: &str,
    ) -> Result<Option<String>> {
        let mut parent: Option<String> = None;
        for seg in segments {
            if seg.trim().is_empty() {
                continue;
            }
            match self.folder(parent.as_deref(), seg, source_ref)? {
                Some(k) => parent = Some(k),
                None => break,
            }
        }
        Ok(parent)
    }

    /// A connection; invalid name, host or protocol → skipped, `None`.
    pub fn connection(&mut self, c: NewConnection, source_ref: &str) -> Result<Option<String>> {
        let (Ok(name), Ok(host), Some(protocol)) =
            (validate_name(&c.name), validate_host(&c.host), c.protocol)
        else {
            self.skip(source_ref, SkipReason::Invalid);
            return Ok(None);
        };
        if self.plan.connections.len() >= self.limits.max_connections {
            return Err(ImportError::limits("connections"));
        }
        let user = self.account_field(c.user.as_deref(), MAX_USER, source_ref);
        let domain = self.account_field(c.domain.as_deref(), MAX_DOMAIN, source_ref);
        let mut tags: Vec<String> = Vec::new();
        for t in &c.tags {
            if let Ok(t) = validate_tag(t) {
                if !tags.contains(&t) {
                    tags.push(t);
                }
            }
        }
        if tags.len() > MAX_TAGS {
            tags.truncate(MAX_TAGS);
            self.warn(WarningCode::TagsTruncated, source_ref);
        }
        let key = self.key('c');
        self.plan.connections.push(PlanConnection {
            key: key.clone(),
            folder: c.folder,
            name,
            protocol,
            host,
            port: c.port,
            user,
            domain,
            credential: c.credential,
            tags,
        });
        Ok(Some(key))
    }

    /// Trimmed, bounded username / domain; a bad value is dropped with a warning.
    pub fn account_field(
        &mut self,
        raw: Option<&str>,
        max: usize,
        source_ref: &str,
    ) -> Option<String> {
        let v = raw.map(str::trim).filter(|s| !s.is_empty())?;
        if v.len() > max || v.chars().any(mooring_core::credential::is_forbidden) {
            self.warn(WarningCode::UserIgnored, source_ref);
            return None;
        }
        Some(v.to_owned())
    }

    /// A credential; the same kind, fields and secrets return the existing key. Invalid
    /// fields or secrets → skipped, `None`.
    pub fn credential(&mut self, c: NewCredential, source_ref: &str) -> Result<Option<String>> {
        let Ok(name) = validate_name(&c.name) else {
            self.skip(source_ref, SkipReason::Invalid);
            return Ok(None);
        };
        let Ok(fields) = CredentialFields::from_input(c.kind, &c.fields, None) else {
            self.skip(source_ref, SkipReason::Invalid);
            return Ok(None);
        };
        let fields = fields.to_value();
        let secrets = c.secrets.filter(|s| !s.is_empty());
        if let Some(s) = &secrets {
            if s.iter().any(|(n, v)| validate_secret(c.kind, n, v).is_err()) {
                self.skip(source_ref, SkipReason::Invalid);
                return Ok(None);
            }
        }
        let index_key = (c.kind, fields.to_string());
        if let Some(candidates) = self.cred_index.get(&index_key) {
            for &i in candidates {
                let have = &self.plan.credentials[i];
                if have.secrets == secrets && have.key_file == c.key_file {
                    return Ok(Some(have.key.clone()));
                }
            }
        }
        if self.plan.credentials.len() >= self.limits.max_credentials {
            return Err(ImportError::limits("credentials"));
        }
        let key = self.key('k');
        self.cred_index.entry(index_key).or_default().push(self.plan.credentials.len());
        self.plan.credentials.push(PlanCredential {
            key: key.clone(),
            name,
            kind: c.kind,
            fields,
            secrets,
            key_file: c.key_file,
        });
        Ok(Some(key))
    }

    /// The plan.
    #[must_use]
    pub fn finish(self) -> ImportPlan {
        self.plan
    }

    /// Folders so far (the mRemoteNG / Royal TS importers resolve parents by key).
    #[must_use]
    pub fn folder_count(&self) -> usize {
        self.plan.folders.len()
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
