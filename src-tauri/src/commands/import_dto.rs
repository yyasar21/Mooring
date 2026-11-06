//! Wire shapes of the import commands (ADR-0019 §5). Names only: a credential shows
//! `hasSecret`, never a secret; a source is a `pickId` or a known location, never a path.

use mooring_core::{CredentialKind, Protocol};
use mooring_import::{Counts, ImportFormat, Skipped, Warning};
use serde::{Deserialize, Serialize};

/// `import_formats()` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatDto {
    /// Wire name.
    pub format: ImportFormat,
    /// Label.
    pub label: &'static str,
    /// Picker extensions.
    pub extensions: &'static [&'static str],
    /// `known` value Rust can read without a pick.
    pub known_location: Option<&'static str>,
    /// Whether the plaintext-secret toggle applies.
    pub secrets_possible: bool,
}

/// `import_preview` source: a pick or a known location.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceInput {
    /// From `import_pick`.
    #[serde(default)]
    pub pick_id: Option<String>,
    /// `"openssh"` | `"putty"`.
    #[serde(default)]
    pub known: Option<String>,
}

/// `import_preview` arguments.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewInput {
    /// Source.
    pub source: SourceInput,
    /// Owner decision 16: carry plaintext secrets of plaintext formats.
    #[serde(default)]
    pub include_plaintext_secrets: bool,
    /// ADR-0019 §3: read OpenSSH `IdentityFile`s under `~/.ssh/`.
    #[serde(default)]
    pub import_key_files: bool,
}

/// One tree item of the preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDto {
    /// Plan key.
    pub key: String,
    /// Parent folder key (`None` = import root).
    pub parent: Option<String>,
    /// `folder` | `connection`.
    pub kind: &'static str,
    /// Name.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Protocol (connections).
    pub protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Host.
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Port.
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Username.
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Credential key.
    pub credential_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Existing connection id this duplicates (protocol + host + port + user).
    pub duplicate_of: Option<String>,
}

/// One credential of the preview (names only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialItemDto {
    /// Plan key.
    pub key: String,
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: CredentialKind,
    /// Whether a plaintext secret rides with it (never the secret).
    pub has_secret: bool,
}

/// `import_preview` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// Single-use plan id (10 min).
    pub plan_id: String,
    /// Format.
    pub format: ImportFormat,
    /// Name of the root folder the apply will create.
    pub root_name: String,
    /// Counts.
    pub counts: Counts,
    /// Folders and connections.
    pub items: Vec<ItemDto>,
    /// Credentials.
    pub credentials: Vec<CredentialItemDto>,
    /// Skipped items.
    pub skipped: Vec<Skipped>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// `import_apply` arguments.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyInput {
    /// From the preview.
    pub plan_id: String,
    /// Plan keys to leave out (folders, connections, credentials).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// `skip` (default) | `import` for connections flagged `duplicateOf`.
    #[serde(default)]
    pub duplicates: Option<String>,
}

/// `import_apply` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    /// The new root subfolder.
    pub root_folder_id: String,
    /// Folders created under it.
    pub folders: usize,
    /// Connections created.
    pub connections: usize,
    /// Credentials created.
    pub credentials: usize,
    /// Secrets sealed.
    pub secrets: usize,
    /// Skipped by the parser, excluded or duplicates left out.
    pub skipped: usize,
}
