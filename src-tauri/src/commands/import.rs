//! Importer commands (ADR-0019 §3, §5): `import_formats`, `import_pick`, `import_preview`,
//! `import_apply`, `import_discard`. The plan stays in Rust under a `planId`
//! ([`crate::import_plans`]); DTOs carry names only (`hasSecret`, never a secret). Every
//! command needs an unlocked vault; apply is one store transaction into a new root subfolder.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use mooring_audit::AuditEvent;
use mooring_core::{CredentialKind, Protocol, SecretName};
use mooring_import::{
    detect, parse, ImportFormat, ImportOptions, ImportPlan, ImportSource, PlanCredential,
    SkipReason, Skipped,
};
use mooring_store::{ImportBatch, ImportConnection, ImportCredential, ImportFolder, Secrets};
use tauri::{AppHandle, Manager, Runtime, State};

pub use crate::commands::import_dto::{
    ApplyInput, CredentialItemDto, FormatDto, ImportPreview, ImportReport, ItemDto, PreviewInput,
    SourceInput,
};
use crate::commands::import_source::{self, Known, PickedFile};
use crate::commands::sftp_pick::DialogPicker;
use crate::error::{IpcError, IpcResult};
use crate::import_plans::HeldPlan;
use crate::state::AppState;

/// Most keys one `import_apply` may exclude.
pub const MAX_EXCLUDE: usize = 30_000;

/// Codes forwarded verbatim from `mooring_import::ImportError::code` (listed here so the
/// checked-in `ipc-codes.json` carries them; a test pins the two lists).
pub const PARSER_CODES: &[&str] = &[
    "import.too_large",
    "import.format",
    "import.encrypted",
    "import.doctype",
    "import.limits",
    "import.unsupported_container",
];

/// `import_formats()`.
pub fn formats() -> Vec<FormatDto> {
    ImportFormat::ALL
        .into_iter()
        .map(|f| FormatDto {
            format: f,
            label: f.label(),
            extensions: f.extensions(),
            known_location: match f {
                ImportFormat::Openssh => Some("openssh"),
                ImportFormat::Putty => Some("putty"),
                _ => None,
            },
            secrets_possible: f.secrets_possible(),
        })
        .collect()
}

fn import_err(e: &mooring_import::ImportError) -> IpcError {
    IpcError::new(e.code(), e.to_string())
}

/// Root folder name of an apply.
pub fn root_name(format: ImportFormat) -> String {
    let today = time::OffsetDateTime::now_utc().date();
    format!("Imported from {} ({today})", format.label())
}

/// `import_preview`: read the source, parse, keep the plan, answer names only.
pub fn preview(state: &AppState, home: &Path, input: PreviewInput) -> IpcResult<ImportPreview> {
    state.with_ready(|_, _| Ok(()))?;
    let opts = ImportOptions {
        include_plaintext_secrets: input.include_plaintext_secrets,
        limits: mooring_import::Limits::DEFAULT,
    };
    let parsed = match (input.source.pick_id, input.source.known) {
        (Some(pick_id), None) => {
            let (name, bytes) = import_source::read_picked(state, &pick_id, opts.limits.max_input)?;
            let format = detect(&bytes, &name)
                .ok_or_else(|| IpcError::new("import.format", "the file is not a supported export"))?;
            (format, parse(format, ImportSource::File { name: &name, bytes: &bytes }, &opts))
        }
        (None, Some(known)) => match import_source::read_known(home, &known, &opts.limits)? {
            Known::File(format, name, bytes) => {
                (format, parse(format, ImportSource::File { name: &name, bytes: &bytes }, &opts))
            }
            Known::Dir(format, files) => (format, parse(format, ImportSource::Dir(&files), &opts)),
        },
        _ => return Err(IpcError::invalid("source", "exactly one of pickId or known")),
    };
    let (format, plan) = match parsed {
        (format, Ok(plan)) => (format, plan),
        (_, Err(e)) => {
            state.audit(AuditEvent::ImportRefused { code: e.code().to_owned() });
            return Err(import_err(&e));
        }
    };
    finish_preview(state, home, format, plan, input.import_key_files)
}

/// The part of `import_preview` after parsing: key-file opt-in, duplicate check, store the
/// plan, build the DTO. Public for tests that start from a parsed plan.
pub fn finish_preview(
    state: &AppState,
    home: &Path,
    format: ImportFormat,
    mut plan: ImportPlan,
    import_key_files: bool,
) -> IpcResult<ImportPreview> {
    if import_key_files && format == ImportFormat::Openssh {
        attach_key_files(home, &mut plan);
    }
    let duplicates = find_duplicates(state, &plan)?;
    let dto_items = items(&plan, &duplicates);
    let credentials = plan
        .credentials
        .iter()
        .map(|c| CredentialItemDto { key: c.key.clone(), name: c.name.clone(), kind: c.kind, has_secret: c.has_secret() })
        .collect();
    let counts = plan.counts();
    let skipped = plan.skipped.clone();
    let warnings = plan.warnings.clone();
    let plan_id = state.import_plans.insert(plan, format, duplicates, Instant::now());
    state.audit(AuditEvent::ImportPreviewed { format: format.name().to_owned() });
    Ok(ImportPreview {
        plan_id,
        format,
        root_name: root_name(format),
        counts,
        items: dto_items,
        credentials,
        skipped,
        warnings,
    })
}

/// ADR-0019 §3: an `ssh_agent` credential whose key file is readable becomes an `ssh_key`
/// credential with the private key as its secret; anything else is `skipped(key_unreadable)`.
fn attach_key_files(home: &Path, plan: &mut ImportPlan) {
    for c in &mut plan.credentials {
        let Some(key_file) = c.key_file.clone() else { continue };
        if c.kind != CredentialKind::SshAgent {
            continue;
        }
        match import_source::read_identity(home, &key_file) {
            Ok(pem) => {
                let mut secrets = mooring_import::SecretBundle::default();
                secrets.push(SecretName::PrivateKey, pem);
                c.kind = CredentialKind::SshKey;
                c.secrets = Some(secrets);
            }
            Err(_) => plan.skipped.push(Skipped { source_ref: c.key.clone(), reason: SkipReason::KeyUnreadable }),
        }
    }
}

/// Plan connection key → existing connection id with the same protocol, host, port and user.
fn find_duplicates(state: &AppState, plan: &ImportPlan) -> IpcResult<HashMap<String, String>> {
    let existing: HashMap<(Protocol, String, Option<u16>, Option<String>), String> =
        state.with_ready(|_, store| {
            let mut map = HashMap::new();
            for f in store.list_folders()? {
                for c in store.list_connections(f.id)? {
                    let user = match &c.username_override {
                        Some(u) => Some(u.clone()),
                        None => match store.effective_credential(c.id)? {
                            Some(id) => {
                                let v = store.get_credential(id)?.fields.to_value();
                                v.get("username").or_else(|| v.get("user")).and_then(|u| u.as_str()).map(str::to_owned)
                            }
                            None => None,
                        },
                    };
                    let key = (c.protocol, c.host.to_lowercase(), c.effective_port(), user);
                    map.entry(key).or_insert_with(|| c.id.to_string());
                }
            }
            Ok(map)
        })?;
    Ok(plan
        .connections
        .iter()
        .filter_map(|c| {
            let port = c.port.or_else(|| c.protocol.default_port());
            let key = (c.protocol, c.host.to_lowercase(), port, c.user.clone());
            existing.get(&key).map(|id| (c.key.clone(), id.clone()))
        })
        .collect())
}

fn items(plan: &ImportPlan, duplicates: &HashMap<String, String>) -> Vec<ItemDto> {
    let folders = plan.folders.iter().map(|f| ItemDto {
        key: f.key.clone(),
        parent: f.parent.clone(),
        kind: "folder",
        name: f.name.clone(),
        protocol: None,
        host: None,
        port: None,
        username: None,
        credential_key: None,
        duplicate_of: None,
    });
    let connections = plan.connections.iter().map(|c| ItemDto {
        key: c.key.clone(),
        parent: c.folder.clone(),
        kind: "connection",
        name: c.name.clone(),
        protocol: Some(c.protocol),
        host: Some(c.host.clone()),
        port: c.port,
        username: c.user.clone(),
        credential_key: c.credential.clone(),
        duplicate_of: duplicates.get(&c.key).cloned(),
    });
    folders.chain(connections).collect()
}

/// `import_discard({ planId })`.
pub fn discard(state: &AppState, plan_id: &str) -> IpcResult<()> {
    state.with_ready(|_, _| Ok(()))?;
    state.import_plans.take(plan_id, Instant::now()).map(drop)
}

/// `import_apply`: take the plan (single use), drop excluded keys and skipped duplicates,
/// write everything in one transaction.
pub fn apply(state: &AppState, input: ApplyInput) -> IpcResult<ImportReport> {
    state.with_ready(|_, _| Ok(()))?;
    if input.exclude.len() > MAX_EXCLUDE {
        return Err(IpcError::invalid("exclude", "too many keys"));
    }
    let import_duplicates = match input.duplicates.as_deref() {
        None | Some("skip") => false,
        Some("import") => true,
        Some(_) => return Err(IpcError::invalid("duplicates", "expected skip or import")),
    };
    let held = state.import_plans.take(&input.plan_id, Instant::now())?;
    let exclude: HashSet<&str> = input.exclude.iter().map(String::as_str).collect();
    let (batch, left_out) = build_batch(&held, &exclude, import_duplicates, root_name(held.format));
    let outcome = state.with_ready(|vault, store| Ok(store.import_apply(vault, &batch)?))?;
    let skipped = held.plan.counts().skipped + left_out;
    state.audit(AuditEvent::ImportApplied {
        format: held.format.name().to_owned(),
        folders: outcome.folders as u64,
        connections: outcome.connections as u64,
        credentials: outcome.credentials as u64,
        secrets: outcome.secrets as u64,
        skipped: skipped as u64,
    });
    Ok(ImportReport {
        root_folder_id: outcome.root.to_string(),
        folders: outcome.folders,
        connections: outcome.connections,
        credentials: outcome.credentials,
        secrets: outcome.secrets,
        skipped,
    })
}

fn secrets_of(c: &PlanCredential) -> Secrets<'_> {
    c.secrets.as_ref().map(|s| s.iter().collect()).unwrap_or_default()
}

/// The store batch for a held plan: an excluded folder lifts its subtree to the nearest kept
/// ancestor, an excluded credential unlinks its connections, an excluded or skipped-duplicate
/// connection is left out. Returns the batch and how many items were left out.
fn build_batch<'a>(
    held: &'a HeldPlan,
    exclude: &HashSet<&str>,
    import_duplicates: bool,
    root_name: String,
) -> (ImportBatch<'a>, usize) {
    let plan = &held.plan;
    let mut left_out = 0;
    // Effective parent of every plan folder: itself when kept, else its kept ancestor.
    let mut effective: HashMap<&str, Option<String>> = HashMap::new();
    let mut folders = Vec::new();
    for f in &plan.folders {
        let parent = f.parent.as_deref().and_then(|p| effective.get(p).cloned()).flatten();
        if exclude.contains(f.key.as_str()) {
            left_out += 1;
            effective.insert(&f.key, parent);
        } else {
            folders.push(ImportFolder { key: f.key.clone(), parent, name: f.name.clone() });
            effective.insert(&f.key, Some(f.key.clone()));
        }
    }
    let mut connections = Vec::new();
    let mut used: HashSet<&str> = HashSet::new();
    for c in &plan.connections {
        let duplicate = held.duplicates.contains_key(&c.key);
        if exclude.contains(c.key.as_str()) || (duplicate && !import_duplicates) {
            left_out += 1;
            continue;
        }
        let credential = c.credential.as_deref().filter(|k| !exclude.contains(k));
        if let Some(k) = credential {
            used.insert(k);
        }
        connections.push(ImportConnection {
            folder: c.folder.as_deref().and_then(|f| effective.get(f).cloned()).flatten(),
            name: c.name.clone(),
            protocol: c.protocol,
            host: c.host.clone(),
            port: c.port,
            credential: credential.map(str::to_owned),
            tags: c.tags.clone(),
        });
    }
    let mut credentials = Vec::new();
    for c in &plan.credentials {
        if exclude.contains(c.key.as_str()) {
            left_out += 1;
            continue;
        }
        if !used.contains(c.key.as_str()) && c.secrets.is_none() {
            // An unreferenced prompt / agent credential adds nothing.
            continue;
        }
        credentials.push(ImportCredential {
            key: c.key.clone(),
            name: c.name.clone(),
            kind: c.kind,
            fields: c.fields.clone(),
            secrets: secrets_of(c),
        });
    }
    (ImportBatch { root_name, folders, connections, credentials }, left_out)
}

/// `import_formats()`.
#[tauri::command]
pub fn import_formats() -> Vec<FormatDto> {
    formats()
}

/// `import_pick({ format })` → `{ pickId, fileName, size } | null`.
#[tauri::command]
pub async fn import_pick<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    format: String,
) -> IpcResult<Option<PickedFile>> {
    let format = ImportFormat::parse(&format).ok_or_else(|| IpcError::invalid("format", "unknown format"))?;
    let picker = DialogPicker::new(app.clone());
    let autolock = app.try_state::<crate::autolock::AutoLock>();
    import_source::pick(&state, &picker, autolock.as_deref(), format).await
}

/// `import_preview({ source, includePlaintextSecrets, importKeyFiles })`.
#[tauri::command]
pub fn import_preview(
    state: State<'_, AppState>,
    source: SourceInput,
    include_plaintext_secrets: bool,
    import_key_files: bool,
) -> IpcResult<ImportPreview> {
    let home = import_source::home_dir()?;
    preview(&state, &home, PreviewInput { source, include_plaintext_secrets, import_key_files })
}

/// `import_apply({ planId, exclude, duplicates })`.
#[tauri::command]
pub fn import_apply(
    state: State<'_, AppState>,
    plan_id: String,
    exclude: Vec<String>,
    duplicates: Option<String>,
) -> IpcResult<ImportReport> {
    apply(&state, ApplyInput { plan_id, exclude, duplicates })
}

/// `import_discard({ planId })`.
#[tauri::command]
pub fn import_discard(state: State<'_, AppState>, plan_id: String) -> IpcResult<()> {
    discard(&state, &plan_id)
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
