//! `audit_export({ format, filter? })` (A5 Harbor W3 decision 1): the audit log, filtered like
//! `audit_tail`, written to a file the user picks.
//!
//! * The save dialog opens from Rust (review 4 B-4, like `vault_export_pick`); the `WebView`
//!   never sees a path, only `{ count, cancelled }`. The auto-lock ignores focus loss while the
//!   dialog is open (M-9). A vault locked while the dialog was open refuses the write.
//! * Rows are [`Redacted`] entries (the redaction `audit_tail` applies), oldest first. A header
//!   carries the chain verification of the whole log at export time; a footer the row count.
//!   The rows are a redacted, possibly filtered subset, so the file itself cannot be
//!   re-verified; the `prev` column only lets a reader match rows against the original log.
//! * CSV is written by hand (RFC 4180 quoting) and neutralises spreadsheet formulas: a cell
//!   starting with `=`, `+`, `-`, `@`, tab or CR gets a leading `'` (OWASP CSV injection).
//! * The file goes through a fresh `.<name>.<nonce>.part` (`create_new`, 0600, fsync, rename;
//!   review 9 L-51). Audited `audit.exported { format, count }`, no path.

use std::borrow::Cow;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use mooring_audit::{AuditEvent, AuditLog};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::oneshot;

use crate::autolock::AutoLock;
use crate::commands::audit::VerifyResult;
use crate::commands::audit_query::{for_each_match, AuditFilter, AuditFilterInput, Redacted};
use crate::commands::sftp_pick::{DialogPicker, LocalPicker};
use crate::commands::vault_export::check_save_target;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Version of the export layout (header row / object).
pub const EXPORT_VERSION: u32 = 1;
/// CSV column names, in order.
pub const CSV_COLUMNS: [&str; 5] = ["seq", "at", "event", "details", "prev"];

/// `csv` | `jsonl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// Comma-separated, one row per entry, details as `key=value; …`.
    Csv,
    /// One JSON object per line, entries in the `audit_tail` shape.
    Jsonl,
}

impl ExportFormat {
    /// Wire name, file extension and audit `format`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Csv => "CSV",
            Self::Jsonl => "JSON Lines",
        }
    }
}

/// `{ count, cancelled }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportResult {
    /// Entries written (0 when cancelled).
    pub count: u64,
    /// The user closed the dialog; nothing was written or audited.
    pub cancelled: bool,
}

impl AuditExportResult {
    const CANCELLED: Self = Self { count: 0, cancelled: true };
}

fn export_failed(e: &std::io::Error) -> IpcError {
    tracing::warn!(kind = ?e.kind(), "audit export not written");
    IpcError::new("audit.export", "the audit export could not be written")
}

fn suggested_name(format: ExportFormat) -> String {
    let date = time::OffsetDateTime::now_utc().date();
    format!("mooring-audit-{date}.{}", format.name())
}

/// Validate the filter, open the save dialog, validate the answer. `None` when cancelled.
pub async fn pick_target(
    state: &AppState,
    picker: &dyn LocalPicker,
    autolock: Option<&AutoLock>,
    format: ExportFormat,
    filter: Option<&AuditFilterInput>,
) -> IpcResult<Option<PathBuf>> {
    state.with_ready(|_, _| Ok(()))?;
    AuditFilter::compile(filter)?; // refuse a bad filter before any dialog
    let chosen = {
        let _open = autolock.map(AutoLock::dialog_guard);
        let (tx, rx) = oneshot::channel();
        let reply = Box::new(move |p| drop(tx.send(p)));
        picker.pick_save(&suggested_name(format), format.label(), &[format.name()], reply);
        rx.await.ok().flatten()
    };
    let Some(raw) = chosen else { return Ok(None) };
    state.with_ready(|_, _| Ok(()))?; // locked while the dialog was open
    let (path, _name) = check_save_target(state, &raw, format.name())?;
    Ok(Some(path))
}

/// RFC 4180 cell with formula neutralisation.
#[must_use]
pub fn csv_cell(raw: &str) -> Cow<'_, str> {
    let risky = raw.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let quote = raw.contains([',', '"', '\n', '\r']);
    if !risky && !quote {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len() + 4);
    if quote {
        out.push('"');
    }
    if risky {
        out.push('\'');
    }
    if quote {
        out.push_str(&raw.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(raw);
    }
    Cow::Owned(out)
}

fn csv_row(w: &mut impl Write, cells: &[&str]) -> std::io::Result<()> {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        w.write_all(csv_cell(cell).as_bytes())?;
    }
    w.write_all(b"\r\n")
}

fn chain_word(v: &VerifyResult) -> &'static str {
    if v.ok {
        "intact"
    } else {
        "broken"
    }
}

fn write_header(
    w: &mut impl Write,
    format: ExportFormat,
    chain: &VerifyResult,
    filtered: bool,
) -> std::io::Result<()> {
    let exported_at = crate::dto::ts(time::OffsetDateTime::now_utc());
    match format {
        ExportFormat::Csv => {
            let broken = chain.broken_at.map(|b| b.to_string()).unwrap_or_default();
            csv_row(
                w,
                &[
                    "#mooring-audit-export",
                    &format!("version={EXPORT_VERSION}"),
                    &format!("exported_at={exported_at}"),
                    &format!("chain={}", chain_word(chain)),
                    &format!("verified_entries={}", chain.entries),
                    &format!("broken_at={broken}"),
                    &format!("filtered={filtered}"),
                ],
            )?;
            csv_row(w, &CSV_COLUMNS)
        }
        ExportFormat::Jsonl => {
            let header = serde_json::json!({ "header": {
                "format": "mooring-audit-export",
                "version": EXPORT_VERSION,
                "exportedAt": exported_at,
                "chain": chain,
                "filtered": filtered,
            }});
            serde_json::to_writer(&mut *w, &header)?;
            w.write_all(b"\n")
        }
    }
}

fn write_row(w: &mut impl Write, format: ExportFormat, e: &Redacted) -> std::io::Result<()> {
    match format {
        ExportFormat::Csv => {
            let seq = e.seq.to_string();
            let details = e.rendered_details().join("; ");
            csv_row(w, &[&seq, &e.at, &e.event, &details, &e.prev])
        }
        ExportFormat::Jsonl => {
            serde_json::to_writer(&mut *w, e)?;
            w.write_all(b"\n")
        }
    }
}

fn write_footer(
    w: &mut impl Write,
    format: ExportFormat,
    chain: &VerifyResult,
    rows: u64,
) -> std::io::Result<()> {
    match format {
        ExportFormat::Csv => csv_row(
            w,
            &["#end", &format!("rows={rows}"), &format!("chain={}", chain_word(chain))],
        ),
        ExportFormat::Jsonl => {
            let footer = serde_json::json!({ "footer": { "rows": rows, "chain": chain } });
            serde_json::to_writer(&mut *w, &footer)?;
            w.write_all(b"\n")
        }
    }
}

/// Write `body` to `path` through a fresh part file (0600, `create_new`, fsync, rename).
fn write_through_part(
    path: &Path,
    body: impl FnOnce(&mut BufWriter<std::fs::File>) -> std::io::Result<u64>,
) -> std::io::Result<u64> {
    let (part, f) = crate::state::create_part(path)?;
    let result = (|| {
        let mut w = BufWriter::new(f);
        let n = body(&mut w)?;
        let f = w.into_inner().map_err(std::io::IntoInnerError::into_error)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&part, path)?;
        Ok(n)
    })();
    if result.is_err() {
        drop(std::fs::remove_file(&part));
    } else if let Some(dir) = path.parent() {
        crate::state::sync_dir(dir);
    }
    result
}

/// Verify the chain, write the export to `path` and audit it. Returns the row count.
pub fn write_export(
    state: &AppState,
    path: &Path,
    format: ExportFormat,
    filter: Option<&AuditFilterInput>,
) -> IpcResult<u64> {
    state.with_ready(|_, _| Ok(()))?;
    let compiled = AuditFilter::compile(filter)?;
    let log = state.data_dir.join(AppState::AUDIT_FILE);
    let count = {
        // One consistent view: no append between the verification and the rows.
        let _guard = state.audit.lock().map_err(|_| IpcError::poisoned())?;
        let chain = if log.exists() {
            let r = AuditLog::verify(&log).map_err(|e| {
                tracing::error!(error = %e, "audit verify failed");
                IpcError::new("audit.io", "the audit log could not be read")
            })?;
            VerifyResult { ok: r.ok(), entries: r.entries, broken_at: r.broken_at }
        } else {
            VerifyResult { ok: true, entries: 0, broken_at: None }
        };
        write_through_part(path, |w| {
            write_header(w, format, &chain, !compiled.is_empty())?;
            let mut rows = 0_u64;
            for_each_match(&log, &compiled, |e| {
                rows += 1;
                write_row(w, format, e)
            })?;
            write_footer(w, format, &chain, rows)?;
            Ok(rows)
        })
        .map_err(|e| export_failed(&e))?
    };
    state.audit(AuditEvent::AuditExported { format: format.name().to_owned(), count });
    Ok(count)
}

/// Pick and write in one call (tests and the command share it; the command writes off the
/// async runtime).
pub async fn export(
    state: &AppState,
    picker: &dyn LocalPicker,
    autolock: Option<&AutoLock>,
    format: ExportFormat,
    filter: Option<&AuditFilterInput>,
) -> IpcResult<AuditExportResult> {
    let Some(path) = pick_target(state, picker, autolock, format, filter).await? else {
        return Ok(AuditExportResult::CANCELLED);
    };
    let count = write_export(state, &path, format, filter)?;
    Ok(AuditExportResult { count, cancelled: false })
}

// ------------------------------------------------------------------ Tauri wrapper

/// `audit_export({ format, filter? })` → `{ count, cancelled }`.
#[tauri::command]
pub async fn audit_export<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    format: ExportFormat,
    filter: Option<AuditFilterInput>,
) -> IpcResult<AuditExportResult> {
    let picker = DialogPicker::new(app.clone());
    let autolock = app.try_state::<AutoLock>();
    let target =
        pick_target(&state, &picker, autolock.as_deref(), format, filter.as_ref()).await?;
    let Some(path) = target else { return Ok(AuditExportResult::CANCELLED) };
    let count = super::off_thread(app, move |app| {
        write_export(&app.state::<AppState>(), &path, format, filter.as_ref())
    })
    .await?;
    Ok(AuditExportResult { count, cancelled: false })
}

#[cfg(test)]
#[path = "audit_export_tests.rs"]
mod tests;
