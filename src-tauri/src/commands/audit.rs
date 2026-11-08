//! Audit viewer commands (ADR-0008 §Audit). Entries hold ids, reasons and fingerprints only
//! (`mooring_audit::AuditEvent`), so returning them is safe; the vault must be unlocked because
//! they reveal inventory (hosts, ids).

//!
//! `audit_tail` takes an optional `filter` (`commands::audit_query`): one call tests at most
//! [`SCAN_CAP`] candidate rows and returns a `scannedTo` cursor to continue from.

use mooring_audit::AuditLog;
use serde::Serialize;
use tauri::State;

use crate::commands::audit_query::{
    self, AuditFilter, AuditFilterInput, Redacted, TailPage, SCAN_CAP,
};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Most entries per `audit_tail` page.
pub const MAX_TAIL: u32 = 500;

fn io_error(e: &std::io::Error) -> IpcError {
    tracing::error!(kind = ?e.kind(), "audit log read failed");
    IpcError::new("audit.io", "the audit log could not be read")
}

/// One filtered page, testing at most `cap` candidate rows (`seq < before`), newest first.
/// `limit` is clamped to 1..=500. Broken lines are skipped (reported by `audit_verify`).
pub fn tail_page(
    state: &AppState,
    limit: u32,
    before: Option<u64>,
    filter: Option<&AuditFilterInput>,
    cap: usize,
) -> IpcResult<TailPage> {
    state.with_ready(|_, _| Ok(()))?;
    let filter = AuditFilter::compile(filter)?;
    let limit = usize::try_from(limit.clamp(1, MAX_TAIL)).unwrap_or(1);
    let path = state.data_dir.join(AppState::AUDIT_FILE);
    // Hold the log mutex so a concurrent append is not read half-written.
    let _guard = state.audit.lock().map_err(|_| IpcError::poisoned())?;
    audit_query::scan_page(&path, &filter, limit, before, cap).map_err(|e| io_error(&e))
}

/// Entries newest first, `seq < before` when given, at most `limit` (clamped to 1..=500),
/// details redacted. The unfiltered shape of `audit_tail`.
pub fn tail(state: &AppState, limit: u32, before: Option<u64>) -> IpcResult<Vec<Redacted>> {
    Ok(tail_page(state, limit, before, None, SCAN_CAP)?.entries)
}

/// `audit_tail` answer: the bare array without `filter` (unchanged wire shape), the page with
/// its cursor when a filter was given.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TailReply {
    /// `AuditEntry[]`.
    Entries(Vec<Redacted>),
    /// `{ entries, scannedTo, done }`.
    Page(TailPage),
}

/// `{ ok, entries, brokenAt }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    /// Chain intact.
    pub ok: bool,
    /// Entries checked.
    pub entries: usize,
    /// First broken line (1-based).
    pub broken_at: Option<usize>,
}

/// Walk the chain.
pub fn verify(state: &AppState) -> IpcResult<VerifyResult> {
    state.with_ready(|_, _| Ok(()))?;
    let path = state.data_dir.join(AppState::AUDIT_FILE);
    let _guard = state.audit.lock().map_err(|_| IpcError::poisoned())?;
    if !path.exists() {
        return Ok(VerifyResult { ok: true, entries: 0, broken_at: None });
    }
    let r = AuditLog::verify(&path).map_err(|e| {
        tracing::error!(error = %e, "audit verify failed");
        IpcError::new("audit.io", "the audit log could not be read")
    })?;
    Ok(VerifyResult { ok: r.ok(), entries: r.entries, broken_at: r.broken_at })
}

// ------------------------------------------------------------------ Tauri wrappers

/// `audit_tail({ limit, before, filter? })`: `AuditEntry[]` without `filter`, otherwise
/// `{ entries, scannedTo, done }`.
#[tauri::command]
pub fn audit_tail(
    state: State<'_, AppState>,
    limit: u32,
    before: Option<u64>,
    filter: Option<AuditFilterInput>,
) -> IpcResult<TailReply> {
    match filter {
        None => tail(&state, limit, before).map(TailReply::Entries),
        Some(f) => tail_page(&state, limit, before, Some(&f), SCAN_CAP).map(TailReply::Page),
    }
}

/// `audit_verify()`.
#[tauri::command]
pub fn audit_verify(state: State<'_, AppState>) -> IpcResult<VerifyResult> {
    verify(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::*;
    use mooring_audit::AuditEvent;

    #[test]
    fn tail_pages_newest_first() {
        let f = unlocked(); // seq 1 = vault_created
        for i in 0..9 {
            f.state.audit(AuditEvent::VaultLocked { reason: format!("r{i}") });
        }
        let page = tail(&f.state, 4, None).expect("tail");
        assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), [10, 9, 8, 7]);
        let next = tail(&f.state, 4, Some(7)).expect("tail");
        assert_eq!(next.iter().map(|e| e.seq).collect::<Vec<_>>(), [6, 5, 4, 3]);
        let last = tail(&f.state, 100, Some(3)).expect("tail");
        assert_eq!(last.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 1]);
        assert_eq!(tail(&f.state, 0, None).expect("clamped").len(), 1);
        let json = serde_json::to_value(&page[0]).expect("json");
        assert_eq!(json["event"], "vault_locked", "flattened as the UI expects");
    }

    #[test]
    fn filtered_tail_returns_a_page_and_the_bare_tail_keeps_its_shape() {
        let f = unlocked();
        f.state.audit(AuditEvent::VaultLocked { reason: "token=abc".into() });
        f.state.audit(AuditEvent::VaultUnlocked);
        let flt: AuditFilterInput =
            serde_json::from_value(serde_json::json!({ "events": ["vault_locked"] })).expect("f");
        let page = tail_page(&f.state, 10, None, Some(&flt), SCAN_CAP).expect("page");
        let json = serde_json::to_value(TailReply::Page(page)).expect("json");
        assert_eq!(json["entries"][0]["reason"], "token=[REDACTED]");
        assert_eq!((json["scannedTo"].as_u64(), json["done"].as_bool()), (Some(1), Some(true)));
        let bare = serde_json::to_value(TailReply::Entries(tail(&f.state, 10, None).expect("t")))
            .expect("json");
        assert_eq!(bare.as_array().map(Vec::len), Some(3), "a plain array, as before");
        let bad: AuditFilterInput =
            serde_json::from_value(serde_json::json!({ "events": ["nope"] })).expect("f");
        let e = tail_page(&f.state, 10, None, Some(&bad), SCAN_CAP).expect_err("bad");
        assert_eq!(e.code, "input.invalid");
    }

    #[test]
    fn verify_detects_tampering_and_requires_unlock() {
        let f = unlocked();
        f.state.audit(AuditEvent::VaultUnlocked);
        f.state.audit(AuditEvent::VaultUnlocked);
        let v = verify(&f.state).expect("verify");
        assert_eq!((v.ok, v.entries, v.broken_at), (true, 3, None));
        let path = f.dir.path().join(AppState::AUDIT_FILE);
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).expect("tamper");
        let v = verify(&f.state).expect("verify");
        assert_eq!((v.ok, v.broken_at), (false, Some(2)));
        assert_eq!(
            serde_json::to_string(&v).expect("json"),
            r#"{"ok":false,"entries":1,"brokenAt":2}"#
        );
        crate::commands::vault::lock(&f.state, None).expect("lock");
        assert_eq!(verify(&f.state).expect_err("locked").code, "vault.locked");
        assert_eq!(tail(&f.state, 10, None).expect_err("locked").code, "vault.locked");
    }
}
