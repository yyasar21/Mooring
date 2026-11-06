//! Helpers shared by the A4 (ADR-0018 / 0019 / 0020) flow tests: audit-log inspection that
//! every hostile case ends with, so no file name, host, bind name, DN or secret ever lands in
//! an audit row.

use serde_json::Value;

use crate::state::AppState;

/// The raw audit log.
pub fn audit_text(st: &AppState) -> String {
    std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).unwrap_or_default()
}

/// Every audit row (parsed JSON line) with `event == name`.
pub fn audit_rows(st: &AppState, name: &str) -> Vec<Value> {
    audit_text(st)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["event"] == name)
        .collect()
}

/// Fail when any of `markers` appears anywhere in the audit log (case-sensitive, so pass the
/// lower-case form of a host as well when the input had mixed case).
pub fn assert_audit_free_of(st: &AppState, markers: &[&str]) {
    let text = audit_text(st);
    for m in markers {
        assert!(!text.contains(m), "`{m}` leaked into the audit log:\n{text}");
    }
}

/// Every `import_refused` row carries exactly `{ code }` (plus the envelope), never a name.
pub fn assert_refusals_carry_only_a_code(st: &AppState, event: &str) {
    for row in audit_rows(st, event) {
        let obj = row.as_object().expect("row object");
        for (k, v) in obj {
            assert!(
                matches!(k.as_str(), "event" | "code" | "seq" | "at" | "prev"),
                "{event} row carries `{k}` = {v}: {row}"
            );
        }
        assert!(row["code"].is_string(), "{event} without a code: {row}");
    }
}
