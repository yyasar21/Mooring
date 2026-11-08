//! Filter validation and semantics, the scan cap and cursor, redaction of what leaves.

use super::*;
use mooring_audit::{AuditEntry, AuditEvent};
use time::OffsetDateTime;

const T0_MS: u64 = 1_700_000_000_000;

fn entry(seq: u64, at_ms: u64, event: AuditEvent) -> String {
    let nanos = i128::from(at_ms) * 1_000_000;
    let e = AuditEntry {
        seq,
        at: OffsetDateTime::from_unix_timestamp_nanos(nanos).expect("time"),
        prev: "0".repeat(64),
        event,
    };
    serde_json::to_string(&e).expect("json")
}

fn locked(reason: &str) -> AuditEvent {
    AuditEvent::VaultLocked { reason: reason.to_owned() }
}

fn used(conn: Option<&str>) -> AuditEvent {
    AuditEvent::CredentialUsed {
        credential: "cr-1".into(),
        purpose: "connect".into(),
        connection: conn.map(str::to_owned),
    }
}

/// A log file of `events`, seq 1.., one second apart from `T0_MS`.
fn log(events: Vec<AuditEvent>) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("audit.jsonl");
    let mut text = String::new();
    for (i, ev) in events.into_iter().enumerate() {
        let seq = u64::try_from(i).expect("seq") + 1;
        text.push_str(&entry(seq, T0_MS + (seq - 1) * 1000, ev));
        text.push('\n');
    }
    std::fs::write(&path, text).expect("write");
    (dir, path)
}

fn compile(json: serde_json::Value) -> IpcResult<AuditFilter> {
    let input: AuditFilterInput = serde_json::from_value(json).expect("shape");
    AuditFilter::compile(Some(&input))
}

fn seqs(p: &TailPage) -> Vec<u64> {
    p.entries.iter().map(|e| e.seq).collect()
}

#[test]
fn compile_validates_every_field() {
    let names: Vec<String> = (0..=MAX_FILTER_EVENTS).map(|_| "vault_locked".to_owned()).collect();
    let too_many = compile(serde_json::json!({ "events": names })).expect_err("33");
    assert_eq!((too_many.code, too_many.message.as_str()), ("input.invalid", "invalid filter: too many event names"));
    let e = compile(serde_json::json!({ "events": ["vault_locked", "rm -rf"] })).expect_err("x");
    assert!(e.message.contains("unknown event"), "{}", e.message);
    assert!(compile(serde_json::json!({ "since": 5, "until": 4 })).is_err());
    assert!(compile(serde_json::json!({ "since": 5, "until": 5 })).is_ok());
    let long = "é".repeat(MAX_FILTER_TEXT + 1);
    assert!(compile(serde_json::json!({ "text": long })).is_err());
    assert!(compile(serde_json::json!({ "text": "é".repeat(MAX_FILTER_TEXT) })).is_ok());
    assert!(compile(serde_json::json!({ "text": "a\u{7}b" })).is_err());
    assert!(compile(serde_json::json!({ "connection": "x".repeat(129) })).is_err());
    assert!(compile(serde_json::json!({ "connection": "c\nd" })).is_err());
    // empty pieces constrain nothing
    let empty = compile(serde_json::json!({ "events": [], "connection": "", "text": "  " }));
    assert!(empty.expect("ok").is_empty());
    assert!(AuditFilter::compile(None).expect("none").is_empty());
    // unknown fields are refused at the IPC boundary
    let unknown = serde_json::from_value::<AuditFilterInput>(serde_json::json!({ "path": "/" }));
    assert!(unknown.is_err());
}

#[test]
fn filter_semantics_events_connection_window_and_text() {
    let (_d, path) = log(vec![
        locked("idle"),         // 1  t0
        used(Some("c-web")),    // 2  t0+1s
        used(Some("c-db")),     // 3  t0+2s
        used(None),             // 4  t0+3s
        locked("Screen_Lock"),  // 5  t0+4s
        AuditEvent::VaultUnlocked, // 6 t0+5s
    ]);
    let page = |f: serde_json::Value| {
        scan_page(&path, &compile(f).expect("filter"), 100, None, SCAN_CAP).expect("scan")
    };
    assert_eq!(seqs(&page(serde_json::json!({}))), [6, 5, 4, 3, 2, 1]);
    let ev = page(serde_json::json!({ "events": ["vault_locked", "vault_unlocked"] }));
    assert_eq!(seqs(&ev), [6, 5, 1]);
    assert_eq!(seqs(&page(serde_json::json!({ "connection": "c-db" }))), [3]);
    // since inclusive, until exclusive (Unix ms)
    let w = page(serde_json::json!({ "since": T0_MS + 1000, "until": T0_MS + 4000 }));
    assert_eq!(seqs(&w), [4, 3, 2]);
    // text: case-insensitive, rendered details only (not the event name)
    assert_eq!(seqs(&page(serde_json::json!({ "text": "SCREEN_lock" }))), [5]);
    assert_eq!(seqs(&page(serde_json::json!({ "text": "reason=idle" }))), [1]);
    assert!(page(serde_json::json!({ "text": "vault_unlocked" })).entries.is_empty());
    assert!(page(serde_json::json!({ "text": "null" })).entries.is_empty(), "nulls not rendered");
    // all constraints at once
    let all = page(serde_json::json!({
        "events": ["credential_used"], "connection": "c-web", "since": T0_MS, "text": "CONNECT"
    }));
    assert_eq!(seqs(&all), [2]);
    assert!(all.done);
}

#[test]
fn paging_cursor_and_scan_cap() {
    // 20 entries; only seq 2 and 3 are `vault_unlocked`.
    let events = (1..=20)
        .map(|i| if i == 2 || i == 3 { AuditEvent::VaultUnlocked } else { locked("r") })
        .collect();
    let (_d, path) = log(events);
    let f = compile(serde_json::json!({ "events": ["vault_unlocked"] })).expect("filter");
    // Cap 5: the newest 5 candidates (20..16) hold no match; continue from 16.
    let p1 = scan_page(&path, &f, 10, None, 5).expect("scan");
    assert_eq!((seqs(&p1), p1.scanned_to, p1.done), (vec![], Some(16), false));
    let p2 = scan_page(&path, &f, 10, p1.scanned_to, 5).expect("scan");
    assert_eq!((seqs(&p2), p2.scanned_to, p2.done), (vec![], Some(11), false));
    let p3 = scan_page(&path, &f, 10, Some(6), 5).expect("scan");
    assert_eq!((seqs(&p3), p3.scanned_to, p3.done), (vec![3, 2], Some(1), true));
    // A full page continues from its oldest entry, even when the window is exhausted.
    let all = AuditFilter::default();
    let full = scan_page(&path, &all, 4, None, SCAN_CAP).expect("scan");
    assert_eq!((seqs(&full), full.scanned_to, full.done), (vec![20, 19, 18, 17], Some(17), false));
    let last = scan_page(&path, &all, 4, Some(3), SCAN_CAP).expect("scan");
    assert_eq!((seqs(&last), last.scanned_to, last.done), (vec![2, 1], Some(1), true));
    // Nothing older than seq 1; a missing log is empty and done.
    let none = scan_page(&path, &all, 4, Some(1), SCAN_CAP).expect("scan");
    assert_eq!((seqs(&none), none.scanned_to, none.done), (vec![], None, true));
    let missing = scan_page(&path.with_extension("x"), &all, 4, None, 5).expect("scan");
    assert_eq!((missing.entries.len(), missing.done), (0, true));
}

#[test]
fn broken_and_oversized_lines_are_skipped() {
    let (_d, path) = log(vec![locked("a"), locked("b")]);
    let mut text = std::fs::read_to_string(&path).expect("read");
    text.push_str("{\"seq\":3,\"garbage\n");
    text.push_str("{\"seq\":4,\"pad\":\"");
    text.push_str(&"x".repeat(MAX_LINE_BYTES));
    text.push_str("\"}\n");
    text.push('\n');
    std::fs::write(&path, text).expect("write");
    let p = scan_page(&path, &AuditFilter::default(), 10, None, SCAN_CAP).expect("scan");
    assert_eq!(seqs(&p), [2, 1]);
}

#[test]
fn line_seq_fast_path_and_fallback() {
    assert_eq!(line_seq(r#"{"seq":42,"at":"x"}"#), Some(42));
    assert_eq!(line_seq(r#"{"at":"x","seq":7}"#), Some(7), "fallback parse");
    assert_eq!(line_seq(r#"{"seq":-1,"at":"x"}"#), None);
    assert_eq!(line_seq("not json"), None);
}

#[test]
fn details_are_redacted_and_text_never_sees_secrets() {
    let (_d, path) = log(vec![
        locked("password=hunter2 user=alice"),
        AuditEvent::CredentialCopied { credential: "cr-1".into(), name: "token: abc.def".into() },
    ]);
    let all = AuditFilter::default();
    let p = scan_page(&path, &all, 10, None, SCAN_CAP).expect("scan");
    let wire = serde_json::to_string(&p).expect("json");
    for secret in ["hunter2", "abc.def"] {
        assert!(!wire.contains(secret), "{secret} leaked: {wire}");
        let f = compile(serde_json::json!({ "text": secret })).expect("filter");
        assert!(scan_page(&path, &f, 10, None, SCAN_CAP).expect("scan").entries.is_empty());
    }
    assert!(wire.contains("user=alice"), "non-secret text kept");
    let f = compile(serde_json::json!({ "text": "[redacted]" })).expect("filter");
    assert_eq!(seqs(&scan_page(&path, &f, 10, None, SCAN_CAP).expect("scan")), [2, 1]);
    // flattened like AuditEntry; an unchanged value keeps its JSON type
    let v = serde_json::to_value(&p.entries[1]).expect("json");
    assert_eq!(v["event"], "vault_locked");
    assert_eq!(v["seq"], 1);
    assert!(v.get("at_ms").is_none());
}

#[test]
fn secret_named_detail_keys_lose_their_value() {
    assert_eq!(redact_value("token", Value::String("abc".into())), Value::String("[REDACTED]".into()));
    assert_eq!(redact_value("count", Value::from(3)), Value::from(3));
    assert_eq!(redact_value("connection", Value::Null), Value::Null);
    assert_eq!(redact_value("purpose", Value::String("copy".into())), Value::String("copy".into()));
}
