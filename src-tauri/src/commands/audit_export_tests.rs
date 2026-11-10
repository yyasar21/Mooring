//! `audit_export`: CSV escaping and formula neutralisation, JSONL shape, header / footer with
//! the chain result, redaction, filters, the cancel path, refusals, the private part-file write
//! and the `audit.exported` row.

use super::*;
use crate::commands::sftp_pick::FixedPicker;
use crate::state::testing::{self, audit_events, Fixture};

fn seeded() -> Fixture {
    let f = testing::unlocked(); // seq 1 = vault_created
    f.state.audit(AuditEvent::VaultLocked { reason: "password=hunter2 user=alice".into() });
    f.state.audit(AuditEvent::VaultUnlocked);
    f.state.audit(AuditEvent::CredentialUsed {
        credential: "cr-1".into(),
        purpose: "connect".into(),
        connection: Some("c-web".into()),
    });
    f
}

fn filter(json: serde_json::Value) -> AuditFilterInput {
    serde_json::from_value(json).expect("filter")
}

async fn run(
    f: &Fixture,
    target: Option<PathBuf>,
    format: ExportFormat,
    flt: Option<&AuditFilterInput>,
) -> IpcResult<AuditExportResult> {
    export(&f.state, &FixedPicker(target), None, format, flt).await
}

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("dir")
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| Path::new(n).extension().is_some_and(|e| e.eq_ignore_ascii_case("part")))
        .collect()
}

#[test]
fn csv_cells_are_quoted_and_formulas_neutralised() {
    assert_eq!(csv_cell("plain"), "plain");
    assert_eq!(csv_cell(""), "");
    assert_eq!(csv_cell("a,b"), "\"a,b\"");
    assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
    for risky in ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "=HYPERLINK(\"http://x.example.test\")"] {
        let cell = csv_cell(risky);
        let inner = cell.trim_start_matches('"');
        assert!(inner.starts_with('\''), "{risky:?} -> {cell:?}");
    }
    assert_eq!(csv_cell("=A1"), "'=A1");
    assert_eq!(csv_cell("=A1,B1"), "\"'=A1,B1\"");
    assert_eq!(csv_cell("\rcmd"), "\"'\rcmd\"");
    assert_eq!(csv_cell("a=b"), "a=b", "only a leading formula character counts");
    let mut row = Vec::new();
    csv_row(&mut row, &["1", "-x", "a\"b"]).expect("row");
    assert_eq!(String::from_utf8(row).expect("utf8"), "1,'-x,\"a\"\"b\"\r\n");
}

#[tokio::test]
async fn csv_export_writes_header_rows_footer_privately_and_is_audited() {
    let f = seeded();
    let out = tempfile::tempdir().expect("out");
    let r = run(&f, Some(out.path().join("audit")), ExportFormat::Csv, None).await.expect("export");
    assert_eq!(r, AuditExportResult { count: 4, cancelled: false });
    let path = out.path().join("audit.csv");
    let text = std::fs::read_to_string(&path).expect("file");
    let lines: Vec<&str> = text.split("\r\n").collect();
    assert!(lines[0].starts_with("#mooring-audit-export,version=1,exported_at="), "{}", lines[0]);
    assert!(lines[0].ends_with(",chain=intact,verified_entries=4,broken_at=,filtered=false"));
    assert_eq!(lines[1], "seq,at,event,details,prev");
    assert!(lines[2].starts_with("1,") && lines[2].contains(",vault_created,,"));
    assert!(
        lines[3].contains(",vault_locked,reason=password=[REDACTED] user=alice,"),
        "{}",
        lines[3]
    );
    for part in [",credential_used,", "connection=c-web", "credential=cr-1", "purpose=connect"] {
        assert!(lines[5].contains(part), "{part} in {}", lines[5]);
    }
    assert_eq!(lines[6], "#end,rows=4,chain=intact");
    assert_eq!(lines[7], "", "file ends with CRLF");
    assert!(!text.contains("hunter2"));
    assert!(leftovers(out.path()).is_empty(), "no part file left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let events = audit_events(&f.state);
    assert_eq!(events.last().map(String::as_str), Some("audit.exported"));
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    let last: serde_json::Value =
        serde_json::from_str(log.lines().last().expect("line")).expect("json");
    assert_eq!((last["format"].as_str(), last["count"].as_u64()), (Some("csv"), Some(4)));
    assert!(!log.contains(out.path().to_string_lossy().as_ref()), "no path in the audit row");
}

#[tokio::test]
async fn jsonl_export_is_filtered_redacted_and_framed() {
    let f = seeded();
    let out = tempfile::tempdir().expect("out");
    let flt = filter(serde_json::json!({ "events": ["vault_locked", "credential_used"] }));
    let target = Some(out.path().join("audit.JSONL"));
    let r = run(&f, target, ExportFormat::Jsonl, Some(&flt)).await.expect("export");
    assert_eq!(r.count, 2);
    let text = std::fs::read_to_string(out.path().join("audit.JSONL")).expect("existing ext kept");
    let rows: Vec<serde_json::Value> =
        text.lines().map(|l| serde_json::from_str(l).expect("json line")).collect();
    assert_eq!(rows.len(), 4);
    let h = &rows[0]["header"];
    assert_eq!((h["format"].as_str(), h["version"].as_u64()), (Some("mooring-audit-export"), Some(1)));
    assert_eq!(h["chain"], serde_json::json!({ "ok": true, "entries": 4, "brokenAt": null }));
    assert_eq!(h["filtered"], true);
    assert_eq!((rows[1]["seq"].as_u64(), rows[1]["event"].as_str()), (Some(2), Some("vault_locked")));
    assert_eq!(rows[1]["reason"], "password=[REDACTED] user=alice");
    assert_eq!(rows[2]["connection"], "c-web");
    assert_eq!(rows[3]["footer"]["rows"], 2);
    assert!(!text.contains("hunter2"));
}

#[tokio::test]
async fn header_reports_a_broken_chain() {
    let f = seeded();
    let log = f.dir.path().join(AppState::AUDIT_FILE);
    let text = std::fs::read_to_string(&log).expect("log");
    let kept: Vec<&str> = text.lines().filter(|l| !l.contains("vault_unlocked")).collect();
    std::fs::write(&log, kept.join("\n") + "\n").expect("tamper");
    let out = tempfile::tempdir().expect("out");
    run(&f, Some(out.path().join("a.csv")), ExportFormat::Csv, None).await.expect("export");
    let text = std::fs::read_to_string(out.path().join("a.csv")).expect("file");
    assert!(text.lines().next().expect("h").contains(",chain=broken,verified_entries=2,broken_at=3,"));
    assert!(text.contains("#end,rows=3,chain=broken"));
}

#[tokio::test]
async fn cancel_writes_and_audits_nothing() {
    let f = seeded();
    let before = audit_events(&f.state);
    let r = run(&f, None, ExportFormat::Csv, None).await.expect("cancel");
    assert_eq!(r, AuditExportResult { count: 0, cancelled: true });
    assert_eq!(audit_events(&f.state), before);
    assert_eq!(serde_json::to_string(&r).expect("json"), r#"{"count":0,"cancelled":true}"#);
}

#[tokio::test]
async fn refusals_bad_filter_bad_target_and_locked() {
    let f = seeded();
    let out = tempfile::tempdir().expect("out");
    let bad = filter(serde_json::json!({ "events": ["not_an_event"] }));
    let e = run(&f, Some(out.path().join("a")), ExportFormat::Csv, Some(&bad)).await;
    assert_eq!(e.expect_err("filter").code, "input.invalid");
    assert!(std::fs::read_dir(out.path()).expect("dir").next().is_none(), "nothing written");
    // inside the app data directory
    let e = run(&f, Some(f.dir.path().join("x.csv")), ExportFormat::Csv, None).await;
    assert_eq!(e.expect_err("data dir").code, "input.invalid");
    // a directory at the target name
    std::fs::create_dir(out.path().join("d.csv")).expect("mkdir");
    let e = run(&f, Some(out.path().join("d.csv")), ExportFormat::Csv, None).await;
    assert_eq!(e.expect_err("dir").code, "input.invalid");
    let e = run(&f, Some(PathBuf::from("relative.csv")), ExportFormat::Csv, None).await;
    assert_eq!(e.expect_err("relative").code, "input.invalid");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    let e = run(&f, Some(out.path().join("a")), ExportFormat::Jsonl, None).await;
    assert_eq!(e.expect_err("locked").code, "vault.locked");
    assert!(write_export(&f.state, &out.path().join("b.csv"), ExportFormat::Csv, None).is_err());
}

#[test]
fn a_failed_write_leaves_no_part_file() {
    let f = seeded();
    let out = tempfile::tempdir().expect("out");
    let target = out.path().join("gone").join("a.csv"); // parent missing
    let e = write_export(&f.state, &target, ExportFormat::Csv, None).expect_err("io");
    assert_eq!(e.code, "audit.export");
    assert!(!audit_events(&f.state).iter().any(|n| n == "audit.exported"));
    let r = write_through_part(&out.path().join("b.csv"), |w| {
        w.write_all(b"partial")?;
        Err(std::io::Error::other("boom"))
    });
    assert!(r.is_err());
    assert!(leftovers(out.path()).is_empty() && !out.path().join("b.csv").exists());
}

#[test]
fn format_and_input_wire_names() {
    let f: ExportFormat = serde_json::from_str("\"jsonl\"").expect("jsonl");
    assert_eq!(f, ExportFormat::Jsonl);
    assert!(serde_json::from_str::<ExportFormat>("\"xlsx\"").is_err());
    assert!(serde_json::from_str::<ExportFormat>("\"CSV\"").is_err());
    assert_eq!(suggested_name(ExportFormat::Csv).rsplit('.').next(), Some("csv"));
}
