use mooring_core::CredentialKind;

use super::*;
use crate::{ImportOptions, ImportSource};

const REG: &[u8] = include_bytes!("../tests/fixtures/putty.reg");

fn parse_file(bytes: &[u8]) -> Result<crate::ImportPlan> {
    Putty.parse(ImportSource::File { name: "putty.reg", bytes }, &ImportOptions::default())
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn check(plan: &crate::ImportPlan) {
    assert!(plan.is_consistent());
    assert!(plan.folders.is_empty());
    let conns: Vec<(&str, &str, Option<u16>, Option<&str>, Option<&str>)> = plan
        .connections
        .iter()
        .map(|c| (c.name.as_str(), c.host.as_str(), c.port, c.user.as_deref(), c.credential.as_deref()))
        .collect();
    assert_eq!(
        conns,
        vec![
            ("prod web", "web01.example.test", Some(22), Some("deploy"), Some("k1")),
            ("db-box", "192.0.2.40", Some(2201), Some("dba"), Some("k3")),
        ]
    );
    assert!(plan.credentials.iter().all(|c| c.kind == CredentialKind::Prompt && !c.has_secret()));
    let skipped: Vec<(&str, SkipReason)> = plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(
        skipped,
        vec![("session #1", SkipReason::Unsupported), ("session #4", SkipReason::Unsupported), ("session #5", SkipReason::Invalid)]
    );
    let warnings: Vec<(WarningCode, &str)> = plan.warnings.iter().map(|w| (w.code, w.source_ref.as_str())).collect();
    assert_eq!(warnings, vec![(WarningCode::PpkKey, "session #2")]);
}

#[test]
fn reg_golden_utf8_and_utf16() {
    check(&parse_file(REG).expect("utf-8"));
    let wide = utf16le(std::str::from_utf8(REG).expect("ascii"));
    assert!(Putty.sniff(&wide[..64]));
    check(&parse_file(&wide).expect("utf-16"));
    let bom = [b"\xEF\xBB\xBF".as_slice(), REG].concat();
    check(&parse_file(&bom).expect("bom"));
}

#[test]
fn sessions_directory() {
    let files = vec![
        ("prod%20web".to_owned(), b"HostName=deploy@web01.example.test\nProtocol=ssh\nPortNumber=22\nUserName=\nPublicKeyFile=/home/u/.ssh/k.ppk\n".to_vec()),
        ("Default%20Settings".to_owned(), b"Protocol=ssh\n".to_vec()),
        ("db%2Dbox".to_owned(), b"HostName=192.0.2.40\r\nProtocol=ssh\r\nPortNumber=2201\r\nUserName=dba\r\n".to_vec()),
        ("console".to_owned(), b"HostName=198.51.100.9\nProtocol=serial\n".to_vec()),
        ("quoted".to_owned(), b"HostName=h x.example.test\nProtocol=ssh\n".to_vec()),
        ("bad%FF".to_owned(), b"HostName=h.example.test\n".to_vec()),
        ("binary".to_owned(), b"\xFF\xFEx".to_vec()),
    ];
    let plan = Putty.parse(ImportSource::Dir(&files), &ImportOptions::default()).expect("dir");
    let names: Vec<&str> = plan.connections.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["prod web", "db-box"]);
    assert_eq!(plan.connections[0].user.as_deref(), Some("deploy"));
    assert_eq!(plan.connections[1].port, Some(2201));
    let reasons: Vec<SkipReason> = plan.skipped.iter().map(|s| s.reason).collect();
    assert_eq!(
        reasons,
        vec![SkipReason::Unsupported, SkipReason::Unsupported, SkipReason::Invalid, SkipReason::Invalid, SkipReason::Invalid]
    );
}

#[test]
fn hostile_shapes() {
    assert!(matches!(parse_file(b"not a reg file"), Err(ImportError::Format { .. })));
    assert!(matches!(parse_file(b""), Err(ImportError::Format { .. })));
    assert!(matches!(parse_file(b"\xFF\xFEa"), Err(ImportError::Format { .. })));
    let only_header = parse_file(b"Windows Registry Editor Version 5.00\r\n").expect("empty");
    assert_eq!(only_header.counts(), crate::Counts::default());
    let mut opts = ImportOptions::default();
    opts.limits.max_text = 16;
    let long = format!("Windows Registry Editor Version 5.00\n[x\\PuTTY\\Sessions\\a]\n\"HostName\"=\"{}\"\n", "h".repeat(40));
    let e = Putty.parse(ImportSource::File { name: "x.reg", bytes: long.as_bytes() }, &opts).expect_err("cap");
    assert_eq!(e, ImportError::limits("line length"));
    assert_eq!(percent_decode("a%20b%zz%4"), Some("a b%zz%4".into()));
    assert_eq!(unescape_reg("C:\\\\k\\\"q\\\"\\"), "C:\\k\"q\"\\");
}
