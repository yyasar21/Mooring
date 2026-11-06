use mooring_core::{CredentialKind, SecretName};

use super::*;
use crate::{ImportOptions, ImportSource};

const CSV: &[u8] = include_bytes!("../tests/fixtures/termius.csv");
const JSON: &[u8] = include_bytes!("../tests/fixtures/termius.json");

fn parse(name: &str, bytes: &[u8], secrets: bool) -> Result<crate::ImportPlan> {
    let opts = ImportOptions { include_plaintext_secrets: secrets, ..ImportOptions::default() };
    Termius.parse(ImportSource::File { name, bytes }, &opts)
}

#[test]
fn csv_golden_with_opt_in() {
    let plan = parse("hosts.csv", CSV, true).expect("plan");
    assert!(plan.is_consistent());
    let folders: Vec<(&str, Option<&str>)> = plan.folders.iter().map(|f| (f.name.as_str(), f.parent.as_deref())).collect();
    assert_eq!(folders, vec![("Prod", None), ("Web", Some("f1")), ("Lab", None)]);
    let conns: Vec<(&str, &str, Option<u16>, Option<&str>, Option<&str>)> = plan
        .connections
        .iter()
        .map(|c| (c.name.as_str(), c.host.as_str(), c.port, c.folder.as_deref(), c.credential.as_deref()))
        .collect();
    assert_eq!(
        conns,
        vec![
            ("web01", "web01.example.test", Some(22), Some("f2"), Some("k3")),
            ("db01", "192.0.2.31", Some(2201), Some("f1"), Some("k5")),
            ("quoted \"name\"", "198.51.100.50", None, None, None),
            ("badport", "198.51.100.2", None, Some("f8"), Some("k9")),
        ]
    );
    assert_eq!(plan.connections[0].tags, vec!["prod", "web"]);
    let creds: Vec<(&str, CredentialKind, bool)> = plan.credentials.iter().map(|c| (c.name.as_str(), c.kind, c.has_secret())).collect();
    assert_eq!(
        creds,
        vec![("deploy", CredentialKind::UserPassword, true), ("dba", CredentialKind::Prompt, false), ("ops", CredentialKind::Prompt, false)]
    );
    let secret = plan.credentials[0].secrets.as_ref().expect("bundle");
    assert_eq!(secret.iter().collect::<Vec<_>>(), vec![(SecretName::Password, b"test-only-pw".as_slice())]);
    let skipped: Vec<(&str, SkipReason)> = plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(skipped, vec![("record 5", SkipReason::Unsupported), ("record 7", SkipReason::Invalid)]);
    let warnings: Vec<(WarningCode, &str)> = plan.warnings.iter().map(|w| (w.code, w.source_ref.as_str())).collect();
    assert_eq!(warnings, vec![(WarningCode::PortIgnored, "record 6")]);
}

#[test]
fn csv_without_opt_in_drops_the_password() {
    let plan = parse("hosts.csv", CSV, false).expect("plan");
    assert_eq!(plan.counts().secrets, 0);
    assert_eq!(plan.credentials[0].kind, CredentialKind::Prompt);
    assert_eq!(plan.credentials[0].name, "deploy");
    assert!(plan.warnings.iter().any(|w| w.code == WarningCode::PasswordDropped && w.source_ref == "record 2"));
}

#[test]
fn json_golden_with_opt_in() {
    let plan = parse("hosts.json", JSON, true).expect("plan");
    assert!(plan.is_consistent());
    let folders: Vec<(&str, Option<&str>)> = plan.folders.iter().map(|f| (f.name.as_str(), f.parent.as_deref())).collect();
    assert_eq!(folders, vec![("Prod", None), ("Web", Some("f1")), ("Lab", None), ("Jump", Some("f7"))]);
    let conns: Vec<(&str, &str, Option<u16>, Option<&str>)> =
        plan.connections.iter().map(|c| (c.name.as_str(), c.host.as_str(), c.port, c.folder.as_deref())).collect();
    assert_eq!(
        conns,
        vec![
            ("web01", "web01.example.test", Some(22), Some("f2")),
            ("db01", "192.0.2.31", Some(2201), Some("f1")),
            ("bastion", "198.51.100.50", None, Some("f8")),
        ]
    );
    let creds: Vec<(&str, CredentialKind, bool)> = plan.credentials.iter().map(|c| (c.name.as_str(), c.kind, c.has_secret())).collect();
    assert_eq!(
        creds,
        vec![
            ("deploy", CredentialKind::UserPassword, true),
            ("dba", CredentialKind::Prompt, false),
            ("ops (Termius key)", CredentialKind::SshKey, true),
        ]
    );
    let key = plan.credentials[2].secrets.as_ref().expect("key");
    assert!(key.iter().any(|(n, v)| n == SecretName::PrivateKey && v.starts_with(b"-----BEGIN OPENSSH")));
    let skipped: Vec<(&str, SkipReason)> = plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(
        skipped,
        vec![("hosts[3]", SkipReason::Unsupported), ("hosts[4]", SkipReason::Invalid), ("hosts[5]", SkipReason::Invalid)]
    );
    // Without the opt-in the key holder becomes a prompt and nothing secret rides along.
    let plain = parse("hosts.json", JSON, false).expect("plan");
    assert_eq!(plain.counts().secrets, 0);
    assert!(plain.credentials.iter().all(|c| c.kind == CredentialKind::Prompt));
    assert_eq!(plain.warnings.iter().filter(|w| w.code == WarningCode::PasswordDropped).count(), 2);
}

#[test]
fn format_detection_and_hostile_shapes() {
    assert!(Termius.sniff(b"Groups,Label,Tags,Hostname/IP,Protocol\n"));
    assert!(Termius.sniff(b"\xEF\xBB\xBF{\"hosts\": []}"));
    assert!(!Termius.sniff(b"<xml/>"));
    assert!(!Termius.sniff(b"a,b,c\n"));
    // Content decides, not only the name.
    assert!(parse("export.txt", b"[{\"address\":\"h.example.test\"}]", false).is_ok_and(|p| p.counts().connections == 1));
    assert!(matches!(parse("x.json", b"{\"hosts\": [", false), Err(ImportError::Format { .. })));
    assert!(matches!(parse("x.json", b"42", false), Err(ImportError::Format { .. })));
    assert!(matches!(parse("x.csv", b"", false), Err(ImportError::Format { .. })));
    assert!(matches!(parse("x.csv", b"a,b\n1,2\n", false), Err(ImportError::Format { .. })));
    let mut opts = ImportOptions::default();
    opts.limits.max_text = 8;
    let long = b"[{\"address\":\"a-very-long-host.example.test\"}]";
    let e = Termius.parse(ImportSource::File { name: "x.json", bytes: long }, &opts).expect_err("cap");
    assert_eq!(e, ImportError::limits("json string length"));
    // Deep JSON nesting is refused by serde_json's recursion limit, not a stack overflow.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(parse("x.json", deep.as_bytes(), false).is_err());
}
