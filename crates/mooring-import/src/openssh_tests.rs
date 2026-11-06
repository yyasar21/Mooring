#![allow(clippy::type_complexity)] // golden tuples read better than named structs here

use mooring_core::CredentialKind;

use super::*;
use crate::{ImportError, ImportOptions, ImportSource};

const CONFIG: &[u8] = include_bytes!("../tests/fixtures/ssh_config");

fn parse(bytes: &[u8]) -> Result<crate::ImportPlan> {
    Openssh.parse(ImportSource::File { name: "config", bytes }, &ImportOptions::default())
}

#[test]
fn golden_plan() {
    let plan = parse(CONFIG).expect("plan");
    assert!(plan.is_consistent());
    let conns: Vec<(&str, &str, Option<u16>, Option<&str>, Option<&str>, Vec<&str>)> = plan
        .connections
        .iter()
        .map(|c| {
            (
                c.name.as_str(),
                c.host.as_str(),
                c.port,
                c.user.as_deref(),
                c.credential.as_deref(),
                c.tags.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        conns,
        vec![
            ("web01", "web01.example.test", Some(2222), Some("deploy"), Some("k1"), vec![]),
            ("web01-alt", "web01.example.test", Some(2222), Some("deploy"), Some("k1"), vec![]),
            ("db01", "192.0.2.31", None, Some("dba"), Some("k4"), vec!["jump:bastion"]),
            ("bastion", "198.51.100.2", None, Some("ops"), Some("k6"), vec![]),
            ("bare", "bare", None, Some("%r"), Some("k8"), vec![]),
        ]
    );
    let creds: Vec<(&str, CredentialKind, Option<&str>)> =
        plan.credentials.iter().map(|c| (c.name.as_str(), c.kind, c.key_file.as_deref())).collect();
    assert_eq!(
        creds,
        vec![
            ("deploy (id_ed25519)", CredentialKind::SshAgent, Some("~/.ssh/id_ed25519")),
            ("dba (id_rsa)", CredentialKind::SshAgent, Some("~/.ssh/id_rsa")),
            ("ops (lab key)", CredentialKind::SshAgent, Some("~/.ssh/lab key")),
            ("%r (id_rsa)", CredentialKind::SshAgent, Some("~/.ssh/id_rsa")),
        ]
    );
    assert!(plan.credentials.iter().all(|c| !c.has_secret()));
    let warnings: Vec<(WarningCode, &str)> =
        plan.warnings.iter().map(|w| (w.code, w.source_ref.as_str())).collect();
    assert_eq!(
        warnings,
        vec![
            (WarningCode::IncludeIgnored, "line 2"),
            (WarningCode::HostPattern, "line 22"),
            (WarningCode::MatchBlock, "line 25"),
            (WarningCode::HostPattern, "line 34"),
            (WarningCode::ProxyJump, "line 12"),
        ]
    );
    let skipped: Vec<(&str, SkipReason)> =
        plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(
        skipped,
        vec![
            ("line 22", SkipReason::Unsupported),
            ("line 31", SkipReason::Invalid),
            ("line 34", SkipReason::Unsupported)
        ]
    );
}

#[test]
fn users_without_a_key_prompt_and_first_value_wins() {
    let cfg = b"User top\nHost a\n  User inner\n  HostName 192.0.2.1\n  Port 22\n  Port 23\n";
    let plan = parse(cfg).expect("plan");
    assert_eq!(plan.connections[0].user.as_deref(), Some("top"));
    assert_eq!(plan.connections[0].port, Some(22));
    assert_eq!(plan.credentials[0].kind, CredentialKind::Prompt);
    assert_eq!(plan.credentials[0].name, "top");
    let none = parse(b"Host x\n HostName 192.0.2.2\n").expect("plan");
    assert!(none.credentials.is_empty());
    assert!(none.connections[0].credential.is_none());
}

#[test]
fn hostile_shapes() {
    assert!(Openssh.sniff(b"# c\nHost web\n"));
    assert!(Openssh.sniff(b"HostName x.example.test"));
    assert!(!Openssh.sniff(b"<xml/>"));
    assert_eq!(parse(b"").expect("empty").counts(), crate::Counts::default());
    assert_eq!(parse(b"# only comments\n\n").expect("comments").counts(), crate::Counts::default());
    assert!(matches!(parse(b"\xFFHost a"), Err(ImportError::Format { .. })));
    let mut opts = ImportOptions::default();
    opts.limits.max_text = 8;
    let e = Openssh
        .parse(ImportSource::File { name: "config", bytes: b"Host aaaaaaaaaaaa\n" }, &opts)
        .expect_err("cap");
    assert_eq!(e, ImportError::limits("line length"));
    // A bidi alias is skipped, a bad port falls back with a warning.
    let plan = parse("Host a\u{202E}b\nHost ok\n Port 0\n".as_bytes()).expect("plan");
    assert_eq!(plan.connections.len(), 1);
    assert_eq!(plan.skipped[0].reason, SkipReason::Invalid);
    assert!(plan.warnings.iter().any(|w| w.code == WarningCode::PortIgnored));
    assert_eq!(split_line("  Key=Value  "), Some(("Key", "Value".into())));
    assert_eq!(split_line("Key \"a b\""), Some(("Key", "a b".into())));
    assert_eq!(split_line("# x"), None);
    assert_eq!(split_line("Lonely"), None);
}
