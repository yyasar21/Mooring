use mooring_core::{CredentialKind, Protocol};

use super::*;
use crate::plan::SkipReason;
use crate::{ImportOptions, ImportSource};

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/confCons.xml");

fn parse(bytes: &[u8], secrets: bool) -> Result<crate::ImportPlan> {
    let opts = ImportOptions { include_plaintext_secrets: secrets, ..ImportOptions::default() };
    Mremoteng.parse(ImportSource::File { name: "confCons.xml", bytes }, &opts)
}

#[test]
fn golden_plan() {
    let plan = parse(FIXTURE, true).expect("plan");
    assert!(plan.is_consistent());
    let folders: Vec<(&str, Option<&str>)> =
        plan.folders.iter().map(|f| (f.name.as_str(), f.parent.as_deref())).collect();
    assert_eq!(folders, vec![("Lab", None), ("Old", Some("f1"))]);
    let conns: Vec<(&str, Protocol, &str, Option<u16>, Option<&str>)> = plan
        .connections
        .iter()
        .map(|c| (c.name.as_str(), c.protocol, c.host.as_str(), c.port, c.folder.as_deref()))
        .collect();
    assert_eq!(
        conns,
        vec![
            ("dc01", Protocol::Rdp, "dc01.example.test", Some(3389), Some("f1")),
            ("web01", Protocol::Ssh, "192.0.2.10", Some(2222), Some("f1")),
            ("kvm", Protocol::Vnc, "198.51.100.8", Some(5901), Some("f6")),
            ("intranet", Protocol::Web, "https://wiki.example.test:8443/", None, None),
            ("bad port", Protocol::Ssh, "203.0.113.5", None, None),
        ]
    );
    // Passwords never ride along, even with the opt-in; username + domain become a prompt.
    assert_eq!(plan.credentials.len(), 2);
    assert!(plan.credentials.iter().all(|c| c.kind == CredentialKind::Prompt && !c.has_secret()));
    assert_eq!(plan.credentials[0].name, "CORP\\alice");
    assert_eq!(plan.credentials[0].fields["domain"], "CORP");
    assert_eq!(plan.connections[0].credential.as_deref(), Some(plan.credentials[0].key.as_str()));
    assert_eq!(plan.connections[1].credential.as_deref(), Some(plan.credentials[1].key.as_str()));
    assert_eq!(plan.connections[4].credential.as_deref(), Some(plan.credentials[1].key.as_str()));
    assert!(plan.connections[3].credential.is_none());
    let skipped: Vec<(&str, SkipReason)> =
        plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(skipped, vec![("Node #5", SkipReason::Unsupported), ("Node #8", SkipReason::Invalid)]);
    let warnings: Vec<(WarningCode, &str)> =
        plan.warnings.iter().map(|w| (w.code, w.source_ref.as_str())).collect();
    assert_eq!(
        warnings,
        vec![(WarningCode::PasswordDropped, "Node #2"), (WarningCode::PortIgnored, "Node #9")]
    );
    let counts = plan.counts();
    assert_eq!((counts.folders, counts.connections, counts.credentials, counts.secrets), (2, 5, 2, 0));
}

#[test]
fn encrypted_file_and_wrong_root_are_refused() {
    let enc = String::from_utf8_lossy(FIXTURE).replace("FullFileEncryption=\"false\"", "FullFileEncryption=\"true\"");
    assert_eq!(parse(enc.as_bytes(), false).expect_err("encrypted"), ImportError::Encrypted);
    assert!(matches!(parse(b"<Other/>", false), Err(ImportError::Format { .. })));
    assert!(matches!(parse(b"<!DOCTYPE x><Connections/>", false), Err(ImportError::Doctype { .. })));
    let dir = vec![("confCons.xml".to_owned(), FIXTURE.to_vec())];
    assert!(Mremoteng.parse(ImportSource::Dir(&dir), &ImportOptions::default()).is_err());
}

#[test]
fn sniff_and_empty_document() {
    assert!(Mremoteng.sniff(b"<?xml?><mrng:Connections"));
    assert!(!Mremoteng.sniff(b"<RTSDocument>"));
    let plan = parse(b"<Connections ConfVersion=\"2.6\"/>", false).expect("empty");
    assert_eq!(plan.counts(), crate::Counts::default());
}
