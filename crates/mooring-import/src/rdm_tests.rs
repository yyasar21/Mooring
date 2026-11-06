#![allow(clippy::type_complexity)] // golden tuples read better than named structs here

use mooring_core::{CredentialKind, Protocol};

use super::*;
use crate::{ImportOptions, ImportSource};

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/export.rdm");

fn parse(bytes: &[u8]) -> Result<crate::ImportPlan> {
    Rdm.parse(ImportSource::File { name: "x.rdm", bytes }, &ImportOptions::default())
}

#[test]
fn golden_plan() {
    let plan = parse(FIXTURE).expect("plan");
    assert!(plan.is_consistent());
    let folders: Vec<(&str, &str, Option<&str>)> = plan
        .folders
        .iter()
        .map(|f| (f.key.as_str(), f.name.as_str(), f.parent.as_deref()))
        .collect();
    assert_eq!(folders, vec![("f1", "Prod", None), ("f2", "Web", Some("f1"))]);
    let conns: Vec<(&str, Protocol, &str, Option<u16>, Option<&str>, Option<&str>)> = plan
        .connections
        .iter()
        .map(|c| {
            (
                c.name.as_str(),
                c.protocol,
                c.host.as_str(),
                c.port,
                c.folder.as_deref(),
                c.credential.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        conns,
        vec![
            ("web01", Protocol::Rdp, "web01.example.test", Some(3389), Some("f2"), Some("k3")),
            ("db01", Protocol::Ssh, "192.0.2.30", Some(2200), Some("f1"), Some("k5")),
            ("console", Protocol::Vnc, "198.51.100.40", Some(5901), None, None),
            ("Status page", Protocol::Web, "https://status.example.test/", None, Some("f1"), None),
        ]
    );
    assert_eq!(plan.connections[0].domain.as_deref(), Some("CORP"));
    let creds: Vec<(&str, CredentialKind)> =
        plan.credentials.iter().map(|c| (c.name.as_str(), c.kind)).collect();
    assert_eq!(
        creds,
        vec![("CORP\\svc-web", CredentialKind::Prompt), ("dba", CredentialKind::Prompt)]
    );
    assert!(plan.credentials.iter().all(|c| !c.has_secret()));
    let skipped: Vec<(&str, SkipReason)> =
        plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(
        skipped,
        vec![("Connection #7", SkipReason::Unsupported), ("Connection #8", SkipReason::Invalid)]
    );
    let warnings: Vec<(WarningCode, &str)> =
        plan.warnings.iter().map(|w| (w.code, w.source_ref.as_str())).collect();
    assert_eq!(warnings, vec![(WarningCode::SecretEncrypted, "Connection #3")]);
}

#[test]
fn sniff_roots_and_hostile_shapes() {
    assert!(Rdm.sniff(b"<?xml version=\"1.0\"?><ArrayOfConnection>"));
    assert!(!Rdm.sniff(b"<RTSDocument>"));
    assert!(matches!(parse(b"<Other/>"), Err(ImportError::Format { .. })));
    assert!(matches!(parse(b"<!DOCTYPE a><ArrayOfConnection/>"), Err(ImportError::Doctype { .. })));
    assert_eq!(parse(b"<ArrayOfConnection/>").expect("empty").counts(), crate::Counts::default());
    // A group whose Name repeats the last path segment is not nested twice.
    let doc = b"<ArrayOfConnection><Connection><ConnectionType>Group</ConnectionType><Group>A\\B</Group><Name>B</Name></Connection>\
                <Connection><ConnectionType>Group</ConnectionType><Group>A</Group><Name>C</Name></Connection></ArrayOfConnection>";
    let plan = parse(doc).expect("groups");
    let names: Vec<&str> = plan.folders.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["A", "B", "C"]);
}
