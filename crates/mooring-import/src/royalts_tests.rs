#![allow(clippy::type_complexity)] // golden tuples read better than named structs here

use std::io::Write;

use mooring_core::{CredentialKind, Protocol};

use super::*;
use crate::{ImportOptions, ImportSource};

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/royal.rtsx");

fn parse(bytes: &[u8]) -> Result<crate::ImportPlan> {
    RoyalTs.parse(ImportSource::File { name: "x.rtsx", bytes }, &ImportOptions::default())
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("write");
    e.finish().expect("finish")
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
    assert_eq!(folders, vec![("f1", "Datacenter", None), ("f2", "Rack 1", Some("f1"))]);
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
            ("ts01", Protocol::Rdp, "ts01.example.test", Some(3390), Some("f2"), Some("k3")),
            ("bastion", Protocol::Ssh, "192.0.2.20", Some(22), Some("f1"), Some("k5")),
            ("kvm", Protocol::Vnc, "198.51.100.4", Some(5900), None, None),
            ("Grafana", Protocol::Web, "https://grafana.example.test/d/abc", None, None, None),
        ]
    );
    let creds: Vec<(&str, CredentialKind, bool)> =
        plan.credentials.iter().map(|c| (c.name.as_str(), c.kind, c.has_secret())).collect();
    assert_eq!(
        creds,
        vec![
            ("CORP\\admin", CredentialKind::Prompt, false),
            ("ops", CredentialKind::Prompt, false)
        ]
    );
    let skipped: Vec<(&str, SkipReason)> =
        plan.skipped.iter().map(|s| (s.source_ref.as_str(), s.reason)).collect();
    assert_eq!(
        skipped,
        vec![
            ("RoyalTerminalConnection #7", SkipReason::Unsupported),
            ("RoyalFileTransferConnection #10", SkipReason::Unsupported),
            ("RoyalRDSConnection #11", SkipReason::Invalid),
        ]
    );
    assert_eq!(plan.warnings.len(), 1);
    assert_eq!(plan.warnings[0].code, WarningCode::PasswordDropped);
}

#[test]
fn rtsz_is_gzip_and_zip_is_refused() {
    let z = gz(FIXTURE);
    assert!(RoyalTs.sniff(&z));
    let plan = parse(&z).expect("gzip plan");
    assert_eq!(plan.counts().connections, 4);
    assert_eq!(
        parse(b"PK\x03\x04\x14\x00").expect_err("zip"),
        ImportError::UnsupportedContainer { what: "zip" }
    );
    let mut small = ImportOptions::default();
    small.limits.max_decompressed = 64;
    let e =
        RoyalTs.parse(ImportSource::File { name: "x.rtsz", bytes: &z }, &small).expect_err("cap");
    assert_eq!(e, ImportError::limits("decompressed size"));
}

#[test]
fn protected_document_and_bad_roots() {
    let enc = String::from_utf8_lossy(FIXTURE)
        .replace("<Encrypted>false</Encrypted>", "<Encrypted>true</Encrypted>");
    assert_eq!(parse(enc.as_bytes()).expect_err("encrypted"), ImportError::Encrypted);
    assert!(matches!(parse(b"<Other/>"), Err(ImportError::Format { .. })));
    assert!(matches!(parse(b"<!DOCTYPE r><RTSDocument/>"), Err(ImportError::Doctype { .. })));
    assert!(RoyalTs.sniff(b"<?xml version=\"1.0\"?>\n<RTSDocument"));
    assert!(!RoyalTs.sniff(b"<Connections"));
}

#[test]
fn folder_cycles_land_at_the_root() {
    let doc = r"<RTSDocument>
      <RoyalFolder><ID>a</ID><ParentID>b</ParentID><Name>A</Name></RoyalFolder>
      <RoyalFolder><ID>b</ID><ParentID>a</ParentID><Name>B</Name></RoyalFolder>
      <RoyalSSHConnection><ID>c</ID><ParentID>b</ParentID><Name>s</Name><URI>h.example.test</URI></RoyalSSHConnection>
    </RTSDocument>";
    let plan = parse(doc.as_bytes()).expect("plan");
    assert!(plan.is_consistent());
    assert_eq!(plan.folders.len(), 2);
    assert!(plan.folders.iter().all(|f| f.parent.is_none()));
    assert_eq!(plan.connections[0].folder.as_deref(), Some(plan.folders[1].key.as_str()));
}
