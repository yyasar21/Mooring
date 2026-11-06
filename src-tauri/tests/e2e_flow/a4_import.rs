//! A4 Q1 (ADR-0019 §3 test plan): hostile import files through the real command path —
//! `import_pick` (a fixed Rust-side picker) → `import_preview` → `import_apply` — with the
//! audit log checked after every case: a refusal is `import_refused { code }` and nothing of
//! the file name, host or secret ever reaches a row. The parser-level matrix is
//! `crates/mooring-import/tests/hostile.rs`; this file pins the app's handling of it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use mooring_core::CredentialKind;
use mooring_import::{ImportFormat, Limits};

use crate::a4_support::{assert_audit_free_of, assert_refusals_carry_only_a_code, audit_rows};
use crate::commands::import::{self, ApplyInput, PreviewInput, SourceInput};
use crate::commands::import_source;
use crate::commands::sftp_pick::FixedPicker;
use crate::commands::{credentials, tree};
use crate::state::testing;

const MREMOTENG: &[u8] =
    include_bytes!("../../../crates/mooring-import/tests/fixtures/confCons.xml");
const ROYAL: &[u8] = include_bytes!("../../../crates/mooring-import/tests/fixtures/royal.rtsx");
const TERMIUS: &[u8] = include_bytes!("../../../crates/mooring-import/tests/fixtures/termius.csv");
/// 8 MiB of zeros, gzip -9 (≈ 8 KiB): far over the 20:1 ratio, under the 64 MiB cap.
const BOMB: &[u8] =
    include_bytes!("../../../crates/mooring-import/tests/fixtures/hostile/bomb-8mib-zeros.rtsz");

/// Things from the fixtures that must never be audited.
const MARKERS: &[&str] = &[
    "confCons",
    "royal.rtsx",
    "termius",
    "example.test",
    "192.0.2.",
    "bm90LWltcG9ydGVk",
    "test-only-pw",
    "hostile-",
];

/// A directory of hostile files, outside the app data dir (the picker refuses paths inside it).
struct Files {
    dir: tempfile::TempDir,
}

impl Files {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().expect("tmp") }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }
}

/// Pick `path` through the Rust-side dialog stand-in, then preview it.
async fn preview_file(
    st: &crate::state::AppState,
    path: &Path,
    format: ImportFormat,
    secrets: bool,
) -> Result<import::ImportPreview, crate::error::IpcError> {
    let dialog = FixedPicker(Some(path.to_path_buf()));
    let picked = import_source::pick(st, &dialog, None, format).await?.expect("a pick");
    assert_eq!(picked.file_name, path.file_name().expect("name").to_string_lossy());
    let input = PreviewInput {
        source: SourceInput { pick_id: Some(picked.pick_id), known: None },
        include_plaintext_secrets: secrets,
        import_key_files: false,
    };
    import::preview(st, Path::new("/nonexistent"), input)
}

#[tokio::test]
async fn hostile_files_are_refused_by_code_and_audited_without_names() {
    let f = testing::unlocked();
    let st = &f.state;
    let files = Files::new();
    let royal = std::str::from_utf8(ROYAL).expect("utf-8");
    let (head, rest) = royal.split_once("?>").expect("decl");
    let doctype =
        format!("{head}?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>{rest}");
    let entity = format!("{head}?>{}", rest.replacen('>', ">&hostile-entity;", 1));
    let mut deep = String::from("<RTSDocument>");
    deep.push_str(
        &"<RoyalFolder><Name>hostile-deep</Name>".repeat(Limits::DEFAULT.max_xml_depth + 1),
    );
    deep.push_str(&"</RoyalFolder>".repeat(Limits::DEFAULT.max_xml_depth + 1));
    deep.push_str("</RTSDocument>");
    let utf16_reg: Vec<u8> = "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\hostile-u16]\r\n\"HostName\"=\"hostile-u16.example.test\"\r\n\"Protocol\"=\"ssh\"\r\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let cases: Vec<(&str, Vec<u8>, ImportFormat, &str)> = vec![
        ("hostile-doctype.rtsx", doctype.into_bytes(), ImportFormat::RoyalTs, "import.doctype"),
        ("hostile-entity.rtsx", entity.into_bytes(), ImportFormat::RoyalTs, "import.format"),
        ("hostile-deep.rtsx", deep.into_bytes(), ImportFormat::RoyalTs, "import.limits"),
        ("hostile-bomb.rtsz", BOMB.to_vec(), ImportFormat::RoyalTs, "import.limits"),
        (
            "hostile-zip.rtsz",
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00zip".to_vec(),
            ImportFormat::RoyalTs,
            "import.unsupported_container",
        ),
        ("hostile-nobom.reg", utf16_reg, ImportFormat::Putty, "import.format"),
        (
            "hostile-encrypted.xml",
            std::str::from_utf8(MREMOTENG)
                .expect("utf-8")
                .replace("FullFileEncryption=\"false\"", "FullFileEncryption=\"true\"")
                .into_bytes(),
            ImportFormat::Mremoteng,
            "import.encrypted",
        ),
    ];
    for (name, bytes, format, code) in &cases {
        let path = files.write(name, bytes);
        let err = preview_file(st, &path, *format, true).await.expect_err(name);
        assert_eq!(err.code, *code, "{name}: {}", err.message);
        assert!(
            !err.message.contains("hostile"),
            "{name}: message carries the file: {}",
            err.message
        );
        assert!(!err.message.contains("example.test"), "{name}: message carries a host");
    }
    assert!(st.import_plans.is_empty(), "no plan survives a refusal");
    let refused = audit_rows(st, "import_refused");
    assert_eq!(refused.len(), cases.len(), "{refused:?}");
    let codes: Vec<&str> = refused.iter().filter_map(|r| r["code"].as_str()).collect();
    assert_eq!(codes, cases.iter().map(|c| c.3).collect::<Vec<_>>());
    assert_refusals_carry_only_a_code(st, "import_refused");
    assert!(audit_rows(st, "import_previewed").is_empty());
    assert_audit_free_of(st, MARKERS);
    // A file no importer recognises is refused as `import.format` too, with nothing of it in
    // the message (its audit row is the `#[ignore]`d case below).
    let path = files.write("hostile-unknown.bin", &[0, 1, 2, 3, 4, 5, 6, 7]);
    let err = preview_file(st, &path, ImportFormat::Termius, false).await.expect_err("unknown");
    assert_eq!(err.code, "import.format");
    assert!(!err.message.contains("hostile"), "{}", err.message);
    assert_audit_free_of(st, MARKERS);
}

/// Q1 finding (low): `import_preview` of a file `detect` does not recognise answers
/// `import.format` **without** an `import_refused { code }` row, unlike every parser refusal
/// (`preview` returns before the audit branch). ADR-0019 §5 says every refusal is audited.
/// Decision needed in `docs/handoff/a4-qa-q1.md`; un-ignore when rust-core audits that path.
#[tokio::test]
#[ignore = "product gap: undetected format is not audited as import_refused (a4-qa-q1 decision 1)"]
async fn undetected_format_is_audited_as_a_refusal() {
    let f = testing::unlocked();
    let st = &f.state;
    let files = Files::new();
    let path = files.write("hostile-unknown.bin", &[0, 1, 2, 3, 4, 5, 6, 7]);
    let err = preview_file(st, &path, ImportFormat::Termius, false).await.expect_err("unknown");
    assert_eq!(err.code, "import.format");
    let refused = audit_rows(st, "import_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["code"], "import.format");
}

#[tokio::test]
async fn oversized_file_is_refused_at_the_pick_and_at_the_read() {
    let f = testing::unlocked();
    let st = &f.state;
    let files = Files::new();
    let max = Limits::DEFAULT.max_input;
    let path = files.write("hostile-big.csv", &vec![b'\n'; max + 1]);
    let dialog = FixedPicker(Some(path.clone()));
    let e =
        import_source::pick(st, &dialog, None, ImportFormat::Termius).await.expect_err("cap + 1");
    assert_eq!(e.code, "import.too_large");
    assert!(!e.message.contains("hostile"), "{}", e.message);
    // Exactly the cap is picked; a file that grows between the pick and the read is refused.
    std::fs::write(&path, vec![b'\n'; max]).expect("shrink");
    let picked = import_source::pick(st, &dialog, None, ImportFormat::Termius)
        .await
        .expect("pick")
        .expect("picked");
    assert_eq!(picked.size, max as u64);
    let mut grown = std::fs::OpenOptions::new().append(true).open(&path).expect("open");
    grown.write_all(b"\n").expect("grow");
    drop(grown);
    let input = PreviewInput {
        source: SourceInput { pick_id: Some(picked.pick_id.clone()), known: None },
        include_plaintext_secrets: false,
        import_key_files: false,
    };
    assert_eq!(
        import::preview(st, Path::new("/nonexistent"), input).expect_err("grown").code,
        "import.too_large"
    );
    // The pick was single use: a retry needs the dialog again.
    let input = PreviewInput {
        source: SourceInput { pick_id: Some(picked.pick_id), known: None },
        include_plaintext_secrets: false,
        import_key_files: false,
    };
    assert_eq!(
        import::preview(st, Path::new("/nonexistent"), input).expect_err("used").code,
        "input.invalid"
    );
    assert_audit_free_of(st, &["hostile-big", &path.to_string_lossy()]);
}

#[tokio::test]
async fn mremoteng_passwords_never_reach_plan_store_or_audit() {
    let f = testing::unlocked();
    let st = &f.state;
    let files = Files::new();
    let path = files.write("confCons.xml", MREMOTENG);
    for secrets in [false, true] {
        let p = preview_file(st, &path, ImportFormat::Mremoteng, secrets).await.expect("preview");
        assert_eq!(p.format, ImportFormat::Mremoteng);
        assert_eq!(p.counts.secrets, 0, "opt-in {secrets}");
        assert!(
            p.credentials.iter().all(|c| c.kind == CredentialKind::Prompt && !c.has_secret),
            "{:?}",
            p.credentials
        );
        assert!(p.warnings.iter().any(|w| w.code == mooring_import::WarningCode::PasswordDropped));
        let json = serde_json::to_string(&p).expect("json");
        assert!(
            !json.contains("bm90LWltcG9ydGVk") && !json.contains("not-imported"),
            "password in the DTO"
        );
        assert!(!json.contains("confCons"), "file name in the DTO");
        let report = import::apply(
            st,
            ApplyInput { plan_id: p.plan_id, exclude: vec![], duplicates: Some("import".into()) },
        )
        .expect("apply");
        assert_eq!(report.secrets, 0);
        assert!(report.connections >= 3);
    }
    // The store holds only prompt credentials for the import and no secret for them.
    let creds = credentials::list(st).expect("list");
    let imported: Vec<_> = creds.iter().filter(|c| c.kind == "prompt").collect();
    assert!(!imported.is_empty());
    let listed = serde_json::to_string(&creds).expect("json");
    assert!(!listed.contains("bm90LWltcG9ydGVk"));
    let t = tree::list(st).expect("tree");
    assert!(t.connections.iter().any(|c| c.host == "dc01.example.test"));
    // Audit: previewed / applied rows by format and count; no host, no file name, no password.
    assert_eq!(audit_rows(st, "import_previewed").len(), 2);
    let applied = audit_rows(st, "import_applied");
    assert_eq!(applied.len(), 2);
    assert_eq!(applied[0]["format"], "mremoteng");
    assert_eq!(applied[0]["secrets"], 0);
    assert_audit_free_of(
        st,
        &["confCons", "dc01", "example.test", "bm90LWltcG9ydGVk", "not-imported", "alice"],
    );
}

#[tokio::test]
async fn plaintext_opt_in_is_the_only_way_a_secret_enters_and_it_never_hits_the_audit() {
    let f = testing::unlocked();
    let st = &f.state;
    let files = Files::new();
    let path = files.write("hosts.csv", TERMIUS);
    let without = preview_file(st, &path, ImportFormat::Termius, false).await.expect("no opt-in");
    assert_eq!(without.counts.secrets, 0);
    assert!(without.credentials.iter().all(|c| !c.has_secret));
    import::discard(st, &without.plan_id).expect("discard");
    let with = preview_file(st, &path, ImportFormat::Termius, true).await.expect("opt-in");
    assert_eq!(with.counts.secrets, 1);
    assert!(
        !serde_json::to_string(&with).expect("json").contains("test-only-pw"),
        "secret in the DTO"
    );
    let report =
        import::apply(st, ApplyInput { plan_id: with.plan_id, exclude: vec![], duplicates: None })
            .expect("apply");
    assert_eq!(report.secrets, 1);
    let applied = audit_rows(st, "import_applied");
    assert_eq!(applied.last().map(|r| r["secrets"].clone()), Some(serde_json::json!(1)));
    assert_audit_free_of(st, &["test-only-pw", "hosts.csv", "web01", "example.test", "deploy"]);
    // Locking drops a pending plan with its secret.
    let pending = preview_file(st, &path, ImportFormat::Termius, true).await.expect("pending");
    assert_eq!(st.import_plans.len(), 1);
    crate::commands::vault::lock(st, None).expect("lock");
    assert!(st.import_plans.is_empty());
    crate::commands::vault::unlock(st, secrecy::SecretString::from(testing::MASTER.to_owned()))
        .expect("unlock");
    assert_eq!(
        import::apply(
            st,
            ApplyInput { plan_id: pending.plan_id, exclude: vec![], duplicates: None }
        )
        .expect_err("gone")
        .code,
        "import.plan_expired"
    );
}
