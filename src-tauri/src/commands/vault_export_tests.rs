//! ADR-0023 §2 export: pick + write, passphrase rules, master password, atomic 0600 file,
//! no per-device wrap and no plaintext in the file, counts-only audit.

use std::path::PathBuf;

use super::*;
use crate::commands::credentials::{self, NewCredential};
use crate::commands::sftp_pick::FixedPicker;
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing::{self, audit_events, Fixture, MASTER};

pub(crate) const PASSPHRASE: &str = "a long export passphrase";

pub(crate) fn s(x: &str) -> SecretString {
    SecretString::from(x.to_owned())
}

/// One folder, one connection with its credential (secret `test-only secret`).
pub(crate) fn seed(f: &Fixture) -> (String, String) {
    let root = tree::list(&f.state).expect("tree").folders[0].id.clone();
    let lab = tree::create_folder(&f.state, &root, "Lab").expect("folder");
    let cred = credentials::create(&f.state, NewCredential::password_for_tests("ops")).expect("cred");
    let mut c = ConnectionFields::basic(&lab.id, "web", "ssh", "web.example.test");
    c.credential_id = Some(cred.id.clone());
    let conn = tree::create_connection(&f.state, c).expect("conn");
    (conn.id, cred.id)
}

pub(crate) async fn export_to(f: &Fixture, path: PathBuf) -> ExportSummary {
    let picked = pick(&f.state, &FixedPicker(Some(path)), None).await.expect("pick").expect("some");
    let input = ExportInput {
        pick_id: picked.pick_id,
        password: MASTER.into(),
        export_passphrase: PASSPHRASE.into(),
    };
    export(&f.state, input).expect("export")
}

#[tokio::test]
async fn export_writes_an_armored_private_file_and_audits_counts() {
    let f = testing::unlocked();
    seed(&f);
    let out = tempfile::tempdir().expect("out");
    let picked = pick(&f.state, &FixedPicker(Some(out.path().join("backup"))), None)
        .await
        .expect("pick")
        .expect("some");
    assert_eq!(picked.name, "backup.age", "extension appended, name only");
    let input = |pw: &str, pass: &str| ExportInput {
        pick_id: picked.pick_id.clone(),
        password: pw.into(),
        export_passphrase: pass.into(),
    };
    // refusals keep the pick
    assert_eq!(export(&f.state, input(MASTER, "short")).expect_err("short").code, "vault.export_passphrase");
    let e = export(&f.state, input(MASTER, MASTER)).expect_err("same");
    assert_eq!(e.code, "vault.export_passphrase");
    assert!(e.message.contains("differ"));
    assert_eq!(export(&f.state, input("wrong master pw!", PASSPHRASE)).expect_err("pw").code, "vault.unlock");
    let sum = export(&f.state, input(MASTER, PASSPHRASE)).expect("export");
    assert_eq!((sum.folders, sum.connections, sum.credentials), (2, 1, 1));
    let path = out.path().join("backup.age");
    let bytes = std::fs::read(&path).expect("file");
    assert_eq!(sum.bytes, bytes.len() as u64);
    let text = String::from_utf8(bytes.clone()).expect("armored");
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(!text.contains("test-only secret") && !text.contains("example.test"));
    assert!(!out.path().join("backup.age.part").exists(), "part file renamed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // the pick was consumed by the success
    assert_eq!(export(&f.state, input(MASTER, PASSPHRASE)).expect_err("used").code, "input.invalid");
    let back = backup::import_age(&bytes, &s(PASSPHRASE)).expect("parse");
    let mooring_sync::Imported::V2(d) = back else { panic!("v2") };
    assert!(d.header.keyring_wrap.is_none());
    assert_eq!(d.app_version, env!("CARGO_PKG_VERSION"));
    assert!(audit_events(&f.state).contains(&"vault.exported".to_owned()));
}

#[tokio::test]
async fn the_per_device_wrap_never_reaches_the_file() {
    let (f, _bio) = testing::with_biometric("windows");
    crate::commands::vault::create(&f.state, s(MASTER)).expect("create");
    crate::commands::vault_biometric::enroll(&f.state, s(MASTER)).expect("enrol");
    let out = tempfile::tempdir().expect("out");
    export_to(&f, out.path().join("b.age")).await;
    let bytes = std::fs::read(out.path().join("b.age")).expect("file");
    let mooring_sync::Imported::V2(d) = backup::import_age(&bytes, &s(PASSPHRASE)).expect("parse") else {
        panic!("v2")
    };
    assert!(d.header.keyring_wrap.is_none());
}

#[tokio::test]
async fn pick_refuses_locked_vaults_and_the_data_directory() {
    let f = testing::unlocked();
    let inside = f.state.data_dir.join("x.age");
    let e = pick(&f.state, &FixedPicker(Some(inside)), None).await.expect_err("data dir");
    assert_eq!(e.code, "input.invalid");
    assert_eq!(pick(&f.state, &FixedPicker(None), None).await.expect("cancel"), None);
    let out = tempfile::tempdir().expect("out");
    std::fs::create_dir(out.path().join("dir.age")).expect("dir");
    let e = pick(&f.state, &FixedPicker(Some(out.path().join("dir.age"))), None).await.expect_err("dir");
    assert_eq!(e.code, "input.invalid");
    crate::commands::vault::lock(&f.state, None).expect("lock");
    let e = pick(&f.state, &FixedPicker(Some(out.path().join("a.age"))), None).await.expect_err("locked");
    assert_eq!(e.code, "vault.locked");
}

#[test]
fn passphrase_rules_and_error_mapping() {
    assert!(check_export_passphrase(&s(PASSPHRASE), &s(MASTER)).is_ok());
    assert_eq!(check_export_passphrase(&s("11 chars..."), &s(MASTER)).expect_err("short").code, "vault.export_passphrase");
    let cases = [
        (ExportError::Passphrase, false, "vault.import_passphrase"),
        (ExportError::TooLarge, false, "vault.import_too_large"),
        (ExportError::Version(3), false, "vault.import_version"),
        (ExportError::Format("x"), false, "vault.import_format"),
        (ExportError::Sealed, true, "vault.import_source_password"),
        (ExportError::Sealed, false, "vault.import_format"),
        (ExportError::WeakPassphrase { min: 12 }, false, "vault.import_passphrase"),
    ];
    for (e, foreign, code) in cases {
        let ipc = import_error(&e, foreign);
        assert_eq!(ipc.code, code, "{e:?}");
        assert!(!ipc.message.contains(PASSPHRASE));
    }
    assert_eq!(export_error(&ExportError::TooLarge).code, "vault.export");
}
