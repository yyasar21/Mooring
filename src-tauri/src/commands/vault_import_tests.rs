//! ADR-0023 §2 import, end to end over the plain command functions: same-vault merge
//! (added / skipped / both copies kept), foreign import with the source master password
//! (re-sealed secrets), typed-confirmation `replace`, trust union, and the refusals that
//! leave the store untouched.

use std::path::{Path, PathBuf};

use super::*;
use crate::commands::sftp_pick::FixedPicker;
use crate::commands::tree;
use crate::commands::vault_export::tests::{export_to, s, seed, PASSPHRASE};
use crate::state::testing::{self, audit_events, Fixture, MASTER};

async fn picked(f: &Fixture, path: &Path) -> String {
    pick(&f.state, &FixedPicker(Some(path.to_path_buf())), None).await.expect("pick").expect("some").pick_id
}

fn input(pick_id: &str, mode: &str, source: Option<&str>, confirm: Option<&str>) -> ImportInput {
    ImportInput {
        pick_id: pick_id.into(),
        password: MASTER.into(),
        source_password: source.map(Into::into),
        mode: mode.into(),
        confirm: confirm.map(Into::into),
    }
}

fn shape(f: &Fixture) -> (usize, usize, usize) {
    let t = tree::list(&f.state).expect("tree");
    let creds = crate::commands::credentials::list(&f.state).expect("creds").len();
    (t.folders.len(), t.connections.len(), creds)
}

/// The plaintext of `cred`'s `password` secret, opened under this state's vault.
fn secret(f: &Fixture, cred: &str) -> Vec<u8> {
    f.state
        .with_ready(|v, st| {
            let snap = mooring_sync::snapshot::from_store(st, &f.state.data_dir, v.vault_id(), "t").expect("snap");
            let sealed: mooring_vault::Sealed =
                serde_json::from_str(&snap.credentials[cred].secrets["password"]).expect("sealed");
            Ok(v.open(cred, "password", &sealed).expect("opens under our DEK").to_vec())
        })
        .expect("ready")
}

async fn backup(f: &Fixture) -> (tempfile::TempDir, PathBuf) {
    let out = tempfile::tempdir().expect("out");
    let path = out.path().join("b.age");
    export_to(f, path.clone()).await;
    (out, path)
}

#[tokio::test]
async fn same_vault_merge_adds_skips_and_keeps_both_copies() {
    let f = testing::unlocked();
    let (conn, cred) = seed(&f);
    let lab = tree::list(&f.state).expect("t").folders.into_iter().find(|x| x.name == "Lab").expect("lab");
    let db = tree::create_connection(&f.state, tree::ConnectionFields::basic(&lab.id, "db", "ssh", "db.example.test"))
        .expect("db");
    let (_out, path) = backup(&f).await;
    // after the backup: `web` edited, `db` deleted, a local-only folder added
    let mut c = tree::ConnectionFields::basic(&lab.id, "web2", "ssh", "web.example.test");
    c.credential_id = Some(cred);
    tree::update_connection(&f.state, &conn, c).expect("update");
    tree::delete_connection(&f.state, &db.id).expect("delete");
    let root = tree::list(&f.state).expect("t").folders.into_iter().find(|x| x.parent_id.is_none()).expect("root");
    tree::create_folder(&f.state, &root.id, "Local only").expect("folder");

    let id = picked(&f, &path).await;
    let info = inspect(&f.state, &id, &s(PASSPHRASE)).expect("inspect");
    assert!(info.same_vault && !info.needs_source_password);
    assert_eq!((info.counts.folders, info.counts.connections, info.counts.credentials), (2, 2, 1));
    let r = apply(&f.state, input(&id, "merge", None, None)).expect("merge");
    assert_eq!(r.mode, "merge");
    assert_eq!(r.added, 1, "the deleted `db` comes back");
    assert_eq!(r.skipped, 2, "Lab and the credential (same secret, other nonce)");
    assert_eq!(r.conflicts.len(), 1, "{:?}", r.conflicts);
    assert_eq!((r.conflicts[0].kind, r.conflicts[0].resolution), ("connection", "kept_both"));
    assert!(r.conflicts[0].name.starts_with("web (imported "), "{:?}", r.conflicts[0]);
    let names: Vec<String> = tree::list(&f.state).expect("t").connections.into_iter().map(|x| x.name).collect();
    assert!(names.contains(&"web2".to_owned()), "the local edit is never overwritten: {names:?}");
    assert_eq!(shape(&f), (3, 3, 1), "root, Lab, Local only; web2, its imported copy, db; one credential");
    let ev = audit_events(&f.state);
    assert!(ev.contains(&"vault.import".to_owned()), "{ev:?}");
    // single use
    assert_eq!(apply(&f.state, input(&id, "merge", None, None)).expect_err("used").code, "input.invalid");
}

#[tokio::test]
async fn foreign_import_needs_the_source_password_and_reseals() {
    let a = testing::unlocked();
    let (_, cred) = seed(&a);
    let (_out, path) = backup(&a).await;
    let b = testing::unlocked();
    let before = shape(&b);
    let id = picked(&b, &path).await;
    let info = inspect(&b.state, &id, &s(PASSPHRASE)).expect("inspect");
    assert!(!info.same_vault && info.needs_source_password);
    let e = apply(&b.state, input(&id, "merge", None, None)).expect_err("no source pw");
    assert_eq!(e.code, "vault.import_source_password");
    assert_eq!(shape(&b), before, "nothing applied");

    // the held document was consumed: inspect again
    let id = picked(&b, &path).await;
    inspect(&b.state, &id, &s(PASSPHRASE)).expect("inspect");
    let e = apply(&b.state, input(&id, "merge", Some("wrong source pw!"), None)).expect_err("wrong");
    assert_eq!(e.code, "vault.import_source_password");
    assert_eq!(shape(&b), before);
    assert!(audit_events(&b.state).contains(&"vault.import_refused".to_owned()));

    let id = picked(&b, &path).await;
    inspect(&b.state, &id, &s(PASSPHRASE)).expect("inspect");
    // both test vaults share the test master password; the source unlocks with it
    let r = apply(&b.state, input(&id, "merge", Some(MASTER), None)).expect("foreign merge");
    assert_eq!(r.added, 3, "Lab, web, ops (the file's root folds into ours)");
    assert_eq!(shape(&b), (2, 1, 1), "one root only");
    assert_eq!(secret(&b, &cred), b"test-only secret", "re-sealed under B's DEK");
}

#[tokio::test]
async fn replace_needs_the_typed_confirmation_and_swaps_everything() {
    let f = testing::unlocked();
    seed(&f);
    let (_out, path) = backup(&f).await;
    let root = tree::list(&f.state).expect("t").folders[0].id.clone();
    tree::create_folder(&f.state, &root, "Extra").expect("extra");
    std::fs::write(f.state.known_hosts_path(), "local.example.test ssh-ed25519 AAAAlocal\n").expect("kh");
    let id = picked(&f, &path).await;
    inspect(&f.state, &id, &s(PASSPHRASE)).expect("inspect");
    for bad in [None, Some("replace"), Some("yes")] {
        let e = apply(&f.state, input(&id, "replace", None, bad)).expect_err("confirm");
        assert_eq!(e.code, "input.invalid", "{bad:?}");
    }
    assert_eq!(apply(&f.state, input(&id, "overwrite", None, None)).expect_err("mode").code, "input.invalid");
    let mut wrong = input(&id, "replace", None, Some(REPLACE_CONFIRMATION));
    wrong.password = "wrong master pw!".into();
    assert_eq!(apply(&f.state, wrong).expect_err("pw").code, "vault.unlock");
    let r = apply(&f.state, input(&id, "replace", None, Some(REPLACE_CONFIRMATION))).expect("replace");
    assert_eq!((r.mode, r.added), ("replace", 4));
    let names: Vec<String> = tree::list(&f.state).expect("t").folders.into_iter().map(|x| x.name).collect();
    assert!(!names.contains(&"Extra".to_owned()), "{names:?}");
    let kh = std::fs::read_to_string(f.state.known_hosts_path()).unwrap_or_default();
    assert!(!kh.contains("local.example.test"), "replace swaps the trust stores too");
}

#[tokio::test]
async fn merge_unions_trust_stores() {
    let f = testing::unlocked();
    std::fs::write(f.state.known_hosts_path(), "a.example.test ssh-ed25519 AAAAa\n").expect("kh");
    let (_out, path) = backup(&f).await;
    std::fs::write(f.state.known_hosts_path(), "b.example.test ssh-ed25519 AAAAb\n").expect("kh");
    let id = picked(&f, &path).await;
    assert_eq!(inspect(&f.state, &id, &s(PASSPHRASE)).expect("i").counts.trust, 1);
    apply(&f.state, input(&id, "merge", None, None)).expect("merge");
    let kh = std::fs::read_to_string(f.state.known_hosts_path()).expect("kh");
    assert!(kh.contains("a.example.test") && kh.contains("b.example.test"), "{kh}");
}

#[tokio::test]
async fn hostile_and_wrong_files_are_refused_as_a_whole() {
    let f = testing::unlocked();
    seed(&f);
    let before = shape(&f);
    let dir = tempfile::tempdir().expect("d");
    // wrong passphrase: the pick survives two refusals, the third consumes it
    let (_out, path) = backup(&f).await;
    let id = picked(&f, &path).await;
    for _ in 0..2 {
        let e = inspect(&f.state, &id, &s("not the passphrase")).expect_err("wrong");
        assert_eq!(e.code, "vault.import_passphrase");
    }
    inspect(&f.state, &id, &s(PASSPHRASE)).expect("third try works");
    // garbage
    let junk = dir.path().join("junk.age");
    std::fs::write(&junk, b"not an age file").expect("junk");
    let id = picked(&f, &junk).await;
    assert_eq!(inspect(&f.state, &id, &s(PASSPHRASE)).expect_err("junk").code, "vault.import_format");
    // a structurally hostile document inside a valid age layer
    let evil = br#"{"version":2,"header":{},"snapshot":{},"exported_at":"","app_version":""}"#;
    let bytes = mooring_vault::export_age_bytes_with_work_factor(evil, &s(PASSPHRASE), 10).expect("age");
    let p = dir.path().join("evil.age");
    std::fs::write(&p, bytes).expect("evil");
    let id = picked(&f, &p).await;
    assert_eq!(inspect(&f.state, &id, &s(PASSPHRASE)).expect_err("evil").code, "vault.import_format");
    // future version
    let v3 = mooring_vault::export_age_bytes_with_work_factor(br#"{"version":3}"#, &s(PASSPHRASE), 10).expect("age");
    std::fs::write(&p, v3).expect("v3");
    let id = picked(&f, &p).await;
    assert_eq!(inspect(&f.state, &id, &s(PASSPHRASE)).expect_err("v3").code, "vault.import_version");
    // too large: refused at the pick, before any read
    let big = dir.path().join("big.age");
    std::fs::File::create(&big).expect("big").set_len(MAX_EXPORT_BYTES as u64 + 1).expect("len");
    let e = pick(&f.state, &FixedPicker(Some(big)), None).await.expect_err("big");
    assert_eq!(e.code, "vault.import_too_large");
    assert_eq!(shape(&f), before, "nothing applied");
}

#[tokio::test]
async fn v1_backups_are_refused_and_holds_die_with_the_lock() {
    let f = testing::unlocked();
    let header = f.state.vault().expect("v").as_ref().expect("v").header().clone();
    let v1 = mooring_vault::ExportDocument {
        header,
        credentials: vec![],
        folders: serde_json::json!([]),
        connections: serde_json::json!([]),
    };
    let raw = serde_json::to_vec(&v1).expect("json");
    let dir = tempfile::tempdir().expect("d");
    let p = dir.path().join("v1.age");
    std::fs::write(&p, mooring_vault::export_age_bytes_with_work_factor(&raw, &s(PASSPHRASE), 10).expect("age")).expect("w");
    let id = picked(&f, &p).await;
    assert_eq!(inspect(&f.state, &id, &s(PASSPHRASE)).expect_err("v1").code, "vault.import_version");

    let (_out, path) = backup(&f).await;
    let id = picked(&f, &path).await;
    inspect(&f.state, &id, &s(PASSPHRASE)).expect("inspect");
    assert!(!f.state.imports.is_empty());
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert!(f.state.imports.is_empty(), "a decrypted document does not outlive the lock");
    crate::commands::vault::unlock(&f.state, s(MASTER)).expect("unlock");
    assert_eq!(apply(&f.state, input(&id, "merge", None, None)).expect_err("gone").code, "input.invalid");
}

/// Review 9 L-52: a crafted backup carrying an ECDSA key for a host pinned here with Ed25519
/// (and a second certificate pin for it) adds nothing for that host; the drop is reported as
/// a `trust` conflict and only the line for an unpinned host is added.
#[tokio::test]
async fn merge_import_never_adds_trust_for_a_pinned_host() {
    use mooring_core::known_certs::{CertProtocol, KnownCerts};
    use mooring_proto_ssh::{KnownHosts, TrustDecision};
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::{PrivateKey, PublicKey};
    const ATTACKER: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJgrXpqaMSFp2gv+iwMloeVMxCGz9/S/RAjpVclIxY+yrNaQXXIJHOQR+gBIGkkIxZR1mb1KMu7gM2jJk0S3YSw=";
    let ed = |seed| PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32])).public_key().clone();
    let attacker = PublicKey::from_openssh(ATTACKER).expect("ecdsa");
    let f = testing::unlocked();
    seed(&f); // ssh `web.example.test` (port 22)
    let kh_path = f.state.known_hosts_path();
    let certs = f.state.data_dir.join(CertProtocol::Rdp.file_name());
    let now = time::OffsetDateTime::now_utc();
    let mut theirs = KnownHosts::new();
    theirs.add_hashed("web.example.test", 22, &attacker).expect("add");
    theirs.add_hashed("new.example.test", 22, &ed(2)).expect("add");
    theirs.save(&kh_path).expect("save");
    let mut their_pin = KnownCerts::new();
    their_pin.add("web.example.test", 22, &[0xbb; 32], now);
    their_pin.save(&certs).expect("save");
    let (_out, path) = backup(&f).await;

    let mut ours = KnownHosts::new();
    ours.add_hashed("web.example.test", 22, &ed(1)).expect("add");
    ours.save(&kh_path).expect("save");
    let mut our_pin = KnownCerts::new();
    our_pin.add("web.example.test", 22, &[0xaa; 32], now);
    our_pin.save(&certs).expect("save");
    let id = picked(&f, &path).await;
    inspect(&f.state, &id, &s(PASSPHRASE)).expect("inspect");
    let r = apply(&f.state, input(&id, "merge", None, None)).expect("merge");

    for file in ["known_hosts", "known_rdp_certs"] {
        let want = ImportConflict {
            kind: "trust",
            id: "web.example.test:22".into(),
            name: file.into(),
            resolution: "kept_local",
        };
        assert!(r.conflicts.contains(&want), "{file}: {:?}", r.conflicts);
    }
    assert_eq!(r.trust_added, 1, "only the unpinned host's key");
    let after = KnownHosts::load(&kh_path).expect("load");
    assert_eq!(after.check("web.example.test", 22, &ed(1)), TrustDecision::Known);
    assert!(matches!(after.check("web.example.test", 22, &attacker), TrustDecision::Mismatch { .. }));
    assert_eq!(after.check("new.example.test", 22, &ed(2)), TrustDecision::Known);
    let pins = KnownCerts::load(&certs).expect("load");
    assert_eq!(pins.distinct_pins("web.example.test", 22), 1, "no trust_conflict from an import");
}
