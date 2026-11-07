//! Sync tests of security re-review 6b (L-35 fail-closed trust conflicts, L-37 staged header
//! recovery). Fixtures (`Dev`, `server`, `FailingWriter`, …) live in `sync_tests.rs`.

use mooring_core::known_certs::{CertProtocol, KnownCerts};
use serde_json::json;

use super::super::sync_trust::StatusConflict;
use super::*;
use crate::commands::sync_join::{self, JoinInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vault;
use crate::state::testing::{self, Fixture, MASTER};
use crate::state::AppState;

/// Review 6b L-37: (a) when the start-up rename of a staged joined header fails, the staged
/// file is kept (it is the only copy) and the device still starts on the joined vault its
/// store is bound to; (b) a staged header is never installed over a newer header of the same
/// vault: after a failed commit, a password change rewrites the header and removes the staged
/// copy, and a restart unlocks with the new password.
#[tokio::test]
async fn a_staged_header_is_neither_lost_nor_installed_over_a_newer_one() {
    let s3 = server().await;
    let a = dev("device-a");
    a.add("shared", "192.0.2.70");
    a.configure(&s3).await.expect("configure");
    a.now().await.expect("push");
    let vault_id = a.status().vault_id;
    let tmp = |st: &AppState| st.data_dir.join(sync_join::JOIN_TMP);

    // (a) Unit: the store is bound to the staged vault, the rename fails (the header path is a
    // directory): the staged file stays and the staged vault is returned.
    let dir = tempfile::tempdir().expect("dir");
    let joined_bytes = std::fs::read(a.f.state.data_dir.join(AppState::HEADER_FILE)).expect("header");
    std::fs::write(dir.path().join(sync_join::JOIN_TMP), &joined_bytes).expect("stage");
    std::fs::create_dir(dir.path().join(AppState::HEADER_FILE)).expect("block the rename");
    let store = mooring_store::Store::open(dir.path().join(AppState::DB_FILE)).expect("store");
    store.set_vault_id(&vault_id).expect("bind");
    let recovered = sync_join::recover_staged_header(dir.path(), &store, None).expect("the staged vault");
    assert_eq!(recovered.vault_id().to_string(), vault_id);
    assert!(dir.path().join(sync_join::JOIN_TMP).exists(), "the only copy is kept");

    // (b) A failed commit, then a password change: the staged copy is removed by the header
    // write; after a restart the new password unlocks and the header is the joined vault's.
    let g = dev("device-g");
    let input = JoinInput {
        backend: backend(&s3),
        credential_id: add_key(&g.f.state, &s3),
        vault_id: vault_id.clone(),
        password: MASTER.into(),
        interval_minutes: None,
    };
    let writer = FailingWriter { stage: false, commit: true };
    sync_join::join_with(&g.f.state, &g.hub, Some(&g.p), None, input, &writer).await.expect("join");
    assert!(tmp(&g.f.state).exists());
    let new_pw = "another-long-master-password-42";
    vault::change_password(&g.f.state, secrecy::SecretString::from(MASTER.to_owned()), secrecy::SecretString::from(new_pw.to_owned()))
        .expect("change password");
    assert!(!tmp(&g.f.state).exists(), "save_header removed the stale staged copy");
    assert_eq!(header_on_disk(&g.f.state), vault_id);
    let Dev { f: Fixture { dir, state, clipboard }, .. } = g;
    drop(state);
    let st = AppState::new(testing::dirs(dir.path()), testing::settings(clipboard)).expect("restart");
    assert_eq!(header_on_disk(&st), vault_id);
    assert!(vault::unlock(&st, secrecy::SecretString::from(MASTER.to_owned())).is_err(), "the old password is gone");
    vault::unlock(&st, secrecy::SecretString::from(new_pw.to_owned())).expect("the new password unlocks");
    // Belt and braces: a staged copy of the same vault that appears later is not installed
    // either (the current header is newer).
    std::fs::write(st.data_dir.join(sync_join::JOIN_TMP), &joined_bytes).expect("stale copy");
    drop(st);
    let st = AppState::new(testing::dirs(dir.path()), testing::settings(std::sync::Arc::new(crate::clipboard::MemoryClipboard::default()))).expect("restart");
    assert!(!tmp(&st).exists(), "removed, not installed");
    vault::unlock(&st, secrecy::SecretString::from(new_pw.to_owned())).expect("still the new password");
    s3.recorder().assert_no_violations();
}

/// Review 6 L-35 / 6b: two devices pin different certificates for one host; after the merge
/// both lines are kept, the conflict is audited and listed in `sync_status.conflicts`, every
/// connection to the host fails closed (`http.trust_conflict`) until the pins are removed in
/// the known-certificates manager, and SSH `known_hosts` conflicts are counted per key type.
#[tokio::test]
async fn conflicting_pins_after_a_sync_are_audited_listed_and_fail_closed() {
    use time::OffsetDateTime;
    let s3 = server().await;
    let a = dev("device-a");
    a.configure(&s3).await.expect("configure");
    let rdp = ConnectionFields { port: Some(3389), ..ConnectionFields::basic(&a.root(), "desk", "rdp", "rdp.example.test") };
    tree::create_connection(&a.f.state, rdp).expect("rdp");
    a.add("shell", "ssh.example.test");
    a.now().await.expect("push");
    let vault_id = a.status().vault_id;
    let b = dev("device-b");
    b.join_from(&s3, &vault_id, MASTER).await.expect("join");
    let file = |d: &Dev| d.f.state.data_dir.join(CertProtocol::Rdp.file_name());
    let now = OffsetDateTime::now_utc();
    KnownCerts::add_and_save(&file(&a), "rdp.example.test", 3389, &[1; 32], now).expect("pin a");
    KnownCerts::add_and_save(&file(&b), "rdp.example.test", 3389, &[2; 32], now).expect("pin b");
    a.now().await.expect("a push");
    b.now().await.expect("b merge");
    let merged = KnownCerts::load(&file(&b)).expect("load");
    assert_eq!(merged.distinct_pins("rdp.example.test", 3389), 2, "both pins kept, none removed");
    let conflicts = |d: &Dev| {
        std::fs::read_to_string(d.f.state.data_dir.join(AppState::AUDIT_FILE))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["event"] == "trust_conflict")
            .map(|v| (v["file"].as_str().unwrap_or_default().to_owned(), v["host"].as_str().unwrap_or_default().to_owned()))
            .collect::<Vec<_>>()
    };
    assert_eq!(conflicts(&b), [("known_rdp_certs".to_owned(), "rdp.example.test:3389".to_owned())]);
    assert!(conflicts(&a).is_empty(), "A has not pulled yet");
    a.now().await.expect("a pull");
    assert_eq!(conflicts(&a).len(), 1);
    // The audit names only the file and host: no fingerprint, no hashed line.
    let raw = std::fs::read_to_string(b.f.state.data_dir.join(AppState::AUDIT_FILE)).expect("log");
    let row = raw.lines().find(|l| l.contains("trust_conflict")).expect("row");
    assert!(!row.contains("|2|") && !row.contains("SHA256"), "{row}");

    // 6b: listed in the status DTO, and every connection to the host fails closed.
    let trust = |file: &'static str, name: &str| StatusConflict::Trust { kind: "trust", id: file, name: name.to_owned() };
    assert_eq!(b.status().conflicts, [trust("known_rdp_certs", "rdp.example.test:3389")]);
    let json = serde_json::to_value(&b.status().conflicts).expect("json");
    assert_eq!(json, json!([{ "kind": "trust", "id": "known_rdp_certs", "name": "rdp.example.test:3389" }]));
    for presented in [[1; 32], [2; 32], [3; 32]] {
        assert_eq!(merged.check("rdp.example.test", 3389, &presented), mooring_core::known_certs::CertTrust::Conflict);
    }
    // SSH known_hosts: two ed25519 keys for one host conflict; a second key *type* does not.
    let kh = b.f.state.known_hosts_path();
    let ed = |seed: u8| {
        use russh::keys::ssh_key::private::Ed25519Keypair;
        russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32])).public_key().clone()
    };
    mooring_proto_ssh::KnownHosts::add_and_save(&kh, "ssh.example.test", 22, &ed(1)).expect("key 1");
    assert_eq!(b.status().conflicts.len(), 1, "one key: no conflict");
    mooring_proto_ssh::KnownHosts::add_and_save(&kh, "ssh.example.test", 22, &ed(2)).expect("key 2");
    assert_eq!(
        b.status().conflicts,
        [trust("known_hosts", "ssh.example.test:22"), trust("known_rdp_certs", "rdp.example.test:3389")],
        "sorted by file"
    );
    assert!(matches!(
        mooring_proto_ssh::KnownHosts::load(&kh).expect("kh").check("ssh.example.test", 22, &ed(1)),
        mooring_proto_ssh::TrustDecision::Conflict { .. }
    ));
    // The user removes the host's pins in the known-certificates manager: the conflict is gone
    // and the host is back to "unknown" (a fresh TOFU prompt), never silently trusted.
    let removed = crate::commands::known_certs::remove(&b.f.state, CertProtocol::Rdp, "rdp.example.test", 3389).expect("remove");
    assert_eq!(removed.removed, 2);
    assert_eq!(b.status().conflicts, [trust("known_hosts", "ssh.example.test:22")]);
    let after = KnownCerts::load(&file(&b)).expect("load");
    assert_eq!(after.check("rdp.example.test", 3389, &[1; 32]), mooring_core::known_certs::CertTrust::Unknown);
    std::fs::write(&kh, b"").expect("truncate");
    mooring_proto_ssh::KnownHosts::add_and_save(&kh, "ssh.example.test", 22, &ed(1)).expect("key 1");
    assert!(b.status().conflicts.is_empty());
    s3.recorder().assert_no_violations();
}

/// Review 6b L-35, end to end on the sync endpoint itself: a second distinct pin for the S3
/// host refuses the next run with `http.trust_conflict` (no prompt, nothing pulled); removing
/// the host's pins lets the gate ask again and the run goes through.
#[tokio::test]
async fn a_conflicting_sync_endpoint_pin_refuses_the_run_until_removed() {
    let s3 = server().await;
    let a = dev("device-a");
    a.configure(&s3).await.expect("configure");
    a.now().await.expect("push");
    let st = &a.f.state;
    let pins = || crate::commands::known_certs::list(st, CertProtocol::Sync).expect("list");
    assert_eq!(pins().len(), 1, "the endpoint certificate is pinned");
    let (host, port) = (s3.addr().ip().to_string(), s3.addr().port());
    let file = st.data_dir.join(CertProtocol::Sync.file_name());
    KnownCerts::add_and_save(&file, &host, port, &[9; 32], time::OffsetDateTime::now_utc()).expect("stray pin");
    let before = a.p.asked().len();
    let e = a.now().await.expect_err("conflict");
    assert_eq!(e.code, "http.trust_conflict");
    assert!(!e.message.contains("SHA256") && !e.message.contains(&host), "{}", e.message);
    assert_eq!(a.p.asked().len(), before, "never prompted over a conflict");
    assert_eq!(a.status().last_error.expect("err").code, "http.trust_conflict");
    let removed = crate::commands::known_certs::remove(st, CertProtocol::Sync, &host, u32::from(port)).expect("remove");
    assert_eq!(removed.removed, 2);
    a.now().await.expect("asked again and pinned");
    assert_eq!(a.p.asked().len(), before + 1);
    assert_eq!(pins().len(), 1);
    s3.recorder().assert_no_violations();
}
