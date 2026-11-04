//! A1 item 6 stand-in for the Playwright/tauri-driver E2E (which needs a real WebView): the same
//! user flow driven end to end through the Tauri command plain functions, against the in-process
//! russh test server on loopback.
//!
//! create vault → add folder → add credential (folder default) → add SSH connection → search →
//! session_open → TOFU yes → `uname -a` (the test server echoes) → close → lock → every
//! vault-gated command fails with `vault.locked` → unlock → data and audit chain intact.
//!
//! The command layer comes from `mooring_app_lib` through its `test-util` feature (enabled for
//! this package's tests by the self dev-dependency in `src-tauri/Cargo.toml`). The modules are
//! re-exported at this crate's root so the helper files keep using `crate::commands::...`.

#![allow(clippy::doc_markdown)]

use mooring_app_lib::{commands, error, sessions, state, sync_runner, test_ssh_server};

#[path = "e2e_flow/credential_kinds.rs"]
mod credential_kinds;
#[path = "e2e_flow/graphical.rs"]
mod graphical;
#[path = "e2e_flow/hostile.rs"]
mod hostile;
#[path = "e2e_flow/hostile_edges.rs"]
mod hostile_edges;
#[path = "e2e_flow/kube.rs"]
mod kube;
#[path = "e2e_flow/secrets.rs"]
mod secrets;
#[path = "e2e_flow/support.rs"]
mod support;
// ADR-0017 S2: vault sync between two devices.
#[path = "e2e_flow/sync.rs"]
mod sync;
#[path = "e2e_flow/vsphere.rs"]
mod vsphere;

use std::time::Duration;

use mooring_core::session::Size;
use secrecy::SecretString;

use crate::commands::credentials::{self, NewCredential};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vault::VaultStatus;
use crate::commands::{audit, vault};
use crate::state::testing::{self, MASTER};
use crate::support::{b64, next, read_until, sink, wait_until_empty};
use crate::test_ssh_server::{self as server, PASSWORD, USER};

const SIZE: Size = Size { width: 120, height: 40 };

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// Folder "Lab" with a default password credential and one SSH connection that inherits it.
fn build_tree(state: &state::AppState, port: u16) -> (String, String, String) {
    let root = tree::list(state).expect("tree").folders[0].id.clone();
    let lab = tree::create_folder(state, &root, "Lab").expect("folder");
    let cred =
        credentials::create(state, NewCredential::user_password("lab login", USER, PASSWORD))
            .expect("credential");
    tree::set_default_credential(state, &lab.id, Some(&cred.id)).expect("default cred");
    let conn = tree::create_connection(
        state,
        ConnectionFields {
            port: Some(u32::from(port)),
            tags: vec!["lab".into(), "linux".into()],
            ..ConnectionFields::basic(&lab.id, "web01 (loopback stand-in)", "ssh", "127.0.0.1")
        },
    )
    .expect("connection");
    assert_eq!(conn.credential_id, None, "no own credential");
    assert_eq!(conn.effective_credential_id.as_deref(), Some(cred.id.as_str()), "inherited");
    (lab.id, cred.id, conn.id)
}

#[tokio::test]
async fn create_vault_add_connection_run_uname_close_and_lock() {
    let srv = server::start(31).await;
    let f = testing::empty();
    let st = &f.state;

    // 1. Create vault.
    assert_eq!(vault::status(st).expect("status"), VaultStatus::Missing);
    assert_eq!(vault::create(st, pw(MASTER)).expect("create"), VaultStatus::Unlocked);

    // 2-3. Folder, credential, connection.
    let (lab, cred, conn) = build_tree(st, srv.port);
    let hits = tree::search(st, "web01", 10).expect("search");
    assert_eq!(hits.len(), 1);
    assert_eq!((hits[0].id.as_str(), hits[0].folder_id.as_str()), (conn.as_str(), lab.as_str()));
    let creds = serde_json::to_string(&credentials::list(st).expect("creds")).expect("json");
    assert!(!creds.contains(PASSWORD), "credential_list never carries the secret");

    // 4. Open session: unknown host → TOFU prompt → yes → connected.
    let (sink, mut rx) = sink();
    let opened = sess::open(st, &conn, SIZE, sink).await.expect("open");
    let prompt = next(&mut rx).await;
    assert_eq!(prompt["kind"], "prompt", "{prompt}");
    assert_eq!(prompt["purpose"], "host_key_trust", "{prompt}");
    let id = u32::try_from(prompt["id"].as_u64().expect("id")).expect("u32");
    let yes = WireInput::Answer { id, text: pw("yes") };
    sess::send(st, &opened.session_id, yes).await.expect("answer");
    let connected = next(&mut rx).await;
    assert_eq!(connected["kind"], "connected", "{connected}");
    read_until(&mut rx, "welcome").await;
    assert_eq!(sess::list(st).expect("list")[0].state, "connected");

    // 5. `uname -a`: the test shell echoes the line back.
    let cmd = WireInput::Bytes { data: b64(b"uname -a\n") };
    sess::send(st, &opened.session_id, cmd).await.expect("send");
    let out = read_until(&mut rx, "uname -a").await;
    assert!(out.contains("uname -a\n"), "{out:?}");

    // 6. Close.
    sess::close(st, &opened.session_id).await.expect("close");
    loop {
        if next(&mut rx).await["kind"] == "closed" {
            break;
        }
    }
    wait_until_empty(st).await;
    let e = sess::send(st, &opened.session_id, WireInput::Bytes { data: b64(b"x") }).await;
    assert_eq!(e.expect_err("closed").code, "session.not_found");

    // 7. Lock: every vault-gated command fails with vault.locked.
    assert_eq!(vault::lock(st, Some("user")).expect("lock"), VaultStatus::Locked);
    assert_eq!(vault::status(st).expect("status"), VaultStatus::Locked);
    let locked = support::vault_gated_codes(st, &lab, &cred, &conn).await;
    for (name, code) in &locked {
        assert_eq!(*code, "vault.locked", "{name} after lock");
    }
    assert_eq!(locked.len(), 22, "every vault-gated command is covered");
    assert_eq!(support::change_password_while_locked(st), "vault.unlock");
    assert_eq!(vault::status(st).expect("status"), VaultStatus::Locked, "still locked");
    assert_eq!(sess::list(st).expect("session_list is not gated"), vec![]);

    // 8. Wrong password stays locked; right password brings everything back.
    assert_eq!(vault::unlock(st, pw("not the master pw")).expect_err("wrong").code, "vault.unlock");
    assert_eq!(vault::status(st).expect("status"), VaultStatus::Locked);
    vault::unlock(st, pw(MASTER)).expect("unlock");
    let t = tree::list(st).expect("tree");
    assert!(t.connections.iter().any(|c| c.id == conn));

    // Audit: chain intact, the flow is recorded, no secret in the log.
    let v = audit::verify(st).expect("verify");
    assert!(v.ok && v.broken_at.is_none(), "{v:?}");
    let events = testing::audit_events(st);
    for want in [
        "vault_created",
        "credential_used",
        "trust_decision",
        "session_opened",
        "session_closed",
        "vault_locked",
        "vault_unlocked",
    ] {
        assert!(events.iter().any(|e| e == want), "{want} missing in {events:?}");
    }
    let raw = std::fs::read_to_string(f.dir.path().join(state::AppState::AUDIT_FILE)).expect("log");
    assert!(!raw.contains(PASSWORD) && !raw.contains(MASTER), "no secret in the audit log");
    let newest = audit::tail(st, 1, None).expect("tail");
    let newest = serde_json::to_value(&newest[0]).expect("json");
    assert_eq!(newest["event"], "vault_unlocked", "{newest}");
}

#[tokio::test]
async fn open_session_survives_vault_lock() {
    // ADR-0006: locking wipes the key; live sessions keep running and can be closed.
    let srv = server::start(32).await;
    let f = testing::unlocked();
    let st = &f.state;
    let (_, _, conn) = build_tree(st, srv.port);
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &srv.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");
    let (sink, mut rx) = sink();
    let opened = sess::open(st, &conn, SIZE, sink).await.expect("open");
    assert_eq!(next(&mut rx).await["kind"], "connected", "known host: no prompt");
    read_until(&mut rx, "welcome").await;

    vault::lock(st, Some("idle")).expect("lock");
    let line = WireInput::Bytes { data: b64(b"still here\n") };
    sess::send(st, &opened.session_id, line).await.expect("send while locked");
    read_until(&mut rx, "still here").await;
    let (sink2, _rx2) = support::sink();
    let e = sess::open(st, &conn, SIZE, sink2).await.expect_err("new session needs unlock");
    assert_eq!(e.code, "vault.locked");
    sess::close(st, &opened.session_id).await.expect("close while locked");
    tokio::time::timeout(Duration::from_secs(20), async {
        while next(&mut rx).await["kind"] != "closed" {}
    })
    .await
    .expect("closed");
    wait_until_empty(st).await;
}
