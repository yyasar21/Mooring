//! ADR-0009 through the command layer: `session_open` builds the secret from the typed kind
//! (prompt-at-connect form, become), refuses an incompatible inherited credential and an
//! unsupported kind before any network I/O, and audits `credential_prompted` without the
//! password.

use mooring_core::session::Size;
use secrecy::SecretString;
use serde_json::json;

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::state::{testing, AppState};
use crate::support::{next, read_until, sink, wait_until_empty};
use crate::test_ssh_server::{self as server, PASSWORD, USER};

const SIZE: Size = Size { width: 80, height: 24 };

fn cred(st: &AppState, kind: &str, fields: serde_json::Value, secrets: &[(&str, &str)]) -> String {
    let c = NewCredential {
        name: kind.into(),
        kind: kind.into(),
        fields,
        secrets: WireSecrets::of(secrets),
    };
    credentials::create(st, c).expect("credential").id
}

fn trust(st: &AppState, srv: &server::TestServer) {
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &srv.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");
}

fn ssh_conn(st: &AppState, folder: &str, port: u16, f: ConnectionFields) -> String {
    let base = ConnectionFields {
        port: Some(u32::from(port)),
        ..ConnectionFields::basic(folder, "c", "ssh", "127.0.0.1")
    };
    let fields =
        ConnectionFields { folder_id: base.folder_id, port: base.port, host: base.host, ..f };
    tree::create_connection(st, fields).expect("connection").id
}

fn root(st: &AppState) -> String {
    tree::list(st).expect("tree").folders[0].id.clone()
}

#[tokio::test]
async fn prompt_kind_asks_once_signs_in_and_audits_the_username_only() {
    let srv = server::start(41).await;
    let f = testing::unlocked();
    let st = &f.state;
    trust(st, &srv);
    let ask = cred(st, "prompt", json!({}), &[]);
    let root = root(st);
    let conn = ssh_conn(
        st,
        &root,
        srv.port,
        ConnectionFields {
            credential_id: Some(ask),
            username_override: Some(USER.into()),
            ..ConnectionFields::basic(&root, "c", "ssh", "h")
        },
    );
    let (sk, mut rx) = sink();
    let opened = sess::open(st, &conn, SIZE, sk).await.expect("open");
    let p = next(&mut rx).await;
    assert_eq!(
        (p["kind"].as_str(), p["purpose"].as_str()),
        (Some("prompt"), Some("credential")),
        "{p}"
    );
    assert_eq!(p["account"]["username"], USER, "override pre-fills the form: {p}");
    assert_eq!(p["account"]["needs_username"], false);
    let id = u32::try_from(p["id"].as_u64().expect("id")).expect("u32");
    let answer = WireInput::CredentialAnswer {
        id,
        username: USER.into(),
        domain: None,
        password: SecretString::from(PASSWORD.to_owned()),
    };
    sess::send(st, &opened.session_id, answer).await.expect("answer");
    assert_eq!(next(&mut rx).await["kind"], "connected");
    read_until(&mut rx, "welcome").await;
    sess::close(st, &opened.session_id).await.expect("close");
    wait_until_empty(st).await;
    let events = testing::audit_events(st);
    assert!(events.iter().any(|e| e == "credential_prompted"), "{events:?}");
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    assert!(log.contains(&format!("\"username\":\"{USER}\"")) && !log.contains(PASSWORD));
}

#[tokio::test]
async fn prompt_cancel_closes_the_session() {
    let srv = server::start(42).await;
    let f = testing::unlocked();
    let st = &f.state;
    trust(st, &srv);
    let ask = cred(st, "prompt", json!({"username": USER}), &[]);
    let root = root(st);
    let conn = ssh_conn(
        st,
        &root,
        srv.port,
        ConnectionFields {
            credential_id: Some(ask),
            ..ConnectionFields::basic(&root, "c", "ssh", "h")
        },
    );
    let (sk, mut rx) = sink();
    let opened = sess::open(st, &conn, SIZE, sk).await.expect("open");
    let p = next(&mut rx).await;
    let id = u32::try_from(p["id"].as_u64().expect("id")).expect("u32");
    let cancel = WireInput::CredentialAnswer {
        id,
        username: String::new(),
        domain: None,
        password: SecretString::from(String::new()),
    };
    sess::send(st, &opened.session_id, cancel).await.expect("cancel");
    let closed = next(&mut rx).await;
    assert_eq!(
        (closed["kind"].as_str(), closed["reason"].as_str()),
        (Some("closed"), Some("authentication cancelled"))
    );
    wait_until_empty(st).await;
}

#[tokio::test]
async fn become_types_the_escalation_command_after_login() {
    let srv = server::start(43).await;
    let f = testing::unlocked();
    let st = &f.state;
    trust(st, &srv);
    let login = cred(st, "user_password", json!({"username": USER}), &[("password", PASSWORD)]);
    let sudo = cred(st, "sudo_become", json!({"method": "sudo", "become_user": "root"}), &[]);
    let root = root(st);
    let conn = ssh_conn(
        st,
        &root,
        srv.port,
        ConnectionFields {
            credential_id: Some(login.clone()),
            become_credential_id: Some(sudo.clone()),
            ..ConnectionFields::basic(&root, "c", "ssh", "h")
        },
    );
    let (sk, mut rx) = sink();
    let opened = sess::open(st, &conn, SIZE, sk).await.expect("open");
    assert_eq!(next(&mut rx).await["kind"], "connected");
    // the echo shell sends back the line Mooring typed
    read_until(&mut rx, "sudo -p '[mooring]%% become password: ' -i -u root").await;
    sess::close(st, &opened.session_id).await.expect("close");
    wait_until_empty(st).await;
    let log = std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("log");
    for id in [&login, &sudo] {
        assert!(log.contains(id.as_str()), "credential_used for {id}");
    }
}

#[tokio::test]
async fn incompatible_inherited_and_unsupported_kinds_fail_before_connecting() {
    let f = testing::unlocked();
    let st = &f.state;
    let root = root(st);
    let lab = tree::create_folder(st, &root, "lab").expect("folder");
    let token = cred(st, "api_token", json!({}), &[("token", "test-only token")]);
    tree::set_default_credential(st, &lab.id, Some(&token)).expect("folder default");
    // port 9 (discard) is never contacted: the plan fails first
    let conn = ssh_conn(st, &lab.id, 9, ConnectionFields::basic(&lab.id, "c", "ssh", "h"));
    let (sk, _rx) = sink();
    let e = sess::open(st, &conn, SIZE, sk).await.expect_err("api token on ssh");
    assert_eq!(e.code, "credential.incompatible");
    assert_eq!(e.message, "API token is for Web, not SSH sign-in.");
    let listed = tree::list(st).expect("tree");
    let row = listed.connections.iter().find(|c| c.id == conn).expect("row");
    assert_eq!(
        row.effective_credential_id.as_deref(),
        Some(token.as_str()),
        "inherited, not skipped"
    );

    let ext = cred(
        st,
        "external_ref",
        json!({"provider": "vault", "reference": "kv/app", "target_kind": "user_password"}),
        &[],
    );
    let c2 = ssh_conn(
        st,
        &root,
        9,
        ConnectionFields {
            credential_id: Some(ext),
            ..ConnectionFields::basic(&root, "c2", "ssh", "h")
        },
    );
    let (sk, _rx) = sink();
    let e = sess::open(st, &c2, SIZE, sk).await.expect_err("external ref");
    assert_eq!(e.code, "credential.kind_unsupported");
}
