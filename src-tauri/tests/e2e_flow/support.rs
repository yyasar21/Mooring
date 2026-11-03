//! Helpers shared by the E2E flow and the hostile-input tests.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use mooring_core::session::Size;
use secrecy::SecretString;
use tokio::sync::mpsc;

use crate::commands::credentials::{self, NewCredential};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::{audit, vault};
use crate::error::IpcResult;
use crate::sessions::EventSink;
use crate::state::AppState;

pub type Events = mpsc::UnboundedReceiver<serde_json::Value>;

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A sink that forwards every `WireEvent` as JSON, the shape the UI channel receives.
pub fn sink() -> (EventSink, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let sink: EventSink =
        Arc::new(move |e| tx.send(serde_json::to_value(&e).expect("json")).is_ok());
    (sink, rx)
}

pub async fn next(rx: &mut Events) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("event within 20 s")
        .expect("channel open")
}

/// Collect `bytes` events until `needle` shows up; returns the text seen.
pub async fn read_until(rx: &mut Events, needle: &str) -> String {
    let mut out = String::new();
    while !out.contains(needle) {
        let e = next(rx).await;
        assert_eq!(e["kind"], "bytes", "{e}");
        let data = base64::engine::general_purpose::STANDARD
            .decode(e["data"].as_str().expect("data"))
            .expect("base64");
        out.push_str(&String::from_utf8_lossy(&data));
    }
    out
}

pub async fn wait_until_empty(state: &AppState) {
    for _ in 0..100 {
        if sess::list(state).expect("list").is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("session registry not empty: {:?}", sess::list(state));
}

fn code<T>(r: IpcResult<T>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code,
    }
}

/// Call every vault-gated command with otherwise valid arguments; returns (command, code).
pub async fn vault_gated_codes(
    st: &AppState,
    folder: &str,
    cred: &str,
    conn: &str,
) -> Vec<(&'static str, &'static str)> {
    let fields = || ConnectionFields {
        folder_id: folder.to_owned(),
        name: "n".into(),
        protocol: "ssh".into(),
        host: "h".into(),
        port: None,
        credential_id: None,
        tags: vec![],
    };
    let secret = || SecretString::from("test-only secret".to_owned());
    let new_cred = NewCredential {
        name: "c".into(),
        kind: "password".into(),
        username: String::new(),
        secret: secret(),
        secret2: None,
    };
    let (s, _rx) = sink();
    let size = Size { width: 80, height: 24 };
    vec![
        ("tree_list", code(tree::list(st))),
        ("folder_create", code(tree::create_folder(st, folder, "x"))),
        ("folder_rename", code(tree::rename_folder(st, folder, "x"))),
        ("folder_move", code(tree::move_folder(st, folder, folder))),
        ("folder_set_default_credential", code(tree::set_default_credential(st, folder, None))),
        ("folder_delete", code(tree::delete_folder(st, folder))),
        ("connection_create", code(tree::create_connection(st, fields()))),
        ("connection_update", code(tree::update_connection(st, conn, fields()))),
        ("connection_move", code(tree::move_connection(st, conn, folder))),
        ("connection_delete", code(tree::delete_connection(st, conn))),
        ("connection_search", code(tree::search(st, "lab", 10))),
        ("credential_list", code(credentials::list(st))),
        ("credential_create", code(credentials::create(st, new_cred))),
        ("credential_update_meta", code(credentials::update_meta(st, cred, "x", "y"))),
        ("credential_replace_secret", code(credentials::replace_secret(st, cred, &secret(), None))),
        ("credential_delete", code(credentials::delete(st, cred))),
        ("credential_copy_password", code(credentials::copy_password(st, cred))),
        ("session_open", code(sess::open(st, conn, size, s).await)),
        ("audit_tail", code(audit::tail(st, 10, None))),
        ("audit_verify", code(audit::verify(st))),
    ]
}

/// `vault_change_password` is not gated on unlock: it re-proves the current password.
/// While locked, a wrong current password must fail `vault.unlock` and leave the vault locked.
pub fn change_password_while_locked(st: &AppState) -> &'static str {
    code(vault::change_password(
        st,
        SecretString::from("wrong current pw".to_owned()),
        SecretString::from("another long pw".to_owned()),
    ))
}

/// Drive a `WireInput` through the real serde path the Tauri wrapper uses.
pub fn wire_input(json: &serde_json::Value) -> Result<WireInput, serde_json::Error> {
    serde_json::from_value(json.clone())
}
