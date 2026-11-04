//! `guard::check` matrix, manifest coverage and the `ipc-manifest.json` golden file.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

const SID: &str = "7f9c2ba4-e88f-4f0a-9e5b-2f6f1d3c8a11";
const OTHER: &str = "0b1e4a77-2d0c-4c55-8d39-b4e0f6c7a222";

#[test]
fn caller_from_label() {
    assert_eq!(caller("main").expect("main"), Caller::Main);
    assert_eq!(caller(&format!("detached-{SID}")).expect("d"), Caller::Detached(SID.into()));
    for bad in ["web-x", "detached-", "Main", "main2", "", "mainx", "webdetached-x", "x"] {
        assert_eq!(caller(bad).expect_err(bad).code, "ipc.forbidden", "{bad}");
    }
}

#[test]
fn check_matrix() {
    let own = format!("detached-{SID}");
    // main: everything in the manifest, and unknown names fall through to the handler.
    for (cmd, _) in COMMANDS {
        assert_eq!(check(cmd, "main", None).expect(cmd), Caller::Main);
    }
    assert!(check("no_such_command", "main", None).is_ok());
    // detached: the six session commands on its own session only.
    let six: Vec<&str> =
        COMMANDS.iter().filter(|(_, s)| *s == Scope::Session).map(|(n, _)| *n).collect();
    assert_eq!(six, [
        "session_send",
        "session_close",
        "session_frame_ack",
        "session_attach",
        "session_screenshot",
        "window_attach"
    ]);
    for cmd in &six {
        assert!(check(cmd, &own, Some(SID)).is_ok(), "{cmd}");
        assert_eq!(check(cmd, &own, Some(OTHER)).expect_err(cmd).code, "ipc.forbidden");
        assert_eq!(check(cmd, &own, None).expect_err(cmd).code, "ipc.forbidden");
    }
    for cmd in ["vault_unlock", "vault_lock", "credential_copy_secret", "credential_list",
        "session_open", "session_list", "window_detach", "web_open", "tree_list", "no_such"]
    {
        assert_eq!(check(cmd, &own, Some(SID)).expect_err(cmd).code, "ipc.forbidden", "{cmd}");
    }
    // web-* and unknown labels: nothing, not even a session command with a matching id.
    for label in [format!("web-{SID}"), "evil".to_owned(), format!("detached{SID}")] {
        for (cmd, _) in COMMANDS {
            assert_eq!(check(cmd, &label, Some(SID)).expect_err(cmd).code, "ipc.forbidden");
        }
    }
}

#[test]
fn session_id_is_read_from_json_args_only() {
    let body = InvokeBody::Json(serde_json::json!({ "sessionId": SID, "seq": 3 }));
    assert_eq!(session_id_arg(&body), Some(SID));
    let body = InvokeBody::Json(serde_json::json!({ "sessionId": 7 }));
    assert_eq!(session_id_arg(&body), None);
    let body = InvokeBody::Json(serde_json::json!({ "session_id": SID }));
    assert_eq!(session_id_arg(&body), None, "Tauri reads camelCase keys only");
    assert_eq!(session_id_arg(&InvokeBody::Raw(SID.as_bytes().to_vec())), None);
}

/// Command names in `generate_handler![...]` of `lib.rs` (the registered commands).
fn registered() -> Vec<String> {
    let src = include_str!("../lib.rs");
    let start = src.find("generate_handler![").expect("generate_handler in lib.rs");
    let block = &src[start..];
    let block = &block[..block.find("])").expect("end of generate_handler")];
    block
        .lines()
        .map(|l| l.split("//").next().unwrap_or_default().trim())
        .filter_map(|l| l.strip_suffix(','))
        .filter_map(|l| l.rsplit("::").next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_registered_command_has_a_manifest_row() {
    let registered = registered();
    assert!(registered.len() > 60, "parser found {}", registered.len());
    let reg: BTreeSet<&str> = registered.iter().map(String::as_str).collect();
    let table: BTreeSet<&str> = COMMANDS.iter().map(|(n, _)| *n).collect();
    assert_eq!(reg.len(), registered.len(), "duplicate registration");
    assert_eq!(table.len(), COMMANDS.len(), "duplicate manifest row");
    assert_eq!(reg, table, "generate_handler! and guard/table.rs differ");
}

#[test]
fn golden_ipc_manifest_file_is_in_sync() {
    let rows: BTreeMap<String, serde_json::Value> = match manifest_json() {
        serde_json::Value::Object(m) => m.into_iter().collect(),
        other => panic!("not an object: {other}"),
    };
    crate::golden::check_json("ipc-manifest.json", &rows);
}
