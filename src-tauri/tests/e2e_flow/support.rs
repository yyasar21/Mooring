//! Helpers shared by the E2E flow and the hostile-input tests.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use mooring_core::session::Size;
use secrecy::SecretString;
use tokio::sync::mpsc;

use mooring_core::known_certs::CertProtocol;

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::kube::{self, ExecRequest};
use crate::commands::kube_logs::{self, LogsRequest};
use crate::commands::net::{self, NetRuntime, TargetArg};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::sync::{self, ConfigureInput};
use crate::commands::sync_config::BackendInput;
use crate::commands::sync_join::{self, JoinInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vsphere_confirm::{FixedConfirm, Prompt};
use crate::commands::{
    audit, conn_options, credential_copy, detach, known_certs, secret_sources, secret_sources_oidc,
    session_graphics, syslog, vault, vsphere, vsphere_vm, web,
};
use crate::error::IpcResult;
use crate::sessions::EventSink;
use crate::state::AppState;
use crate::sync_runner::SyncHub;
use mooring_app_lib::vsphere_sync::VsCtx;

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
/// The secret-source, vault-sync and vSphere commands (A3) are appended by
/// [`vault_gated_codes_a3`]; `secret_source_revoke` and `secret_source_oidc_status` are not
/// gated (they only drop or report in-memory state) and are left out on purpose.
pub async fn vault_gated_codes(
    st: &AppState,
    folder: &str,
    cred: &str,
    conn: &str,
) -> Vec<(&'static str, &'static str)> {
    let fields = || ConnectionFields::basic(folder, "n", "ssh", "h");
    let new_cred = NewCredential::password_for_tests("c");
    let set = WireSecrets::of(&[("password", "test-only secret")]);
    let no_fields = serde_json::json!({"username": "y"});
    let (s, _rx) = sink();
    let size = Size { width: 80, height: 24 };
    let mut out = vec![
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
        ("credential_update_fields", code(credentials::update_fields(st, cred, "x", &no_fields))),
        ("credential_replace_secrets", code(credentials::replace_secrets(st, cred, &set, &[]))),
        ("credential_delete", code(credentials::delete(st, cred))),
        ("credential_copy_secret", code(credential_copy::copy_secret(st, cred, "password"))),
        ("credential_copy_otp", code(credential_copy::copy_otp(st, cred))),
        (
            "connection_set_role_credential",
            code(tree::set_role_credential(st, conn, "become", None)),
        ),
        ("session_open", code(sess::open(st, conn, size, s).await)),
        ("audit_tail", code(audit::tail(st, 10, None))),
        ("audit_verify", code(audit::verify(st))),
        ("connection_options_get", code(conn_options::get(st, conn))),
        ("connection_options_set", code(conn_options::set(st, conn, serde_json::json!({})))),
        ("known_certs_list", code(known_certs::list(st, CertProtocol::Rdp))),
        (
            "known_certs_remove",
            code(known_certs::remove(st, CertProtocol::Rdp, "h.example.test", 3389)),
        ),
        ("syslog_get", code(syslog::get(st))),
        ("syslog_test", code(syslog::test_target(st))),
        // L-26: the graphical session commands check the vault before the session lookup.
        ("session_screenshot", code(session_graphics::screenshot(st, conn))),
        ("session_set_view_only", code(session_graphics::set_view_only(st, conn, true))),
        ("window_detach", code(detach::plan_detach(st, conn))),
        ("web_clear_data", code(web::check_clear(st, conn))),
    ];
    out.extend(vault_gated_codes_a3(st, folder, cred, conn).await);
    out
}

/// Review 6 L-38: the A3 commands that are gated *indirectly*. `kube_open` goes through
/// `state.ready()` in `connect_plan::kube`, `kube_contexts` through `with_ready`, and
/// `vsphere_console` through `vsphere_vm::vm_target` and `web_open` through `web::plan`
/// (their Tauri wrappers need an `AppHandle`, so the gate function is called directly here,
/// 6b L-38). The six session-bound kube commands are in [`kube_session_bound_codes`].
fn vault_gated_codes_indirect(
    st: &AppState,
    cred: &str,
    conn: &str,
) -> Vec<(&'static str, &'static str)> {
    let (tx, _rx) = mpsc::unbounded_channel::<serde_json::Value>();
    let cluster_sink = Arc::new(move |e: crate::commands::kube_wire::ClusterEvent| {
        tx.send(serde_json::to_value(&e).expect("json")).is_ok()
    });
    vec![
        ("kube_open", code(kube::open(st, conn, cluster_sink))),
        ("kube_contexts", code(kube::contexts(st, cred))),
        ("vsphere_console", code(vsphere_vm::vm_target(&VsCtx::of(st), conn))),
        (
            "web_open",
            code(mooring_app_lib::web::plan(
                st,
                conn,
                mooring_app_lib::web::StorageOs::current(),
                None,
            )),
        ),
    ]
}

/// Review 6 L-38: the session-bound kube commands are gated because `kube_sessions::close_all`
/// ends every cluster on lock, so a cluster session id used after the lock must fail with
/// `session.not_found` for each of them. Returns (command, code) with `session_id`.
pub async fn kube_session_bound_codes(
    st: &AppState,
    session_id: &str,
) -> Vec<(&'static str, &'static str)> {
    let (s, _rx) = sink();
    let exec = ExecRequest {
        namespace: "default".into(),
        pod: "db-0".into(),
        container: None,
        command: None,
        size: Size { width: 80, height: 24 },
    };
    let logs = LogsRequest {
        namespace: "default".into(),
        pod: "db-0".into(),
        container: None,
        follow: false,
        tail_lines: Some(10),
        since_seconds: None,
        timestamps: false,
    };
    let chunks: kube_logs::ChunkSink = Arc::new(|_| true);
    vec![
        ("kube_access", code(kube::access(st, session_id, "default").await)),
        ("kube_namespaces", code(kube::namespaces(st, session_id).await)),
        ("kube_pods", code(kube::pods(st, session_id, "default", None).await)),
        ("kube_pod", code(kube::pod(st, session_id, "default", "db-0").await)),
        ("kube_exec_open", code(kube::exec_open(st, session_id, exec, s).await)),
        ("kube_logs_open", code(kube_logs::open(st, session_id, logs, chunks).await)),
        ("kube_logs_close", code(kube_logs::close(st, session_id, "stream"))),
    ]
}

/// The A3 commands (ADR-0016 secret sources, ADR-0017 vault sync, ADR-0015 vSphere) with
/// well-formed arguments: every one must refuse with `vault.locked` before any I/O.
async fn vault_gated_codes_a3(
    st: &AppState,
    folder: &str,
    cred: &str,
    conn: &str,
) -> Vec<(&'static str, &'static str)> {
    let source_id = mooring_core::SecretSourceId::new().to_string();
    let source = serde_json::json!({
        "name": "lab vault",
        "address": "https://vault.example.test:8200",
        "authMethod": "token",
        "credentialId": cred,
    });
    let hub = SyncHub::new("e2e");
    let backend = || BackendInput {
        kind: "s3".into(),
        endpoint: "https://s3.example.test".into(),
        region: "us-east-1".into(),
        bucket: "team-vault".into(),
        prefix: "mooring".into(),
        path_style: None,
    };
    let configure = ConfigureInput {
        backend: backend(),
        credential_id: cred.into(),
        interval_minutes: Some(30),
    };
    let join = JoinInput {
        backend: backend(),
        credential_id: cred.into(),
        vault_id: "6f1e0a4c-2b3d-4e5f-8a9b-0c1d2e3f4a5b".into(),
        password: "not the master pw".into(),
        interval_minutes: None,
    };
    let yes = FixedConfirm::new(true);
    let p = || Prompt::new(&yes);
    vec![
        ("secret_source_list", code(secret_sources::list(st))),
        ("secret_source_get", code(secret_sources::get(st, &source_id))),
        ("secret_source_create", code(secret_sources::create(st, &source))),
        ("secret_source_update", code(secret_sources::update(st, &source_id, &source).await)),
        ("secret_source_delete", code(secret_sources::delete(st, &source_id).await)),
        ("secret_source_test", code(secret_sources::test(st, &source_id).await)),
        ("credential_external_test", code(secret_sources::external_test(st, cred).await)),
        ("secret_source_oidc_begin", code(secret_sources_oidc::begin(st, &source_id).await)),
        ("sync_configure", code(sync::configure(st, &hub, None, None, configure).await)),
        ("sync_status", code(sync::status(st, &hub))),
        ("sync_now", code(sync::run_once(st, &hub, None, None).await)),
        ("sync_resolve_fork", code(sync::resolve_fork(st, &hub, None, None, "local").await)),
        ("sync_disable", code(sync::disable(st, &hub, None, None, false).await)),
        ("vault_join", code(sync_join::join(st, &hub, None, None, join).await)),
        ("vsphere_test", code(vsphere::test(st, p(), conn).await)),
        ("vsphere_sync_enable", code(vsphere::sync_enable(st, p(), conn, folder).await)),
        ("vsphere_sync_disable", code(vsphere::sync_disable(st, conn, true))),
        ("vsphere_refresh", code(vsphere::refresh(st, p(), conn).await)),
        ("vsphere_status", code(vsphere::status(st, conn))),
        ("vsphere_vm_power", code(vsphere_vm::power_state(st, conn).await)),
        ("vsphere_vm_action", code(vsphere_vm::action(st, p(), conn, "start").await)),
        ("vsphere_vm_identity", code(vsphere_vm::identity(st, p(), conn).await)),
    ]
    .into_iter()
    .chain(vault_gated_codes_indirect(st, cred, conn))
    .chain(vault_gated_codes_a4(st, conn).await)
    .collect()
}

/// ADR-0020 §6 (A4 N1): the network tools refuse with `vault.locked` before resolving the
/// target, touching the rate limiter or spawning anything. A runtime without any tool path
/// proves no binary is needed to see the gate.
async fn vault_gated_codes_a4(st: &AppState, conn: &str) -> Vec<(&'static str, &'static str)> {
    let rt = NetRuntime::with_paths(
        mooring_net::ToolPaths::custom(mooring_net::Os::Linux, vec![], vec![], vec![], vec![]),
        Duration::ZERO,
    );
    let by_id = TargetArg::Connection { connection_id: conn.into() };
    let by_host = TargetArg::Host { host: "h.example.test".into(), port: Some(22) };
    vec![
        ("net_tools", code(net::tools(st, &rt))),
        ("net_port_check", code(net::port_check(st, &rt, &by_host, None).await)),
        ("net_ping", code(net::ping(st, &rt, &by_id, None).await)),
        ("net_traceroute", code(net::traceroute(st, &rt, &by_host, None).await)),
        ("net_wg_show", code(net::wg_show(st, &rt).await)),
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
