//! IPC commands (ADR-0008). Every function here is an attack surface: validate, never leak.
//!
//! Each module keeps the logic in plain functions taking `&AppState` (unit-tested without a
//! `WebView`) and thin `#[tauri::command]` wrappers named exactly as the UI invokes them.
//! Arguments arrive camelCase (Tauri's default) and DTOs leave camelCase.

// `#[tauri::command]` deserialises owned arguments (`State`, `String`); borrowing is not an
// option for them, so this lint only fires on the thin wrappers.
#![allow(clippy::needless_pass_by_value)]

pub mod audit;
pub(crate) mod connect_plan;
pub mod conn_options;
pub mod known_certs;
pub mod session_graphics;
pub mod session_input;
pub mod credential_copy;
pub mod credentials;
// ADR-0013 §IPC: detach / attach, web windows.
pub mod detach;
pub mod web;
pub mod sessions;
pub mod tree;
pub mod vault;
// ADR-0010 §Port forwarding / §SFTP
pub mod forward;
pub mod sftp;
pub mod sftp_pick;
pub mod sftp_transfers;
// ADR-0014 K4: Kubernetes sessions.
pub mod kube;
pub(crate) mod kube_cluster;
pub mod kube_forward;
pub mod kube_logs;
pub mod kube_wire;
// ADR-0016 E2: external secret sources.
pub mod secret_sources;
pub mod secret_sources_oidc;
// ADR-0018 §3 (A4 U0): in-app updates.
pub mod update;
#[cfg(test)]
mod test_session;
// ADR-0010 (A1 exit): auto-lock policy and syslog mirror settings.
pub mod autolock;
pub mod syslog;
// ADR-0017 (A3 S2): vault sync.
pub mod sync;
pub mod sync_config;
pub mod sync_gate;
pub mod sync_join;
pub mod sync_local;
pub mod sync_trust;
// ADR-0015 §5 (A3 V2): vSphere sync, VM power, consoles.
pub mod vsphere;
pub mod vsphere_confirm;
pub mod vsphere_console;
pub mod vsphere_login;
pub mod vsphere_vm;
// ADR-0020 (A4 N1): network tools.
pub mod net;
// ADR-0019 (A4 I1): file importers.
pub mod import;
pub mod import_dto;
pub mod import_source;
// ADR-0019 §4 (A4 I2): LDAPS directory importer.
pub mod ldap_import;

/// Run `f` on Tokio's blocking pool and await it: a command whose work is CPU- or file-bound
/// (a 16 MiB import parse, 2 000 seals, a large kubeconfig) must never run on the thread that
/// serves IPC (review 3 L-10, review 7 N-60). The handle is whatever `f` needs to reach the
/// state (an `AppHandle`, an `Arc`). A panic in `f` becomes an `internal` error without detail.
pub async fn off_thread<H, T, F>(handle: H, f: F) -> crate::error::IpcResult<T>
where
    H: Send + 'static,
    T: Send + 'static,
    F: FnOnce(H) -> crate::error::IpcResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || f(handle)).await.unwrap_or_else(|_| {
        tracing::error!("blocking command task failed");
        Err(crate::error::IpcError::new("internal", "internal error"))
    })
}
