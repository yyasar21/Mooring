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
pub mod kube_jwt;
pub mod kube_logs;
pub mod kube_wire;
// ADR-0016 E2: external secret sources.
pub mod secret_sources;
pub mod secret_sources_oidc;
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
// ADR-0015 §5 (A3 V2): vSphere sync, VM power, consoles.
pub mod vsphere;
pub mod vsphere_confirm;
pub mod vsphere_console;
pub mod vsphere_login;
pub mod vsphere_vm;
