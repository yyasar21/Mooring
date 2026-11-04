//! IPC commands (ADR-0008). Every function here is an attack surface: validate, never leak.
//!
//! Each module keeps the logic in plain functions taking `&AppState` (unit-tested without a
//! `WebView`) and thin `#[tauri::command]` wrappers named exactly as the UI invokes them.
//! Arguments arrive camelCase (Tauri's default) and DTOs leave camelCase.

// `#[tauri::command]` deserialises owned arguments (`State`, `String`); borrowing is not an
// option for them, so this lint only fires on the thin wrappers.
#![allow(clippy::needless_pass_by_value)]

pub mod audit;
mod connect_plan;
pub mod credential_copy;
pub mod credentials;
pub mod sessions;
pub mod tree;
pub mod vault;
// ADR-0010 §Port forwarding / §SFTP
pub mod forward;
#[cfg(test)]
mod test_session;
