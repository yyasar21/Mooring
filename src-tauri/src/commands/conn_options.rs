//! Per-connection protocol options over IPC (ADR-0011 migration 0005): the plain
//! per-protocol object (`RdpConnOptions`, `VncConnOptions`, `WebConnOptions`, `{}` for the
//! rest), camelCase, `deny_unknown_fields`, validated on write and re-validated on read.

use mooring_core::options::MAX_OPTIONS_JSON;
use mooring_core::ProtocolOptions;
use tauri::State;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// `connection_options_get({ connectionId })`.
pub fn get(state: &AppState, connection_id: &str) -> IpcResult<ProtocolOptions> {
    let id = dto::connection_id("connectionId", connection_id)?;
    state.with_ready(|_, store| Ok(store.connection_options(id)?))
}

/// `connection_options_set({ connectionId, options })`: replaces every option; returns what
/// is stored (defaults filled in).
pub fn set(
    state: &AppState,
    connection_id: &str,
    options: serde_json::Value,
) -> IpcResult<ProtocolOptions> {
    let id = dto::connection_id("connectionId", connection_id)?;
    let len = serde_json::to_string(&options).map_or(usize::MAX, |s| s.len());
    if len > MAX_OPTIONS_JSON {
        return Err(IpcError::invalid("options", "larger than 128 KiB"));
    }
    state.with_ready(|_, store| {
        let protocol = store.get_connection(id)?.protocol;
        let parsed = ProtocolOptions::from_value(protocol, options)?;
        Ok(store.set_connection_options(id, &parsed)?)
    })
}

/// `connection_options_get({ connectionId })`.
#[tauri::command]
pub fn connection_options_get(
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<ProtocolOptions> {
    get(&state, &connection_id)
}

/// `connection_options_set({ connectionId, options })`.
#[tauri::command]
pub fn connection_options_set(
    state: State<'_, AppState>,
    connection_id: String,
    options: serde_json::Value,
) -> IpcResult<ProtocolOptions> {
    set(&state, &connection_id, options)
}
