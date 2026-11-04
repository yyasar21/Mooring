//! ADR-0016 §4 (E2): the OIDC sign-in commands. The window itself is `crate::oidc_window`.
//!
//! ```text
//! secret_source_oidc_begin({ id })          -> { sessionId, windowLabel: "oidc-<id>" }
//! secret_source_oidc_status({ sessionId })  -> { state: pending|done|failed, sourceId, error }
//! ```

use mooring_core::secret_source::SecretSourceAuth;
use serde::Serialize;
use tauri::State;

use crate::commands::secret_sources::{load, source_id};
use crate::error::{IpcError, IpcResult};
use crate::oidc_window::{self, OidcStatus, OIDC_PREFIX};
use crate::state::AppState;

/// `secret_source_oidc_begin` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcBegun {
    /// Poll `secret_source_oidc_status` with it.
    pub session_id: String,
    /// `oidc-<sourceId>`.
    pub window_label: String,
}

/// `secret_source_oidc_begin({ id })`: vault must be unlocked; the source must be OIDC.
pub async fn begin(state: &AppState, id: &str) -> IpcResult<OidcBegun> {
    let source = load(state, source_id(id)?)?;
    if !matches!(source.auth, SecretSourceAuth::Oidc { .. }) {
        return Err(IpcError::invalid("id", "not an OIDC source"));
    }
    let window_label = format!("{OIDC_PREFIX}{}", source.id);
    let session_id = oidc_window::begin(&state.secrets, source).await?;
    Ok(OidcBegun { session_id, window_label })
}

/// `secret_source_oidc_status({ sessionId })` (passive).
pub fn status(state: &AppState, session_id: &str) -> IpcResult<OidcStatus> {
    if session_id.len() > 64 {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    oidc_window::status(&state.secrets, session_id)
}

/// `secret_source_oidc_begin({ id })`.
#[tauri::command]
pub async fn secret_source_oidc_begin(state: State<'_, AppState>, id: String) -> IpcResult<OidcBegun> {
    begin(&state, &id).await
}

/// `secret_source_oidc_status({ sessionId })`.
#[tauri::command]
pub fn secret_source_oidc_status(state: State<'_, AppState>, session_id: String) -> IpcResult<OidcStatus> {
    status(&state, &session_id)
}
