//! Per-connection protocol options over IPC (ADR-0011 migration 0005): the plain
//! per-protocol object (`RdpConnOptions`, `VncConnOptions`, `WebConnOptions`, `{}` for the
//! rest), camelCase, `deny_unknown_fields`, validated on write and re-validated on read.

use mooring_audit::AuditEvent;
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
    let (protocol, before, after) = state.with_ready(|_, store| {
        let protocol = store.get_connection(id)?.protocol;
        let parsed = ProtocolOptions::from_value(protocol, options)?;
        let before = store.connection_options(id).ok();
        let after = store.set_connection_options(id, &parsed)?;
        // ADR-0014 K4: the options must fit the connection's Kubernetes credential.
        if let Err(e) = crate::commands::kube::save_check(store, id) {
            if let Some(b) = &before {
                store.set_connection_options(id, b)?;
            }
            return Err(e);
        }
        Ok((protocol, before, after))
    })?;
    if let Some(event) = changes(connection_id, protocol.name(), before.as_ref(), &after) {
        state.audit(event);
    }
    if protocol == mooring_core::Protocol::VsphereConsole {
        // ADR-0015: a new refresh interval takes effect now.
        crate::scheduler::ensure(&crate::vsphere_sync::VsCtx::of(state), id);
    }
    Ok(after)
}

/// L-22: `connection_options_changed` with the changed field names (never values), the
/// fingerprints of a new `caPem`, and whether the change weakens security. `None` when
/// nothing changed. An unreadable previous value counts every field as changed.
fn changes(
    connection: &str,
    protocol: &str,
    before: Option<&ProtocolOptions>,
    after: &ProtocolOptions,
) -> Option<AuditEvent> {
    let as_map = |o: &ProtocolOptions| match serde_json::to_value(o) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    let old = before.map(as_map).unwrap_or_default();
    let new = as_map(after);
    let mut changed: Vec<String> =
        new.iter().filter(|(k, v)| old.get(*k) != Some(*v)).map(|(k, _)| k.clone()).collect();
    changed.extend(old.keys().filter(|k| !new.contains_key(*k)).cloned());
    if changed.is_empty() {
        return None;
    }
    changed.sort();
    let is = |key: &str, want: &serde_json::Value| changed.iter().any(|k| k == key) && new.get(key) == Some(want);
    let ca = new.get("caPem").and_then(serde_json::Value::as_str).filter(|_| changed.iter().any(|k| k == "caPem"));
    let weakened = ca.is_some()
        || ["allowTlsWithoutNla", "allowHttp", "persistent", "allowNoAuth", "allowPowerActions", "allowVmrc"]
            .iter()
            .any(|k| is(k, &serde_json::Value::Bool(true)))
        || is("security", &serde_json::Value::from("allow_plaintext"));
    Some(AuditEvent::ConnectionOptionsChanged {
        connection: connection.to_owned(),
        protocol: protocol.to_owned(),
        changed,
        ca_pem: ca.map(ca_fingerprints).unwrap_or_default(),
        weakened,
    })
}

/// `SHA256:<hex>` of each certificate block (validated as certificates-only on write).
fn ca_fingerprints(pem: &str) -> Vec<String> {
    const END: &str = "-----END CERTIFICATE-----";
    pem.split_inclusive(END)
        .filter(|b| b.contains("-----BEGIN CERTIFICATE-----"))
        .filter_map(|b| mooring_core::credential::fingerprint::x509_pem(b).ok())
        .collect()
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
