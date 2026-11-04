//! Certificate pins of RDP / VNC (ADR-0011 §Trust): list and remove. Removing a pin is the
//! only way past a `trust_mismatch` hard stop, so it is audited (`cert_removed`).

use mooring_audit::AuditEvent;
use mooring_core::known_certs::{host_key, CertProtocol, KnownCert, KnownCerts};
use serde::Serialize;
use tauri::State;

use crate::commands::sessions::known_certs_path;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// `{ removed }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Removed {
    /// Pins removed.
    pub removed: usize,
}

fn store_error(e: &mooring_core::known_certs::KnownCertsError) -> IpcError {
    tracing::warn!(error = %e, "certificate store error");
    IpcError::new("state.io", "the certificate store could not be read or written")
}

/// `known_certs_list({ protocol })`: `[{ hostHash, fingerprint, addedAt, host?, port? }]`.
/// The file keeps hosts hashed; `host` / `port` are filled in Rust (U2) for pins that match
/// one of the user's own connections of that protocol, so the UI needs no HMAC.
pub fn list(state: &AppState, protocol: CertProtocol) -> IpcResult<Vec<KnownCert>> {
    let want = match protocol {
        CertProtocol::Rdp => mooring_core::Protocol::Rdp,
        CertProtocol::Vnc => mooring_core::Protocol::Vnc,
    };
    let candidates = state.with_ready(|_, store| {
        let mut out = Vec::new();
        for folder in store.list_folders()? {
            for c in store.list_connections(folder.id)? {
                if c.protocol == want {
                    if let Some(port) = c.port.or_else(|| want.default_port()) {
                        out.push((c.host, port));
                    }
                }
            }
        }
        Ok(out)
    })?;
    let certs = KnownCerts::load(&known_certs_path(state, protocol)).map_err(|e| store_error(&e))?;
    Ok(certs.list_named(&candidates))
}

/// `known_certs_remove({ protocol, host, port })`.
pub fn remove(state: &AppState, protocol: CertProtocol, host: &str, port: u32) -> IpcResult<Removed> {
    state.with_ready(|_, _| Ok(()))?;
    let host = mooring_core::validate_host(host)?;
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| IpcError::invalid("port", "must be 1..=65535"))?;
    let removed = KnownCerts::remove_and_save(&known_certs_path(state, protocol), &host, port)
        .map_err(|e| store_error(&e))?;
    let name = match protocol {
        CertProtocol::Rdp => "rdp",
        CertProtocol::Vnc => "vnc",
    };
    state.audit(AuditEvent::CertRemoved {
        protocol: name.to_owned(),
        host: host_key(&host, port),
        removed: removed as u64,
    });
    Ok(Removed { removed })
}

/// `known_certs_list({ protocol })`.
#[tauri::command]
pub fn known_certs_list(
    state: State<'_, AppState>,
    protocol: CertProtocol,
) -> IpcResult<Vec<KnownCert>> {
    list(&state, protocol)
}

/// `known_certs_remove({ protocol, host, port })`.
#[tauri::command]
pub fn known_certs_remove(
    state: State<'_, AppState>,
    protocol: CertProtocol,
    host: String,
    port: u32,
) -> IpcResult<Removed> {
    remove(&state, protocol, &host, port)
}

#[cfg(test)]
#[path = "graphics_ipc_tests.rs"]
mod tests;
