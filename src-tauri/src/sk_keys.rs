//! ADR-0024 in the Tauri layer: the FIDO2 `ssh_sk_key` options of an SSH connect, the
//! pre-flight that the ssh-agent holds the key (`ssh.sk_key_not_in_agent` before any network
//! I/O), the `ssh-sk-helper` setting and the unlock-time conversion of `sk-*` `ssh_key` rows.

use std::path::PathBuf;

use mooring_audit::AuditEvent;
use mooring_core::credential::SkBackend;
use mooring_core::session::{ConnectParams, ConnectSecret};
use mooring_proto_ssh::SshOptions;

use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// App setting of the `ssh-sk-helper` backend (ADR-0024 §3, decision 29: off by default).
/// Value `true` turns it on; anything else (or no row) is off.
pub const KEY_SK_HELPER: &str = "app.ssh_sk_helper";

/// The helper binary when the setting is on and the OS has one at its fixed path.
pub fn sk_helper(state: &AppState) -> Option<PathBuf> {
    if helper_setting_on(state) {
        mooring_proto_ssh::sk_helper::system_helper()
    } else {
        None
    }
}

/// The FIDO2 parts of `options`: the agent socket override (tests) and the helper.
pub fn apply(options: &mut SshOptions, agent_path: Option<PathBuf>, helper: Option<PathBuf>) {
    options.agent_path = agent_path;
    options.sk_helper = helper;
}

/// Refuse before connecting when a security key of the target or a hop cannot sign: the
/// agent does not hold it (`ssh.sk_key_not_in_agent`), the helper backend is off
/// (`ssh.sk_helper_disabled`) or has no binary (`ssh.sk_helper_missing`).
pub async fn preflight(
    params: &[&ConnectParams],
    agent_path: Option<&std::path::Path>,
    helper_setting_on: bool,
    helper: Option<&std::path::Path>,
) -> IpcResult<()> {
    for p in params.iter().copied() {
        let ConnectSecret::SecurityKey(login) = &p.secret else { continue };
        match login.backend {
            SkBackend::Agent => match mooring_proto_ssh::agent_holds(&login.public_key, agent_path).await {
                Some(true) => {}
                Some(false) => {
                    return Err(IpcError::new(
                        "ssh.sk_key_not_in_agent",
                        format!(
                            "security key {} is not in ssh-agent; run `ssh-add -K` for a resident key or `ssh-add ~/.ssh/id_ed25519_sk`",
                            login.fingerprint
                        ),
                    ));
                }
                None => {
                    return Err(IpcError::new(
                        "ssh.sk_key_not_in_agent",
                        "no ssh-agent is reachable; start ssh-agent and add the security key with ssh-add",
                    ));
                }
            },
            SkBackend::Helper if !helper_setting_on => {
                return Err(IpcError::new(
                    "ssh.sk_helper_disabled",
                    "the ssh-sk-helper backend is turned off; use the ssh-agent or turn on sshSkHelper",
                ));
            }
            SkBackend::Helper if helper.is_none() => {
                return Err(IpcError::new(
                    "ssh.sk_helper_missing",
                    "ssh-sk-helper was not found at its fixed path on this system",
                ));
            }
            SkBackend::Helper => {}
        }
    }
    Ok(())
}

/// Whether the helper setting row says `true`.
pub fn helper_setting_on(state: &AppState) -> bool {
    state
        .store
        .lock()
        .ok()
        .and_then(|slot| slot.store.as_ref().and_then(|s| s.app_setting(KEY_SK_HELPER).ok().flatten()))
        .is_some_and(|v| v == "true")
}

/// After unlock: convert `ssh_key` rows that hold an `sk-*` handle (migration 0010's flag),
/// one `credential.sk_converted` row each. A failure is logged and retried next unlock.
pub fn convert_on_unlock(state: &AppState) {
    match state.with_ready(|vault, store| Ok(store.convert_sk_keys(vault))) {
        Ok(Ok(ids)) => {
            for id in ids {
                state.audit(AuditEvent::CredentialSkConverted { id: id.to_string() });
            }
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "sk-* key conversion failed; retried next unlock"),
        Err(e) => tracing::warn!(code = e.code, "sk-* key conversion skipped"),
    }
}

#[cfg(test)]
#[path = "sk_keys_tests.rs"]
mod tests;
