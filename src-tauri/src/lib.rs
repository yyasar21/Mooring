//! Tauri shell for Mooring.
//!
//! Trust boundary (ADR-0003): everything that arrives through a `#[tauri::command]` comes from
//! the untrusted `WebView`. Commands validate their input, never return secret material and map
//! internal errors to short, typed messages (`IpcError`).

#![forbid(unsafe_code)]

/// The command layer and its state are private to the app; the `test-util` feature makes them
/// public so integration tests (`tests/e2e_flow`) call the same plain functions as the UI.
macro_rules! test_util_pub {
    ($($m:ident),* $(,)?) => {$(
        #[cfg(feature = "test-util")]
        pub mod $m;
        #[cfg(not(feature = "test-util"))]
        mod $m;
    )*};
}

test_util_pub!(clipboard, commands, dto, error, sessions, state);
// Wired into keyring enable/unlock/disable commands once review M1 is resolved (ADR-0006).
#[allow(dead_code)]
mod keyring_store;
mod navigation;
/// In-process russh server for the session tests (loopback only).
#[cfg(any(test, feature = "test-util"))]
pub mod test_ssh_server;

use tauri::Manager;

use crate::commands::{audit, credential_copy, credentials, sessions as session_cmds, tree, vault};
// ADR-0010 §Port forwarding / §SFTP
use crate::commands::{forward, sftp, sftp_transfers};
use crate::state::{AppState, Settings};

/// Build and run the application.
///
/// # Panics
/// Panics only if the Tauri runtime itself cannot start (no display, broken `WebView` install).
pub fn run() {
    init_tracing();
    let app = tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            create_private_dir(&data_dir)?;
            app.manage(AppState::new(data_dir, Settings::production())?);
            // `"create": false` in tauri.conf.json: the main window is built here so it gets
            // the navigation and new-window guard (security review 2, M-4).
            navigation::create_main_window(app)?;
            tracing::info!("mooring started");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault::app_info,
            vault::vault_status,
            vault::vault_create,
            vault::vault_unlock,
            vault::vault_lock,
            vault::vault_change_password,
            tree::tree_list,
            tree::folder_create,
            tree::folder_rename,
            tree::folder_move,
            tree::folder_set_default_credential,
            tree::folder_delete,
            tree::connection_create,
            tree::connection_update,
            tree::connection_move,
            tree::connection_delete,
            tree::connection_search,
            tree::connection_set_role_credential,
            credentials::credential_kinds,
            credentials::credential_list,
            credentials::credential_create,
            credentials::credential_update_fields,
            credentials::credential_replace_secrets,
            credentials::credential_delete,
            credentials::credential_parse_account,
            credential_copy::credential_copy_secret,
            credential_copy::credential_copy_otp,
            session_cmds::session_open,
            session_cmds::session_send,
            session_cmds::session_close,
            session_cmds::session_list,
            session_cmds::window_detach,
            audit::audit_tail,
            audit::audit_verify,
            // ADR-0010 §Port forwarding / §SFTP
            forward::forward_open,
            forward::forward_close,
            forward::forward_list,
            sftp::sftp_list,
            sftp::sftp_stat,
            sftp::sftp_mkdir,
            sftp::sftp_rename,
            sftp::sftp_remove,
            sftp_transfers::sftp_download,
            sftp_transfers::sftp_upload,
            sftp_transfers::sftp_cancel,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the Tauri application");
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            // Explicit close (review condition 1): never rely on Drop of managed state.
            if let Some(state) = handle.try_state::<AppState>() {
                state.shutdown();
            }
        }
    });
}

/// Create the app data dir owner-only on unix (review M2): it holds the vault header, the audit
/// log, `known_hosts` and `mooring.db` (whose own mode is set to 0600 by
/// `mooring_store::Store::open`). An existing directory is tightened too. Windows relies on the
/// per-user `AppData` ACL.
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("MOORING_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Secrets never reach tracing by contract; mooring_audit::redact is applied again in the
    // file sink added in A1 (defence in depth).
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn data_dir_is_owner_only_and_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().expect("tmp");
        let dir = base.path().join("a/b");
        super::create_private_dir(&dir).expect("create");
        let mode = |p: &std::path::Path| std::fs::metadata(p).expect("m").permissions().mode();
        assert_eq!(mode(&dir) & 0o777, 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        super::create_private_dir(&dir).expect("again");
        assert_eq!(mode(&dir) & 0o777, 0o700);
    }
}
