//! Tauri shell for Mooring.
//!
//! Trust boundary (ADR-0003): everything that arrives through a `#[tauri::command]` comes from
//! the untrusted WebView. Commands validate their input, never return secret material and map
//! internal errors to short, typed messages.

#![forbid(unsafe_code)]

mod commands;
// Wired into keyring enable/unlock/disable commands in the next A1 step (needs capability review).
#[allow(dead_code)]
mod keyring_store;
mod state;

use tauri::Manager;

use crate::state::AppState;

/// Build and run the application.
///
/// # Panics
/// Panics only if the Tauri runtime itself cannot start (no display, broken WebView install).
pub fn run() {
    init_tracing();
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            create_private_dir(&data_dir)?;
            app.manage(AppState::new(data_dir)?);
            tracing::info!("mooring started");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Tauri application");
}

/// Create the app data dir owner-only on unix (review M2): it holds the vault header, the audit
/// log and `mooring.db` (whose own mode is set to 0600 by `mooring_store::Store::open`). An existing
/// directory is tightened too. Windows relies on the per-user AppData ACL.
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
