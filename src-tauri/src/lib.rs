//! Tauri shell for Nexus Remote.
//!
//! Trust boundary (ADR-0003): everything that arrives through a `#[tauri::command]` comes from
//! the untrusted WebView. Commands validate their input, never return secret material and map
//! internal errors to short, typed messages.

#![forbid(unsafe_code)]

mod commands;
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
            std::fs::create_dir_all(&data_dir)?;
            app.manage(AppState::new(data_dir)?);
            tracing::info!("nexus started");
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

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("NEXUS_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Secrets never reach tracing by contract; nexus_audit::redact is applied again in the
    // file sink added in A1 (defence in depth).
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
