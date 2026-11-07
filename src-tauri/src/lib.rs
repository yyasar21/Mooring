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
// Review 4 B-4: local paths from the Rust-side file dialog, by pickId.
test_util_pub!(picks);
// ADR-0010: auto-lock wiring (clock, 5 s tick, focus, invoke hook).
test_util_pub!(autolock);
// ADR-0011 (A2 R2): generic session task, frame pump, reconnect, RDP/VNC factory hook.
test_util_pub!(frame_pump, graphical_task, reconnect, session_audit, session_factory, session_task);
// ADR-0013 (A2 R5): command ACL, web windows, detach routing, lock hiding.
test_util_pub!(guard, route, web, window_lock);
// ADR-0014 K4: Kubernetes cluster / exec sessions.
test_util_pub!(kube_sessions);
// ADR-0017 (A3 S2): vault-sync hub and interval runner.
test_util_pub!(sync_runner);
// ADR-0015 (A3 V2): vCenter sync hub and refresh scheduler.
test_util_pub!(scheduler, vsphere_sync);
// ADR-0016 E2: token cache / renewer runtime and the OIDC window.
test_util_pub!(oidc_window, secrets_runtime);
// Review 6 M-16: one native confirmation at a time, cool-down after a cancel.
test_util_pub!(confirm_gate);
// Review 7 N-52: per-process audit-row budget of the net_* commands.
test_util_pub!(audit_budget);
// ADR-0018 §3 (A4 U0): in-app updates, Rust-side plugin use only.
test_util_pub!(updater);
// ADR-0019 (A4 I1): import plans held between preview and apply.
test_util_pub!(import_plans);
// ADR-0021 (0.1.1): data / cache directories, portable marker, start-up refusals, Windows ACL.
test_util_pub!(dirs, portable_acl, startup);
// ADR-0025 (A5 R1): jump-host chains for SSH, RDP, VNC and Kubernetes sessions.
test_util_pub!(hop_chain);
// Wired into keyring enable/unlock/disable commands once review M1 is resolved (ADR-0006).
/// Checked-in JSON lists kept in sync with the Rust source (M-8, N-14).
#[cfg(test)]
mod golden;
#[allow(dead_code)]
mod keyring_store;
pub(crate) mod navigation;
/// Scripted RDP/VNC session and factory for the graphical tests.
#[cfg(test)]
mod test_graphical;
/// Vault mock fixtures for the ADR-0016 E2 tests.
#[cfg(test)]
mod test_secrets;
/// In-process russh server for the session tests (loopback only).
#[cfg(any(test, feature = "test-util"))]
pub mod test_ssh_server;

use tauri::Manager;

use crate::commands::{audit, credential_copy, credentials, sessions as session_cmds, tree, vault};
// ADR-0010 §Port forwarding / §SFTP
use crate::commands::{autolock as autolock_cmds, syslog as syslog_cmds};
use crate::commands::{forward, sftp, sftp_pick, sftp_transfers};
// ADR-0011 §IPC
use crate::commands::{conn_options, known_certs, session_graphics};
// ADR-0013 §IPC
use crate::commands::{detach, web as web_cmds};
// ADR-0014 K4
use crate::commands::{kube, kube_logs};
// ADR-0017 §5 (A3 S2)
use crate::commands::{sync as sync_cmds, sync_join};
// ADR-0015 §5 (A3 V2)
use crate::commands::{vsphere, vsphere_console};
// ADR-0016 E2
use crate::commands::{secret_sources, secret_sources_oidc};
// ADR-0018 §3 (A4 U0)
use crate::commands::update as update_cmds;
// ADR-0020 (A4 N1)
use crate::commands::net as net_cmds;
// ADR-0019 (A4 I1): importers.
use crate::commands::import;
use crate::state::{AppState, Settings};

/// Build and run the application.
///
/// # Panics
/// Panics only if the Tauri runtime itself cannot start (no display, broken `WebView` install).
// The `generate_handler!` list is one line per command (ADR-0014 K4 pushed it past 100).
#[allow(clippy::too_many_lines)]
pub fn run() {
    init_tracing();
    let context = tauri::generate_context!();
    // ADR-0018 §3: the updater plugin exists only when a pubkey is compiled in; its JS commands
    // are unreachable anyway (no `updater:*` permission in any capability).
    let updater_configured = updater::configured_pubkey(context.config()).is_some();
    let mut builder = tauri::Builder::default()
        // Review 4 B-4: registered for its Rust API only (`sftp_pick_local`, ADR-0015 power /
        // certificate / VMRC confirmations); the `main` capability grants no dialog permission.
        .plugin(tauri_plugin_dialog::init());
    if updater_configured {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }
    let app = builder
        .setup(move |app| {
            // ADR-0021 §1, §3: the marker decides the directories; an unusable portable
            // set-up or a missing WebView2 runtime is a message box and exit 2, no window.
            // The WebView2 check runs before anything is created (review 8 N-65).
            let dirs = match startup::resolve_dirs(app) {
                Ok(dirs) => dirs,
                Err(refusal) => {
                    startup::refuse(app.handle(), &refusal);
                    return Ok(());
                }
            };
            let portable = dirs.portable();
            // macOS: WKWebView has no profile directory knob; nothing to create there.
            let webview_dir = dirs.webview_dir().filter(|_| !cfg!(target_os = "macos"));
            // L-45: a volume without POSIX modes (vfat / exFAT) is audited like FAT on Windows.
            let mut acl_unavailable = portable && dirs.mode_unavailable;
            if let Some(root) = dirs.portable_root.as_deref() {
                // Windows: owner-only ACL on NTFS; FAT32 / policy failures are audited below.
                if let Err(e) = portable_acl::apply(root) {
                    tracing::warn!(error = ?e, "portable data directory ACL not applied");
                    acl_unavailable = true;
                }
            }
            app.manage(AppState::new(dirs, Settings::production())?);
            let state = app.state::<AppState>();
            state.audit(mooring_audit::AuditEvent::AppStart { portable });
            if acl_unavailable {
                state.audit(mooring_audit::AuditEvent::PortableAclUnavailable);
            }
            // ADR-0020: fixed OS tool paths, 2 processes at a time, 1 port check / s.
            app.manage(net_cmds::NetRuntime::production());
            // Review 5 L-29: no ephemeral web profile outlives the window it belonged to.
            web::sweep::ephemeral_profiles(&state);
            // `"create": false` in tauri.conf.json: the main window is built here so it gets
            // the navigation and new-window guard (security review 2, M-4). Portable mode
            // (Windows, Linux): the WebView profile lives under the portable cache.
            if let Some(dir) = &webview_dir {
                create_private_dir(dir)?;
            }
            navigation::create_main_window(app, webview_dir)?;
            // ADR-0010: syslog mirror from the stored config, then the auto-lock clock + tick.
            commands::syslog::start_stored(&app.state::<AppState>());
            // Review 4 L-18: hourly `audit_heartbeat` while the mirror runs.
            commands::syslog::install_heartbeat(app);
            autolock::install(app);
            // Review 7 N-53: expired import plans (possibly holding secrets) are swept every
            // minute, not only on the next preview.
            import_plans::install(app);
            // ADR-0013: web and detached windows hide while the vault is locked.
            window_lock::install(app);
            // ADR-0017 (A3 S2): sync hub + interval runner (runs only while unlocked).
            sync_runner::install(app);
            // ADR-0016 E2: OIDC window backend + Vault token renewer.
            oidc_window::install(app);
            // ADR-0018 §3 (A4 U0): update runtime + opt-in background check.
            let current = app.package_info().version.clone();
            app.manage(if updater_configured {
                let source = updater::source::PluginSource::new(app.handle().clone());
                updater::UpdateRuntime::new(
                    std::sync::Arc::new(source),
                    std::sync::Arc::new(updater::install_mode::OsProbe { portable }),
                    current,
                )
            } else {
                updater::UpdateRuntime::unconfigured(current)
            });
            updater::background::install(app);
            tracing::info!("mooring started");
            Ok(())
        })
        // ADR-0010: focus → window_hidden.
        .on_window_event(autolock::on_window_event)
        // ADR-0013: the label guard (guard/table.rs, also the AppManifest of build.rs), then
        // the ADR-0010 auto-lock activity hook, before every command.
        .invoke_handler(guard::with_guard(tauri::generate_handler![
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
            detach::window_detach,
            // ADR-0011 §IPC (A2 R2)
            session_graphics::session_frame_ack,
            detach::session_attach,
            session_graphics::session_screenshot,
            session_graphics::session_set_view_only,
            known_certs::known_certs_list,
            known_certs::known_certs_remove,
            conn_options::connection_options_get,
            conn_options::connection_options_set,
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
            sftp_pick::sftp_pick_local,
            sftp_transfers::sftp_download,
            sftp_transfers::sftp_upload,
            sftp_transfers::sftp_transfers,
            sftp_transfers::sftp_cancel,
            // ADR-0010 (A1 exit): auto-lock + syslog mirror
            autolock_cmds::autolock_get,
            autolock_cmds::autolock_set,
            syslog_cmds::syslog_get,
            syslog_cmds::syslog_set,
            syslog_cmds::syslog_test,
            // ADR-0013 §IPC (A2 R5)
            web_cmds::web_open,
            web_cmds::web_close,
            web_cmds::web_focus,
            web_cmds::web_reload,
            web_cmds::web_print,
            web_cmds::web_clear_data,
            web_cmds::web_zoom,
            web_cmds::web_list,
            detach::window_attach,
            // ADR-0014 K4: Kubernetes (pod forwards go through forward_open kind "pod")
            kube::kube_open,
            kube::kube_access,
            kube::kube_contexts,
            kube::kube_namespaces,
            kube::kube_pods,
            kube::kube_pod,
            kube::kube_exec_open,
            kube_logs::kube_logs_open,
            kube_logs::kube_logs_close,
            // ADR-0017 §5 (A3 S2)
            sync_cmds::sync_configure,
            sync_cmds::sync_status,
            sync_cmds::sync_now,
            sync_cmds::sync_resolve_fork,
            sync_cmds::sync_disable,
            sync_join::vault_join,
            // ADR-0015 §5 (A3 V2)
            vsphere::vsphere_test,
            vsphere::vsphere_sync_enable,
            vsphere::vsphere_sync_disable,
            vsphere::vsphere_refresh,
            vsphere::vsphere_status,
            vsphere_console::vsphere_vm_power,
            vsphere_console::vsphere_vm_action,
            vsphere_console::vsphere_vm_identity,
            vsphere_console::vsphere_console,
            // ADR-0016 E2: external secret sources
            secret_sources::secret_source_list,
            secret_sources::secret_source_get,
            secret_sources::secret_source_create,
            secret_sources::secret_source_update,
            secret_sources::secret_source_delete,
            secret_sources::secret_source_test,
            secret_sources::secret_source_revoke,
            secret_sources::credential_external_test,
            secret_sources_oidc::secret_source_oidc_begin,
            secret_sources_oidc::secret_source_oidc_status,
            // ADR-0018 §3 (A4 U0): in-app updates
            update_cmds::update_check,
            update_cmds::update_install,
            update_cmds::update_settings_get,
            update_cmds::update_settings_set,
            // ADR-0020 (A4 N1): network tools, main only
            net_cmds::net_tools,
            net_cmds::net_port_check,
            net_cmds::net_ping,
            net_cmds::net_traceroute,
            net_cmds::net_wg_show,
            import::import_formats,
            import::import_pick,
            import::import_preview,
            import::import_apply,
            import::import_discard,
            commands::ldap_import::ldap_import_preview,
            commands::ldap_import::ldap_import_test,
        ]))
        .build(context)
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

/// What [`create_private_dir`] could do about the directory's mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Owner-only (unix 0700), or Windows where the parent's ACL applies.
    Private,
    /// The volume has no POSIX modes (vfat / exFAT: `chmod` → `EPERM` / `ENOTSUP`, review 8
    /// L-45): the directory exists, its mode is whatever the mount gives every file.
    Unavailable,
}

/// Create the app data dir owner-only on unix (review M2): it holds the vault header, the audit
/// log, `known_hosts` and `mooring.db` (whose own mode is set to 0600 by
/// `mooring_store::Store::open`). An existing directory is tightened too. Windows relies on the
/// per-user `AppData` ACL (a portable root gets its own ACL, `portable_acl`, ADR-0021). A
/// create failure is an error; a mode the volume cannot hold is [`Mode::Unavailable`].
pub(crate) fn create_private_dir(dir: &std::path::Path) -> std::io::Result<Mode> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        match std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            Ok(()) => Ok(Mode::Private),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                ) =>
            {
                tracing::warn!(error = %e.kind(), "directory mode not applied: the volume has no POSIX modes");
                Ok(Mode::Unavailable)
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map(|()| Mode::Private)
    }
}

fn init_tracing() {
    use tracing_subscriber::fmt;
    let filter = log_filter(std::env::var("MOORING_LOG").ok().as_deref());
    // Secrets never reach tracing by contract; mooring_audit::redact is applied again in the
    // file sink added in A1 (defence in depth).
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

// --- review 5 L-24: CredSSP / NTLM exchange bytes never reach any log level -------------
/// Targets that log whole `TsRequest`s (the NTLM AUTHENTICATE message is offline-crackable).
const CREDSSP_TARGETS: [&str; 3] =
    ["ironrdp_connector::credssp", "ironrdp_connector::connection", "sspi"];

/// `MOORING_LOG` directives (default `info`) with every directive for [`CREDSSP_TARGETS`]
/// dropped and `<target>=info` appended, so neither a broad `debug` nor a targeted `trace`
/// can lower them. Span-scoped directives (`[span]=trace`, `target[{field}]=debug`) are
/// dropped too (review 5 N-38): they enable events of every target inside matching spans,
/// which the `=info` tail does not override.
fn log_filter(user: Option<&str>) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    let protected = |d: &str| CREDSSP_TARGETS.iter().any(|t| d.trim_start().starts_with(t));
    let span_scoped = |d: &str| d.contains('[');
    let mut spec: Vec<&str> = user
        .unwrap_or("info")
        .split(',')
        .filter(|d| !d.trim().is_empty() && !protected(d) && !span_scoped(d))
        .collect();
    if spec.is_empty() {
        spec.push("info");
    }
    let tail: Vec<String> = CREDSSP_TARGETS.iter().map(|t| format!("{t}=info")).collect();
    let full = format!("{},{}", spec.join(","), tail.join(","));
    EnvFilter::try_new(full).unwrap_or_else(|_| EnvFilter::new(format!("info,{}", tail.join(","))))
}
// --- end L-24 ----------------------------------------------------------------------------

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

    /// L-24: whatever `MOORING_LOG` says, `CredSSP` targets stay at info.
    #[test]
    fn credssp_targets_never_log_below_info() {
        use std::sync::Mutex;
        struct Sink(&'static Mutex<Vec<u8>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for user in [
            None,
            Some("debug"),
            Some("trace,sspi::ntlm=trace,ironrdp_connector::credssp=trace"),
            Some("bogus=["),
            // N-38: span-scoped directives would enable every target inside the span.
            Some("[connect]=trace"),
            Some("info,ironrdp_connector[{step}]=trace,[{step}]=debug"),
            Some("info,[connect{step=1}]=trace"),
        ] {
            let buf: &'static Mutex<Vec<u8>> = Box::leak(Box::new(Mutex::new(Vec::new())));
            let sub = tracing_subscriber::fmt()
                .with_env_filter(super::log_filter(user))
                .with_writer(move || Sink(buf))
                .finish();
            tracing::subscriber::with_default(sub, || {
                // The IronRDP connector emits the CredSSP lines inside its `connect` span.
                let span = tracing::info_span!(target: "ironrdp_connector::connection", "connect", step = 1);
                let _in = span.enter();
                tracing::debug!(target: "ironrdp_connector::credssp", "secret-ts-request");
                tracing::trace!(target: "sspi::ntlm", "secret-ntlm");
                tracing::debug!(target: "ironrdp_connector::connection", "secret-connection");
                tracing::info!(target: "ironrdp_connector::credssp", "visible-info");
                tracing::debug!(target: "mooring_app", "other-debug");
            });
            let text = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8");
            assert!(!text.contains("secret"), "{user:?}: {text}");
            assert!(text.contains("visible-info"), "{user:?}: {text}");
            let debug_on = user.is_some_and(|u| u.starts_with("debug") || u.starts_with("trace"));
            assert_eq!(text.contains("other-debug"), debug_on, "{user:?}: {text}");
        }
    }
}
