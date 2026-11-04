//! `vsphere_console` and the Tauri wrappers of the VM commands (ADR-0015 §4–5).
//!
//! `kind: "client"` opens the vSphere Client (`https://<vcenter>/ui/`, deep-linked when the
//! vCenter instance UUID is known) in an ADR-0013 web window keyed by the **vCenter**
//! connection id (`web-<vcenterId>`), ephemeral storage, allow-list = the vCenter origin only;
//! a second call navigates the open window to the other VM. No secret is in the URL; the user
//! signs in inside the window. `kind: "vmrc"` is the opt-in hand-off of
//! [`crate::commands::vsphere_vm::vmrc`].

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_core::options::WebConnOptions;
use tauri::{AppHandle, Manager, Runtime, State, WindowEvent};

use crate::autolock::AutoLock;
use crate::commands::vsphere_confirm::{DialogConfirm, OsOpener, Prompt};
use crate::commands::vsphere_vm::{self, ActionDto, ConsoleKind, IdentityDto, PowerDto, VmTarget};
use crate::commands::web as web_cmds;
use crate::error::IpcResult;
use crate::guard::WEB_PREFIX;
use crate::state::AppState;
use crate::vsphere_sync::VsCtx;
use crate::web::policy::NavPolicy;
use crate::web::{self, Storage, StorageOs, WebPlan, WebSink};

/// `{ windowLabel }` (`null` for VMRC or a cancelled confirmation).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleOpened {
    /// `web-<vcenterId>` for the vSphere Client.
    pub window_label: Option<String>,
}

/// The web window plan of the vSphere Client for `t`. `storage` is
/// [`web::ephemeral_storage`] of the vCenter id (review 5 L-29: own profile on Windows).
pub fn client_plan(t: &VmTarget, dev_url: Option<tauri::Url>, storage: Storage) -> IpcResult<WebPlan> {
    let url = mooring_vsphere::vsphere_client_url(&t.target.base, &t.vm, None)
        .map_err(|e| crate::commands::vsphere_login::map_error(&e))?;
    let opts = WebConnOptions { url: url.to_string(), allowed_origins: Vec::new(), persistent: false, allow_http: false };
    let (policy, url) = NavPolicy::from_options(&opts, dev_url)?;
    let connection_id = t.source.to_string();
    Ok(WebPlan {
        label: format!("{WEB_PREFIX}{connection_id}"),
        connection_id,
        name: t.target.name.clone(),
        url,
        policy,
        storage,
        persistent_refused: false,
    })
}

/// Review 6 N-39 (the N-30 post-check for this build path): `vsphere_console` is async, so
/// a lock can land between `vm_target` and the window's build or show. Hides the window
/// through `hide` when the vault is locked now (the lock observer shows it again after the
/// unlock). Returns whether it hid.
pub fn post_open(state: &AppState, label: &str, hide: impl FnOnce() -> Result<(), String>) -> bool {
    web_cmds::hide_if_locked(state, || {
        if let Err(e) = hide() {
            tracing::warn!(error = %e, label, "vSphere Client window hide after lock failed");
        } else {
            tracing::info!(label, "vault locked while the vSphere Client window was opened; hidden");
        }
    })
}

fn open_client<R: Runtime>(app: &AppHandle<R>, state: &AppState, plan: &WebPlan) -> IpcResult<String> {
    let sink: WebSink = Arc::new(|_| true);
    if let Some(label) = web_cmds::reopen(state, &plan.connection_id, Arc::clone(&sink))? {
        if let Some(w) = app.get_webview_window(&label) {
            if let Err(e) = w.navigate(plan.url.clone()).and_then(|()| w.show()).and_then(|()| w.set_focus()) {
                tracing::warn!(error = %e, "vSphere Client window navigation failed");
            }
            post_open(state, &label, || w.hide().map_err(|e| e.to_string()));
            return Ok(label);
        }
        web::forget(state, &plan.connection_id);
    }
    let window = web::window::build(app, plan, Arc::clone(&state.audit), Arc::clone(&state.web), Arc::clone(&sink))
        .map_err(|e| web_cmds::window_failed(&e))?;
    web_cmds::register(state, plan, sink)?;
    post_open(state, &plan.label, || window.hide().map_err(|e| e.to_string()));
    let handle = app.clone();
    let connection = plan.connection_id.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::Destroyed = event {
            if let Some(state) = handle.try_state::<AppState>() {
                web_cmds::destroyed(&state, &connection);
            }
        }
    });
    Ok(plan.label.clone())
}

fn dev_url<R: Runtime>(app: &AppHandle<R>) -> Option<tauri::Url> {
    if cfg!(dev) {
        app.config().build.dev_url.clone()
    } else {
        None
    }
}

/// `vsphere_vm_power({ connectionId })` → `{ state }` (passive).
#[tauri::command]
pub async fn vsphere_vm_power(state: State<'_, AppState>, connection_id: String) -> IpcResult<PowerDto> {
    vsphere_vm::power_state(&state, &connection_id).await
}

/// `vsphere_vm_action({ connectionId, action })` → `{ outcome: "done" | "cancelled" }`.
#[tauri::command]
pub async fn vsphere_vm_action<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
    action: String,
) -> IpcResult<ActionDto> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    let prompt = Prompt { confirm: &dialog, autolock: autolock.as_deref() };
    vsphere_vm::action(&state, prompt, &connection_id, &action).await
}

/// `vsphere_vm_identity({ connectionId })` → `{ hostName, ip, family }`.
#[tauri::command]
pub async fn vsphere_vm_identity<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<IdentityDto> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    vsphere_vm::identity(&state, Prompt { confirm: &dialog, autolock: autolock.as_deref() }, &connection_id).await
}

/// `vsphere_console({ connectionId, kind: "client" | "vmrc" })` → `{ windowLabel | null }`.
#[tauri::command]
pub async fn vsphere_console<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
    kind: String,
) -> IpcResult<ConsoleOpened> {
    let kind = ConsoleKind::parse(&kind)?;
    let ctx = VsCtx::of(&state);
    let t = vsphere_vm::vm_target(&ctx, &connection_id)?;
    match kind {
        ConsoleKind::Client => {
            let storage = web::ephemeral_storage(&state, &t.source.to_string(), StorageOs::current());
            let plan = client_plan(&t, dev_url(&app), storage)?;
            let label = open_client(&app, &state, &plan)?;
            ctx.audit(AuditEvent::VsphereConsole {
                connection: t.source.to_string(),
                vm: t.vm.as_str().to_owned(),
                kind: "client".to_owned(),
            });
            Ok(ConsoleOpened { window_label: Some(label) })
        }
        ConsoleKind::Vmrc => {
            let dialog = DialogConfirm { app: app.clone() };
            let autolock = app.try_state::<AutoLock>();
            let prompt = Prompt { confirm: &dialog, autolock: autolock.as_deref() };
            vsphere_vm::vmrc(&state, prompt, &OsOpener, &t).await?;
            Ok(ConsoleOpened { window_label: None })
        }
    }
}
