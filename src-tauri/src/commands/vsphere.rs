//! vCenter sync commands (ADR-0015 §5): `vsphere_test`, `vsphere_sync_enable`,
//! `vsphere_sync_disable`, `vsphere_refresh`, `vsphere_status` (passive). The `WebView` names
//! connection ids only; hosts, credentials and certificates come from the store and the vault.
//! VM commands live in [`crate::commands::vsphere_vm`].

use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime, State};

use crate::autolock::AutoLock;
use crate::commands::vsphere_confirm::{DialogConfirm, Prompt};
use crate::commands::vsphere_login::{self, map_error};
use crate::dto::{self, FolderDto};
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;
use crate::vsphere_sync::{self, source_id, SyncReport, SyncStatus, Trigger, VsCtx};

/// `vsphere_test` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    /// vCenter version.
    pub version: String,
    /// Build number.
    pub build: String,
    /// The UPN that signed in.
    pub user: String,
}

/// `vsphere_test({ connectionId })`: login, version, logout. Nothing is cached.
pub async fn test(state: &AppState, prompt: Prompt<'_>, connection_id: &str) -> IpcResult<TestResult> {
    let source = source_id(connection_id)?;
    let ctx = VsCtx::of(state);
    let login = vsphere_login::login(&ctx, source, Some(prompt)).await?;
    let user = vsphere_login::credential(&ctx.ready, source)?.upn;
    let version = login.session.version().await.map_err(|e| map_error(&e));
    if let Err(e) = login.session.logout().await {
        tracing::debug!(code = e.code(), "vsphere test logout failed");
    }
    let v = version?;
    Ok(TestResult { version: v.version.as_str().to_owned(), build: v.build.as_str().to_owned(), user })
}

/// `vsphere_sync_enable({ connectionId, parentFolderId })`: create the synced root named
/// after the connection under `parentFolderId`, run the first refresh (the import) and start
/// the scheduler. A failed import removes the empty root again and returns the error.
pub async fn sync_enable(
    state: &AppState,
    prompt: Prompt<'_>,
    connection_id: &str,
    parent_folder_id: &str,
) -> IpcResult<FolderDto> {
    let source = source_id(connection_id)?;
    let parent = dto::folder_id("parentFolderId", parent_folder_id)?;
    let ctx = VsCtx::of(state);
    let target = vsphere_login::target(&ctx.ready, source)?;
    let (root, existed) = state.with_ready(|_, store| {
        let existed = store.sync_root(source)?.is_some();
        Ok((store.sync_enable(source, parent, &target.name)?, existed))
    })?;
    if let Err(e) = vsphere_sync::refresh(&ctx, source, Trigger::Import, Some(prompt)).await {
        if !existed {
            state.with_ready(|_, store| Ok(store.sync_disable(source, false)?))?;
            ctx.hub.remove(&source.to_string());
        }
        return Err(e);
    }
    crate::scheduler::ensure(&ctx, source);
    state.with_ready(|_, store| dto::folder(store, root.id))
}

/// `vsphere_sync_disable({ connectionId, keep })`: stop the scheduler, log out, and detach
/// (`keep: true`) or delete (`keep: false`) the subtree.
pub fn sync_disable(state: &AppState, connection_id: &str, keep: bool) -> IpcResult<()> {
    let source = source_id(connection_id)?;
    vsphere_login::target(&state.ready(), source)?;
    let had = state.with_ready(|_, store| Ok(store.sync_disable(source, keep)?))?;
    state.vsphere.remove(&source.to_string());
    if had {
        Ok(())
    } else {
        Err(IpcError::new("vsphere.not_found", "sync is not enabled for this vCenter"))
    }
}

/// `vsphere_refresh({ connectionId })` (joins a running refresh).
pub async fn refresh(state: &AppState, prompt: Prompt<'_>, connection_id: &str) -> IpcResult<SyncReport> {
    let source = source_id(connection_id)?;
    let ctx = VsCtx::of(state);
    vsphere_login::target(&ctx.ready, source)?;
    vsphere_sync::refresh(&ctx, source, Trigger::Manual, Some(prompt)).await
}

/// `vsphere_status({ connectionId })` (passive: no network, no idle-clock touch).
pub fn status(state: &AppState, connection_id: &str) -> IpcResult<SyncStatus> {
    let source = source_id(connection_id)?;
    vsphere_login::target(&state.ready(), source)?;
    Ok(state.vsphere.status(&source.to_string()))
}

// ------------------------------------------------------------------ Tauri wrappers

/// `vsphere_test({ connectionId })` → `{ version, build, user }`.
#[tauri::command]
pub async fn vsphere_test<R: Runtime>(app: AppHandle<R>, state: State<'_, AppState>, connection_id: String) -> IpcResult<TestResult> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    test(&state, Prompt { confirm: &dialog, autolock: autolock.as_deref() }, &connection_id).await
}

/// `vsphere_sync_enable({ connectionId, parentFolderId })` → `Folder`.
#[tauri::command]
pub async fn vsphere_sync_enable<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
    parent_folder_id: String,
) -> IpcResult<FolderDto> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    let prompt = Prompt { confirm: &dialog, autolock: autolock.as_deref() };
    sync_enable(&state, prompt, &connection_id, &parent_folder_id).await
}

/// `vsphere_sync_disable({ connectionId, keep })`.
#[tauri::command]
pub fn vsphere_sync_disable(state: State<'_, AppState>, connection_id: String, keep: bool) -> IpcResult<()> {
    sync_disable(&state, &connection_id, keep)
}

/// `vsphere_refresh({ connectionId })` → `SyncReport`.
#[tauri::command]
pub async fn vsphere_refresh<R: Runtime>(app: AppHandle<R>, state: State<'_, AppState>, connection_id: String) -> IpcResult<SyncReport> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    refresh(&state, Prompt { confirm: &dialog, autolock: autolock.as_deref() }, &connection_id).await
}

/// `vsphere_status({ connectionId })` → `{ lastRefresh, lastError, running, lastReport, scheduled }`.
#[tauri::command]
pub fn vsphere_status(state: State<'_, AppState>, connection_id: String) -> IpcResult<SyncStatus> {
    status(&state, &connection_id)
}
