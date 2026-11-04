//! Web session commands (ADR-0013 §IPC). The window is built from stored connection data
//! only; the `WebView` names a connection id, never a URL or a path (review 4 B-4).

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_core::Protocol;
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, Runtime, State, Url, WebviewWindow, WindowEvent};
use time::OffsetDateTime;

use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;
use crate::web::{self, Storage, StorageOs, WebEntry, WebEvent, WebPlan, WebSink, WebWindowInfo};

/// `web_zoom` range.
pub const ZOOM_RANGE: std::ops::RangeInclusive<f64> = 0.25..=5.0;

/// `{ windowLabel }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowOpened {
    /// Label of the new (or already open) window.
    pub window_label: String,
}

fn not_open() -> IpcError {
    IpcError::new("session.not_found", "no web window is open for this connection")
}

pub(crate) fn window_failed(e: &tauri::Error) -> IpcError {
    tracing::error!(error = %e, "window creation failed");
    IpcError::new("window.failed", "the window could not be created")
}

/// The label of the open window of `connection_id`.
pub fn open_label(state: &AppState, connection_id: &str) -> IpcResult<String> {
    let id = dto::connection_id("connectionId", connection_id)?.to_string();
    let map = state.web.lock().map_err(|_| IpcError::poisoned())?;
    map.get(&id).map(|e| e.label.clone()).ok_or_else(not_open)
}

/// A second `web_open` for a connection: the new channel replaces the old one and the label
/// is returned (the caller focuses the window). `None` when no window is registered.
pub fn reopen(state: &AppState, connection_id: &str, sink: WebSink) -> IpcResult<Option<String>> {
    let mut map = state.web.lock().map_err(|_| IpcError::poisoned())?;
    Ok(map.get_mut(connection_id).map(|e| {
        e.sink = sink;
        e.label.clone()
    }))
}

/// Register a freshly built window and audit `web_opened`.
pub fn register(state: &AppState, plan: &WebPlan, sink: WebSink) -> IpcResult<()> {
    let persistent = plan.storage != Storage::Ephemeral;
    let entry = WebEntry {
        label: plan.label.clone(),
        origin: plan.origin(),
        title: String::new(),
        persistent,
        opened_at: dto::ts(OffsetDateTime::now_utc()),
        sink,
    };
    state.web.lock().map_err(|_| IpcError::poisoned())?.insert(plan.connection_id.clone(), entry);
    state.audit(AuditEvent::WebOpened {
        connection: plan.connection_id.clone(),
        origin: plan.origin(),
        persistent,
    });
    Ok(())
}

/// The window of `connection_id` is gone: forget it, audit `web_closed`, send `closed`.
/// Idempotent (`web_close` and the `Destroyed` event both call it).
pub fn closed(state: &AppState, connection_id: &str) -> bool {
    let Some(entry) = web::forget(state, connection_id) else { return false };
    state.audit(AuditEvent::WebClosed { connection: connection_id.to_owned() });
    (entry.sink)(WebEvent::Closed);
    true
}

/// `web_zoom` factor check.
pub fn check_zoom(factor: f64) -> IpcResult<f64> {
    if factor.is_finite() && ZOOM_RANGE.contains(&factor) {
        Ok(factor)
    } else {
        Err(IpcError::invalid("factor", "0.25 to 5"))
    }
}

/// `web_clear_data` without a window: the connection must be a web connection (vault
/// unlocked); its store directory is removed and `web_data_cleared` audited.
pub fn clear_data(state: &AppState, connection_id: &str) -> IpcResult<bool> {
    let id = dto::connection_id("connectionId", connection_id)?;
    state.with_ready(|_, store| {
        if store.get_connection(id)?.protocol == Protocol::Web {
            Ok(())
        } else {
            Err(IpcError::invalid("connectionId", "not a web connection"))
        }
    })?;
    let removed = web::remove_store_dir(state, connection_id)?;
    state.audit(AuditEvent::WebDataCleared { connection: id.to_string() });
    Ok(removed)
}

fn unlocked(state: &AppState) -> IpcResult<()> {
    state.with_ready(|_, _| Ok(()))
}

fn dev_url<R: Runtime>(app: &AppHandle<R>) -> Option<Url> {
    if cfg!(dev) {
        app.config().build.dev_url.clone()
    } else {
        None
    }
}

fn window_of<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    connection_id: &str,
) -> IpcResult<WebviewWindow<R>> {
    let label = open_label(state, connection_id)?;
    app.get_webview_window(&label).ok_or_else(not_open)
}

fn show<R: Runtime>(w: &WebviewWindow<R>) {
    if let Err(e) = w.show().and_then(|()| w.set_focus()) {
        tracing::warn!(error = %e, "web window focus failed");
    }
}

fn native<T>(r: tauri::Result<T>) -> IpcResult<T> {
    r.map_err(|e| {
        tracing::warn!(error = %e, "web window call failed");
        IpcError::new("window.failed", "the web window did not accept the request")
    })
}

// ------------------------------------------------------------------ Tauri wrappers

/// `web_open({ connectionId, onEvent })` → `{ windowLabel }`. Opening again focuses the open
/// window and moves its events to the new channel.
#[tauri::command]
pub async fn web_open<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
    on_event: Channel<WebEvent>,
) -> IpcResult<WindowOpened> {
    let plan = web::plan(&state, &connection_id, StorageOs::current(), dev_url(&app))?;
    let sink: WebSink = Arc::new(move |e| on_event.send(e).is_ok());
    if let Some(label) = reopen(&state, &plan.connection_id, Arc::clone(&sink))? {
        if let Some(w) = app.get_webview_window(&label) {
            show(&w);
            return Ok(WindowOpened { window_label: label });
        }
        web::forget(&state, &plan.connection_id);
    }
    if let Storage::Directory(dir) = &plan.storage {
        crate::create_private_dir(dir).map_err(|e| {
            tracing::warn!(kind = ?e.kind(), "web store directory");
            IpcError::new("web.store_failed", "the browsing data folder could not be created")
        })?;
    }
    if plan.persistent_refused {
        tracing::warn!("persistent web storage needs macOS 14; this window is ephemeral");
    }
    let window = web::window::build(
        &app,
        &plan,
        Arc::clone(&state.audit),
        Arc::clone(&state.web),
        Arc::clone(&sink),
    )
    .map_err(|e| window_failed(&e))?;
    register(&state, &plan, sink)?;
    let handle = app.clone();
    let connection = plan.connection_id.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::Destroyed = event {
            if let Some(state) = handle.try_state::<AppState>() {
                closed(&state, &connection);
            }
        }
    });
    Ok(WindowOpened { window_label: plan.label })
}

/// `web_close({ connectionId })`.
#[tauri::command]
pub async fn web_close<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<()> {
    let window = window_of(&app, &state, &connection_id);
    let id = dto::connection_id("connectionId", &connection_id)?.to_string();
    if !closed(&state, &id) {
        return Err(not_open());
    }
    if let Ok(w) = window {
        native(w.destroy())?;
    }
    Ok(())
}

/// `web_focus({ connectionId })`: refused while the vault is locked (the window stays hidden).
#[tauri::command]
pub fn web_focus<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<()> {
    unlocked(&state)?;
    show(&window_of(&app, &state, &connection_id)?);
    Ok(())
}

/// `web_reload({ connectionId })`.
#[tauri::command]
pub fn web_reload<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<()> {
    native(window_of(&app, &state, &connection_id)?.reload())
}

/// `web_print({ connectionId })`: the native print dialog of the page.
#[tauri::command]
pub fn web_print<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<()> {
    unlocked(&state)?;
    native(window_of(&app, &state, &connection_id)?.print())
}

/// `web_zoom({ connectionId, factor })`, `0.25..=5.0`.
#[tauri::command]
pub fn web_zoom<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
    factor: f64,
) -> IpcResult<()> {
    let factor = check_zoom(factor)?;
    native(window_of(&app, &state, &connection_id)?.set_zoom(factor))
}

/// `web_clear_data({ connectionId })`: wipes the open window's browsing data, then the
/// connection's store directory. Audited `web_data_cleared`.
#[tauri::command]
pub fn web_clear_data<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    connection_id: String,
) -> IpcResult<()> {
    let open = window_of(&app, &state, &connection_id).ok();
    if let Some(w) = &open {
        native(w.clear_all_browsing_data())?;
    }
    match clear_data(&state, &connection_id) {
        // WebView2 keeps its open profile locked: the data is cleared, the folder goes with
        // the next clear or the connection.
        Err(e) if e.code == "web.clear_failed" && open.is_some() => Ok(()),
        other => other.map(|_| ()),
    }
}

/// `web_list()` (passive).
#[tauri::command]
pub fn web_list(state: State<'_, AppState>) -> IpcResult<Vec<WebWindowInfo>> {
    web::list(&state)
}

/// Close the web window of a deleted connection (`connection_delete`).
pub fn close_for_deleted<R: Runtime>(app: &AppHandle<R>, state: &AppState, connection_id: &str) {
    let window = window_of(app, state, connection_id).ok();
    if let Ok(id) = dto::connection_id("id", connection_id) {
        closed(state, &id.to_string());
    }
    if let Some(w) = window {
        let _ = w.destroy();
    }
}

#[cfg(test)]
#[path = "web_tests.rs"]
mod tests;
