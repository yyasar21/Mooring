//! Detach a session tab to its own window and back (ADR-0013 §Detach, ADR-0008 reservation).
//!
//! `window_detach` opens `detached-<sessionId>` on the bundled UI at `#/detached/<sessionId>`.
//! That view calls `session_attach`, which moves the session's sinks to it ([`Route`]); the
//! main view receives `detached`. `window_attach` (or closing the window) moves the session
//! back to `main`, which receives `attached`.

use std::sync::Arc;

use mooring_audit::AuditEvent;
use mooring_core::Protocol;
use serde::Serialize;
use tauri::ipc::{Channel, InvokeResponseBody, JavaScriptChannelId};
use tauri::{AppHandle, Manager, Runtime, State, Webview, WindowEvent};

use crate::commands::session_graphics::{Attached, DesktopSize};
use crate::commands::web::window_failed;
use crate::error::{IpcError, IpcResult};
use crate::frame_pump::FrameOut;
use crate::guard::DETACHED_PREFIX;
use crate::route::{Route, Sinks};
use crate::sessions::{EventSink, WireEvent};
use crate::state::AppState;

/// `{ windowLabel }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detached {
    /// `detached-<sessionId>`.
    pub window_label: String,
}

/// The route-relevant parts of a registered session.
struct Found {
    connection: String,
    protocol: Protocol,
    route: Arc<Route>,
    attached: Attached,
}

fn find(state: &AppState, session_id: &str) -> IpcResult<Found> {
    if uuid::Uuid::parse_str(session_id).is_err() {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    let h = map.get(session_id).ok_or_else(|| IpcError::new("session.not_found", "session not found"))?;
    let size = h.graphical().map_or(DesktopSize { width: 0, height: 0 }, |g| {
        let (w, h) = g.frames.size();
        DesktopSize { width: u32::from(w), height: u32::from(h) }
    });
    Ok(Found {
        connection: h.connection_id.clone(),
        protocol: h.protocol,
        route: Arc::clone(&h.route),
        attached: Attached { protocol: h.protocol.name(), state: h.phase().as_str(), size },
    })
}

/// `session_attach` from `view` (`main` or `detached-<sessionId>`, checked by the guard):
/// this view's channels take the session over, the previous view gets `detached`, frame
/// credits reset and the next frame is full. RDP/VNC need `frames`; for SSH a `frames`
/// channel is ignored (U3: the detached route does not know the protocol); an SSH session
/// reports size 0×0 (the view sends its own `resize`).
pub fn attach_view(state: &AppState, session_id: &str, view: &str, mut sinks: Sinks) -> IpcResult<Attached> {
    let found = find(state, session_id)?;
    let graphical = matches!(found.protocol, Protocol::Rdp | Protocol::Vnc);
    if graphical && sinks.frames.is_none() {
        return Err(IpcError::invalid("onFrame", "required for rdp and vnc"));
    }
    if !graphical {
        sinks.frames = None;
    }
    found.route.attach(view, sinks);
    Ok(found.attached)
}

/// `window_detach` checks: vault unlocked, a live session (web connections are windows
/// already: `input.invalid`). Returns `(label, connection)`.
pub fn plan_detach(state: &AppState, session_id: &str) -> IpcResult<(String, String)> {
    state.with_ready(|_, _| Ok(()))?;
    if state.web.lock().map_err(|_| IpcError::poisoned())?.contains_key(session_id) {
        return Err(IpcError::invalid("sessionId", "web sessions are always windows"));
    }
    let found = find(state, session_id)?;
    Ok((format!("{DETACHED_PREFIX}{session_id}"), found.connection))
}

/// Move the session back to `main` (`window_attach`, or its window closed). Returns the
/// detached label when there was one; audited `session_attached`.
pub fn attach_main(state: &AppState, session_id: &str) -> IpcResult<Option<String>> {
    let found = find(state, session_id)?;
    let label = found.route.back_to_main();
    if label.is_some() {
        state.audit(AuditEvent::SessionAttached {
            connection: found.connection,
            session: session_id.to_owned(),
        });
    }
    Ok(label)
}

/// The raw MFR1 channel of `webview` (`InvokeResponseBody::Raw`, an `ArrayBuffer` in JS).
pub fn frame_channel<R: Runtime>(webview: &Webview<R>, id: JavaScriptChannelId) -> FrameOut {
    let channel: Channel<InvokeResponseBody> = id.channel_on(webview.clone());
    Arc::new(move |bytes| channel.send(InvokeResponseBody::Raw(bytes)).is_ok())
}

// ------------------------------------------------------------------ Tauri wrappers

/// `session_attach({ sessionId, onEvent, onFrame? })` from `main` or the session's own
/// detached window.
#[tauri::command]
pub fn session_attach<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, AppState>,
    session_id: String,
    on_event: Channel<WireEvent>,
    on_frame: Option<JavaScriptChannelId>,
) -> IpcResult<Attached> {
    let events: EventSink = Arc::new(move |e| on_event.send(e).is_ok());
    let frames = on_frame.map(|id| frame_channel(&webview, id));
    attach_view(&state, &session_id, webview.label(), Sinks { events, frames })
}

/// `window_detach({ sessionId })` → `{ windowLabel }` (main only). A second call focuses
/// the open window.
#[tauri::command]
pub async fn window_detach<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    session_id: String,
) -> IpcResult<Detached> {
    let (label, connection) = plan_detach(&state, &session_id)?;
    if let Some(w) = app.get_webview_window(&label) {
        let _ = w.show().and_then(|()| w.set_focus());
        return Ok(Detached { window_label: label });
    }
    let window = crate::navigation::create_detached_window(&app, &label, &session_id)
        .map_err(|e| window_failed(&e))?;
    let handle = app.clone();
    let sid = session_id.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::Destroyed = event {
            if let Some(state) = handle.try_state::<AppState>() {
                // The session may have ended already: nothing to move back then.
                let _ = attach_main(&state, &sid);
            }
        }
    });
    state.audit(AuditEvent::SessionDetached { connection, session: session_id });
    Ok(Detached { window_label: label })
}

/// `window_attach({ sessionId })` from `main` or the detached window: the session returns to
/// `main` and the detached window closes. The session itself stays open.
#[tauri::command]
pub async fn window_attach<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    session_id: String,
) -> IpcResult<()> {
    let label = attach_main(&state, &session_id)?;
    if let Some(w) = label.and_then(|l| app.get_webview_window(&l)) {
        if let Err(e) = w.destroy() {
            tracing::warn!(error = %e, "detached window close failed");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "detach_tests.rs"]
mod tests;
