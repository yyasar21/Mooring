//! Commands on a graphical session's framebuffer (ADR-0011 §IPC): frame credits, re-attach,
//! screenshot, view-only.

use std::sync::atomic::Ordering;

use mooring_audit::AuditEvent;
use serde::Serialize;
use tauri::State;

use crate::error::{IpcError, IpcResult};
use crate::sessions::GraphicalControl;
use crate::state::AppState;

/// `{ width, height }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DesktopSize {
    /// Pixels.
    pub width: u32,
    /// Pixels.
    pub height: u32,
}

/// `session_attach` result: `{ protocol, state, size }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attached {
    /// `rdp` | `vnc`.
    pub protocol: &'static str,
    /// `connecting` | `connected` | `reconnecting`.
    pub state: &'static str,
    /// Current framebuffer size (0×0 before the first frame).
    pub size: DesktopSize,
}

fn graphical(state: &AppState, session_id: &str) -> IpcResult<(GraphicalControl, String, Attached)> {
    if session_id.is_empty() || session_id.len() > 64 {
        return Err(IpcError::invalid("sessionId", "not a session id"));
    }
    let map = state.sessions.lock().map_err(|_| IpcError::poisoned())?;
    let h = map.get(session_id).ok_or_else(|| IpcError::new("session.not_found", "session not found"))?;
    let g = h.graphical().ok_or_else(|| IpcError::invalid("sessionId", "not an rdp or vnc session"))?;
    let (w, h2) = g.frames.size();
    let info = Attached {
        protocol: h.protocol.name(),
        state: h.phase().as_str(),
        size: DesktopSize { width: u32::from(w), height: u32::from(h2) },
    };
    Ok((g.clone(), h.connection_id.clone(), info))
}

/// `session_frame_ack({ sessionId, seq })`: return the credit of message `seq` (and every
/// earlier one). Passive (not user activity). A forged or stale `seq` is ignored.
pub fn frame_ack(state: &AppState, session_id: &str, seq: u32) -> IpcResult<()> {
    let (g, _, _) = graphical(state, session_id)?;
    g.flow.ack(seq);
    Ok(())
}

/// `session_attach({ sessionId })`: a view (after unlock or re-attach) starts over: in-flight
/// credits are dropped (the old view never acks them) and the next message is a full frame.
pub fn attach(state: &AppState, session_id: &str) -> IpcResult<Attached> {
    let (g, _, info) = graphical(state, session_id)?;
    g.flow.reset();
    g.frames.invalidate();
    Ok(info)
}

/// `session_screenshot({ sessionId })`: the Rust framebuffer goes to the OS clipboard as an
/// image (no pixels cross IPC). Audited `session_screenshot`.
pub fn screenshot(state: &AppState, session_id: &str) -> IpcResult<DesktopSize> {
    // L-26: never behind the lock screen (it would re-fill the clipboard the lock cleared).
    state.with_ready(|_, _| Ok(()))?;
    let (g, connection, _) = graphical(state, session_id)?;
    let (w, h, rgba) = g.frames.snapshot();
    if w == 0 || h == 0 {
        return Err(IpcError::new("session.not_connected", "no desktop to capture yet"));
    }
    let (width, height) = (u32::from(w), u32::from(h));
    state
        .settings
        .clipboard
        .set_image(width, height, &rgba)
        .map_err(|_| IpcError::new("clipboard.unavailable", "the clipboard cannot take an image"))?;
    if let Ok(mut shot) = state.screenshot_clipboard.lock() {
        *shot = Some((width, height));
    }
    state.audit(AuditEvent::SessionScreenshot { connection, width, height });
    Ok(DesktopSize { width, height })
}

/// `session_set_view_only({ sessionId, viewOnly })`: drop pointer, key, wheel, text and
/// clipboard input while on (`release_all` always passes).
/// Needs an unlocked vault; audited `session_view_only` (L-26).
pub fn set_view_only(state: &AppState, session_id: &str, view_only: bool) -> IpcResult<()> {
    state.with_ready(|_, _| Ok(()))?;
    let (g, connection, _) = graphical(state, session_id)?;
    g.view_only.store(view_only, Ordering::Relaxed);
    state.audit(AuditEvent::SessionViewOnly { connection, view_only });
    Ok(())
}

// ------------------------------------------------------------------ Tauri wrappers

/// `session_frame_ack({ sessionId, seq })`.
#[tauri::command]
pub fn session_frame_ack(state: State<'_, AppState>, session_id: String, seq: u32) -> IpcResult<()> {
    frame_ack(&state, &session_id, seq)
}

/// `session_attach({ sessionId })`.
#[tauri::command]
pub fn session_attach(state: State<'_, AppState>, session_id: String) -> IpcResult<Attached> {
    attach(&state, &session_id)
}

/// `session_screenshot({ sessionId })`.
#[tauri::command]
pub fn session_screenshot(state: State<'_, AppState>, session_id: String) -> IpcResult<DesktopSize> {
    screenshot(&state, &session_id)
}

/// `session_set_view_only({ sessionId, viewOnly })`.
#[tauri::command]
pub fn session_set_view_only(
    state: State<'_, AppState>,
    session_id: String,
    view_only: bool,
) -> IpcResult<()> {
    set_view_only(&state, &session_id, view_only)
}
