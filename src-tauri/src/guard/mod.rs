//! Command ACL in Rust (ADR-0013 "defence in depth"), on top of the Tauri `AppManifest`.
//!
//! `build.rs` turns [`COMMANDS`] into `allow-<command>` permissions; the capabilities grant
//! them per window label (`main`: all, `detached-*`: the six [`Scope::Session`] commands,
//! `web-*`: none). [`with_guard`] wraps the generated invoke handler and checks the same table
//! again before any command runs: an unknown or `web-*` label gets `ipc.forbidden`, and a
//! `detached-<sessionId>` window may only name its own `sessionId`.

mod table;

use serde_json::Value;
use tauri::ipc::{Invoke, InvokeBody};
use tauri::Runtime;

pub use self::table::{Scope, COMMANDS};
use crate::error::{IpcError, IpcResult};
use crate::navigation::MAIN_WINDOW;

/// Label prefix of a detached session window: `detached-<sessionId>`.
pub const DETACHED_PREFIX: &str = "detached-";
/// Label prefix of a web connection window: `web-<connectionId>`.
pub const WEB_PREFIX: &str = "web-";

/// Who is calling, from the webview label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// The main window.
    Main,
    /// `detached-<sessionId>`: may act on that session only.
    Detached(String),
}

fn forbidden() -> IpcError {
    IpcError::new("ipc.forbidden", "this window cannot call this command")
}

/// The caller behind a webview label. `web-*` and unknown labels are refused.
pub fn caller(label: &str) -> IpcResult<Caller> {
    if label == MAIN_WINDOW {
        return Ok(Caller::Main);
    }
    match label.strip_prefix(DETACHED_PREFIX) {
        Some(id) if !id.is_empty() => Ok(Caller::Detached(id.to_owned())),
        _ => Err(forbidden()),
    }
}

/// The manifest row of `command`.
pub fn scope(command: &str) -> Option<Scope> {
    COMMANDS.iter().find(|(name, _)| *name == command).map(|(_, s)| *s)
}

/// Whether `label` may call `command` with `session_id` (the `sessionId` argument, if any).
/// Commands outside the manifest are left to the handler for `main` (it reports them
/// unknown) and refused for everyone else.
pub fn check(command: &str, label: &str, session_id: Option<&str>) -> IpcResult<Caller> {
    let who = caller(label)?;
    match (&who, scope(command)) {
        (Caller::Main, _) => Ok(who),
        (Caller::Detached(own), Some(Scope::Session)) if session_id == Some(own.as_str()) => {
            Ok(who)
        }
        _ => Err(forbidden()),
    }
}

/// The `sessionId` string argument of an invoke payload.
pub fn session_id_arg(body: &InvokeBody) -> Option<&str> {
    match body {
        InvokeBody::Json(Value::Object(args)) => args.get("sessionId").and_then(Value::as_str),
        _ => None,
    }
}

/// Wrap the generated command dispatcher: [`check`] first (refusals are answered here and
/// never reach a command), then the auto-lock activity hook (ADR-0010), then the command.
pub fn with_guard<R: Runtime>(
    handler: impl Fn(Invoke<R>) -> bool + Send + Sync + 'static,
) -> impl Fn(Invoke<R>) -> bool + Send + Sync + 'static {
    move |invoke| {
        let msg = &invoke.message;
        let verdict = check(msg.command(), msg.webview_ref().label(), session_id_arg(msg.payload()));
        if let Err(e) = verdict {
            // Command name and label only: arguments may carry secrets.
            tracing::warn!(command = msg.command(), window = msg.webview_ref().label(), "ipc refused");
            invoke.resolver.reject(e);
            return true;
        }
        crate::autolock::on_invoke(&invoke);
        handler(invoke)
    }
}

/// `{ command: [window patterns] }` as checked in at `src-tauri/ipc-manifest.json`.
pub fn manifest_json() -> Value {
    let rows: serde_json::Map<String, Value> = COMMANDS
        .iter()
        .map(|(name, scope)| {
            let windows: &[&str] = match scope {
                Scope::Main => &["main"],
                Scope::Session => &["main", "detached-<sessionId>"],
            };
            ((*name).to_owned(), Value::from(windows.to_vec()))
        })
        .collect();
    Value::Object(rows)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod capability_tests;
