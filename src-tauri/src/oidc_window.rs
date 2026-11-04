//! ADR-0016 §4: OIDC sign-in in an isolated window `oidc-<sourceId>`.
//!
//! The window is built like an A2 web window (ADR-0013 builder settings) with an **empty**
//! capability (`capabilities/oidc.json`), ephemeral storage and no downloads, pop-ups or
//! permissions. `on_navigation` calls [`navigate`]: the `IdP` origin of `auth_url` and the
//! source's `allowedOrigins` load; a navigation to the fixed redirect URI
//! (`http://localhost:8250/oidc/callback`) is **intercepted** — refused, the window closed, and
//! `code` + `state` exchanged by Rust (no loopback listener exists); anything else is refused
//! and audited. The window never sees a Mooring command or the Vault token.
//!
//! The UI polls `secret_source_oidc_status({ sessionId })`: `pending` → `done` | `failed`.
//!
//! Review 6 L-33: storage is [`storage`] — `incognito(true)` everywhere and, on Windows, an
//! own `WebView2` profile `<cache>/web-ephemeral/oidc-<sourceId>` (removed on `Destroyed`,
//! swept at start like the web windows' profiles), so `IdP` cookies never outlive one sign-in
//! or reach another source; the init script runs in every frame.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use mooring_core::secret_source::SecretSource;
use mooring_secrets::{parse_callback, Navigation, OidcFlow, OIDC_TIMEOUT};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{IpcError, IpcResult};
use crate::secrets_runtime::{ipc_error, SecretsRuntime};
use crate::state::AppState;
use crate::web::{self, Storage, StorageOs};

/// Label prefix of an OIDC window.
pub const OIDC_PREFIX: &str = "oidc-";

/// Storage of the OIDC window of `source_id` on `os` (L-33): ephemeral, with an own profile
/// directory `<cache>/web-ephemeral/oidc-<sourceId>` on Windows. The `oidc-` name cannot
/// collide with a web connection's UUID directory and is swept at start with them.
pub fn storage(state: &AppState, source_id: &str, os: StorageOs) -> Storage {
    web::ephemeral_storage(state, &format!("{OIDC_PREFIX}{source_id}"), os)
}
/// Finished flows kept for `secret_source_oidc_status`.
const MAX_FINISHED: usize = 32;

/// Opens and closes the OIDC windows (Tauri in the app, a recorder in tests).
pub trait OidcWindows: Send + Sync {
    /// Open `label` at `url`; its `on_navigation` must call [`navigate`] with `session`.
    fn open(&self, label: &str, url: &str, session: &str) -> Result<(), String>;
    /// Close `label` (idempotent).
    fn close(&self, label: &str);
    /// Bring `label` to the front.
    fn focus(&self, label: &str);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Waiting for the redirect.
    Pending,
    /// Redirect intercepted; the code exchange is running.
    Exchanging,
    Done,
    Failed(String),
}

struct Session {
    source: SecretSource,
    label: String,
    flow: Option<OidcFlow>,
    phase: Phase,
    started: Duration,
}

/// `secret_source_oidc_status` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcStatus {
    /// `pending` | `done` | `failed`.
    pub state: &'static str,
    /// The source.
    pub source_id: String,
    /// Why it failed: `timeout`, `closed`, `locked`, `state_mismatch`, `superseded`, or a
    /// `credential.external_unavailable` category (`auth_failed`, `network`, `tls`, …).
    pub error: Option<String>,
}

/// The flows of this process.
#[derive(Default)]
pub struct OidcSessions {
    map: Mutex<HashMap<String, Session>>,
    windows: Mutex<Option<Arc<dyn OidcWindows>>>,
}

impl std::fmt::Debug for OidcSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSessions").field("flows", &lock(&self.map).len()).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OidcSessions {
    /// Install the window backend.
    pub fn set_windows(&self, w: Arc<dyn OidcWindows>) {
        *lock(&self.windows) = Some(w);
    }

    fn windows(&self) -> Option<Arc<dyn OidcWindows>> {
        lock(&self.windows).clone()
    }

    fn close(&self, labels: Vec<String>) {
        if let Some(w) = self.windows() {
            for l in labels {
                w.close(&l);
            }
        }
    }

    /// Fail every open flow (lock, exit) and close its window.
    pub fn fail_all(&self, rt: &SecretsRuntime, reason: &str) {
        let mut labels = Vec::new();
        for s in lock(&self.map).values_mut() {
            if matches!(s.phase, Phase::Pending | Phase::Exchanging) {
                s.phase = Phase::Failed(reason.to_owned());
                s.flow = None;
                labels.push(s.label.clone());
                rt.refused(Some(s.source.id.to_string()), "oidc", reason);
            }
        }
        self.close(labels);
    }

    /// Number of flows still waiting (tests).
    pub fn pending(&self) -> usize {
        lock(&self.map).values().filter(|s| s.phase == Phase::Pending).count()
    }

    /// Expire a pending flow past [`OIDC_TIMEOUT`]; returns the label to close.
    fn expire(rt: &SecretsRuntime, s: &mut Session) -> Option<String> {
        let now = rt.engine().cache().clock().now();
        if s.phase == Phase::Pending && now.saturating_sub(s.started) > OIDC_TIMEOUT {
            s.phase = Phase::Failed("timeout".into());
            s.flow = None;
            rt.refused(Some(s.source.id.to_string()), "oidc", "timeout");
            return Some(s.label.clone());
        }
        None
    }
}

/// `secret_source_oidc_begin`: ask Vault for `auth_url`, open the window, return the session
/// id. A flow already waiting for the same source is focused and its id returned.
pub async fn begin(rt: &Arc<SecretsRuntime>, source: SecretSource) -> IpcResult<String> {
    let label = format!("{OIDC_PREFIX}{}", source.id);
    let windows = rt.oidc.windows().ok_or_else(|| IpcError::new("window.failed", "no window backend"))?;
    let mut stale = Vec::new();
    {
        let mut map = lock(&rt.oidc.map);
        for (id, s) in map.iter_mut() {
            if s.source.id != source.id {
                continue;
            }
            stale.extend(OidcSessions::expire(rt, s));
            if s.phase == Phase::Pending {
                windows.focus(&label);
                return Ok(id.clone());
            }
        }
    }
    rt.oidc.close(stale);
    let cache = Arc::clone(rt.engine().cache());
    let epoch = cache.epoch();
    let flow = rt.engine().begin_oidc(&source).await.map_err(|e| ipc_error(&e))?;
    // L-34: the vault locked while Vault was asked for the auth URL: no window over the lock
    // screen.
    if cache.epoch() != epoch {
        rt.refused(Some(source.id.to_string()), "oidc", "locked");
        return Err(IpcError::locked());
    }
    let url = Zeroizing::new(flow.auth_url.clone());
    let session = uuid::Uuid::new_v4().to_string();
    let started = cache.clock().now();
    {
        let mut map = lock(&rt.oidc.map);
        if map.len() >= MAX_FINISHED {
            map.retain(|_, s| matches!(s.phase, Phase::Pending | Phase::Exchanging));
        }
        let s = Session { source: source.clone(), label: label.clone(), flow: Some(flow), phase: Phase::Pending, started };
        map.insert(session.clone(), s);
    }
    if let Err(e) = windows.open(&label, &url, &session) {
        tracing::warn!(error = %e, "oidc window failed");
        lock(&rt.oidc.map).remove(&session);
        rt.refused(Some(source.id.to_string()), "oidc", "window.failed");
        return Err(IpcError::new("window.failed", "the sign-in window could not be opened"));
    }
    // L-34: a lock that raced the open: `fail_all` may have run before the session existed.
    if cache.epoch() != epoch {
        if let Some(s) = lock(&rt.oidc.map).get_mut(&session) {
            if s.phase == Phase::Pending {
                s.phase = Phase::Failed("locked".into());
                s.flow = None;
                rt.refused(Some(source.id.to_string()), "oidc", "locked");
            }
        }
        windows.close(&label);
        return Err(IpcError::locked());
    }
    let weak = Arc::downgrade(rt);
    let id = session.clone();
    let timer = async move {
        tokio::time::sleep(OIDC_TIMEOUT + Duration::from_secs(1)).await;
        if let Some(rt) = weak.upgrade() {
            let _ = status(&rt, &id);
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => drop(h.spawn(timer)),
        Err(_) => drop(tauri::async_runtime::spawn(timer)),
    }
    Ok(session)
}

/// `secret_source_oidc_status` (passive).
pub fn status(rt: &SecretsRuntime, session: &str) -> IpcResult<OidcStatus> {
    let (out, close) = {
        let mut map = lock(&rt.oidc.map);
        let s = map.get_mut(session).ok_or_else(|| IpcError::new("session.not_found", "no such sign-in"))?;
        let close = OidcSessions::expire(rt, s);
        let (state, error) = match &s.phase {
            Phase::Pending | Phase::Exchanging => ("pending", None),
            Phase::Done => ("done", None),
            Phase::Failed(r) => ("failed", Some(r.clone())),
        };
        (OidcStatus { state, source_id: s.source.id.to_string(), error }, close)
    };
    rt.oidc.close(close.into_iter().collect());
    Ok(out)
}

/// `scheme://host[:port]` of a navigation, for the audit (never the path or query).
fn origin_of(url: &str) -> String {
    tauri::Url::parse(url).map_or_else(|_| "invalid".to_owned(), |u| crate::web::policy::display_origin(&u))
}

/// The `on_navigation` decision: `true` loads the URL. The redirect is never loaded.
pub fn navigate(rt: &Arc<SecretsRuntime>, session: &str, url: &str) -> bool {
    let mut close: Option<String>;
    let mut exchange = None;
    let allow = {
        let mut map = lock(&rt.oidc.map);
        let Some(s) = map.get_mut(session) else { return false };
        close = OidcSessions::expire(rt, s);
        let source = s.source.id.to_string();
        match (s.phase.clone(), s.flow.as_ref().map(|f| f.navigation(url))) {
            (Phase::Pending, Some(Navigation::Allow)) => true,
            (Phase::Pending, Some(Navigation::Callback { .. })) => {
                s.phase = Phase::Exchanging;
                exchange = s.flow.take().map(|f| (s.source.clone(), f));
                close = Some(s.label.clone());
                false
            }
            (Phase::Pending, Some(Navigation::Deny)) if parse_callback(url).is_some() => {
                // The redirect with a foreign state or an IdP error: the flow is over.
                s.phase = Phase::Failed("state_mismatch".into());
                s.flow = None;
                close = Some(s.label.clone());
                rt.refused(Some(source), "oidc_navigation", "state_mismatch");
                false
            }
            _ => {
                rt.refused(Some(source), "oidc_navigation", &origin_of(url));
                false
            }
        }
    };
    if let Some((source, flow)) = exchange {
        let url = Zeroizing::new(url.to_owned());
        let rt2 = Arc::clone(rt);
        let id = session.to_owned();
        rt.spawn(async move {
            let r = rt2.engine().complete_oidc(&source, flow, &url).await;
            let phase = match r {
                Ok(()) => Phase::Done,
                Err(e) => Phase::Failed(e.category().as_str().to_owned()),
            };
            if let Some(s) = lock(&rt2.oidc.map).get_mut(&id) {
                if s.phase == Phase::Exchanging {
                    s.phase = phase;
                }
            }
        });
    }
    rt.oidc.close(close.into_iter().collect());
    allow
}

/// The window was destroyed (user closed it): a flow still waiting fails with `closed`.
pub fn window_destroyed(rt: &SecretsRuntime, session: &str) {
    if let Some(s) = lock(&rt.oidc.map).get_mut(session) {
        if s.phase == Phase::Pending {
            s.phase = Phase::Failed("closed".into());
            s.flow = None;
            rt.refused(Some(s.source.id.to_string()), "oidc", "closed");
        }
    }
}

// --- Tauri backend -------------------------------------------------------------------------

/// OIDC windows through Tauri (ADR-0013 builder settings, empty capability).
pub struct TauriOidcWindows<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
    rt: Weak<SecretsRuntime>,
}

impl<R: tauri::Runtime> std::fmt::Debug for TauriOidcWindows<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TauriOidcWindows").finish_non_exhaustive()
    }
}

impl<R: tauri::Runtime> OidcWindows for TauriOidcWindows<R> {
    fn open(&self, label: &str, url: &str, session: &str) -> Result<(), String> {
        use tauri::webview::{NewWindowResponse, PermissionResponse};
        use tauri::{WebviewUrl, WebviewWindowBuilder, WindowEvent};
        use tauri::Manager;
        let url = tauri::Url::parse(url).map_err(|_| "auth_url is not a URL".to_owned())?;
        let (nav_rt, nav_s) = (self.rt.clone(), session.to_owned());
        let source_id = label.strip_prefix(OIDC_PREFIX).unwrap_or(label);
        let storage = self
            .app
            .try_state::<AppState>()
            .map_or(Storage::Ephemeral, |st| storage(&st, source_id, StorageOs::current()));
        let mut builder = WebviewWindowBuilder::new(&self.app, label, WebviewUrl::External(url))
            .title("Mooring · Vault sign-in")
            .inner_size(560.0, 760.0)
            .devtools(false)
            .zoom_hotkeys_enabled(false)
            .general_autofill_enabled(false)
            .incognito(true)
            .initialization_script_for_all_frames(crate::web::window::INIT_SCRIPT);
        // L-33: an own WebView2 environment on Windows (as `web::window::build` does).
        if let Some(dir) = storage.ephemeral_dir() {
            builder = builder.data_directory(dir.clone());
        }
        let window = builder
            .on_navigation(move |u| nav_rt.upgrade().is_some_and(|rt| navigate(&rt, &nav_s, u.as_str())))
            .on_new_window(|_, _| NewWindowResponse::Deny)
            .on_download(|_, _| false)
            .on_permission_request(|_, _| PermissionResponse::Deny)
            .build()
            .map_err(|e| e.to_string())?;
        let (rt, s) = (self.rt.clone(), session.to_owned());
        let profile = storage.ephemeral_dir().cloned();
        window.on_window_event(move |e| {
            if matches!(e, WindowEvent::Destroyed) {
                if let Some(rt) = rt.upgrade() {
                    window_destroyed(&rt, &s);
                }
                if let Some(dir) = &profile {
                    web::remove_ephemeral_dir(dir);
                }
            }
        });
        Ok(())
    }

    fn close(&self, label: &str) {
        use tauri::Manager;
        if let Some(w) = self.app.get_webview_window(label) {
            let _ = w.close();
        }
    }

    fn focus(&self, label: &str) {
        use tauri::Manager;
        if let Some(w) = self.app.get_webview_window(label) {
            let _ = w.set_focus();
        }
    }
}

/// Setup hook: the Tauri window backend and the token renewer.
pub fn install<R: tauri::Runtime>(app: &tauri::App<R>) {
    use tauri::Manager;
    let rt = Arc::clone(&app.state::<crate::state::AppState>().secrets);
    rt.oidc.set_windows(Arc::new(TauriOidcWindows { app: app.handle().clone(), rt: Arc::downgrade(&rt) }));
    tauri::async_runtime::spawn(async move { rt.ensure_renewer() });
}
