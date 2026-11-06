//! `update_check` / `update_install` / `update_settings_get` / `update_settings_set`
//! (ADR-0018 §3, A4 U0). All four are vault-gated (owner decision: nothing about updates runs
//! from the lock screen). Settings are JSON under `app.update` in the store's `setting` table.

use mooring_audit::AuditEvent;
use semver::Version;
use serde::{Deserialize, Serialize};
use tauri::State;
use time::OffsetDateTime;

use crate::dto::ts;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;
use crate::updater::install_mode::{InstallMode, ManualReason};
use crate::updater::source::RemoteUpdate;
use crate::updater::{notes, UpdateRuntime};

/// Setting key.
pub const KEY: &str = "app.update";
/// The only release channel in v0.1.
pub const CHANNEL: &str = "stable";
/// UI event carrying an [`UpdateInfo`] whose `available` is set (background check).
pub const AVAILABLE_EVENT: &str = "update:available";

/// Wire shape of `available`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableUpdate {
    /// Offered version (strictly newer than `current`).
    pub version: String,
    /// RFC 3339 publish date, if the manifest has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Sanitised plain-text notes (≤ 4 KiB; may be empty).
    pub notes: String,
    /// Asset size in bytes, if the manifest has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

impl From<&RemoteUpdate> for AvailableUpdate {
    fn from(r: &RemoteUpdate) -> Self {
        Self {
            version: r.version.to_string(),
            date: r.date.clone(),
            notes: notes::sanitise(r.notes.as_deref().unwrap_or_default()),
            size: r.size,
        }
    }
}

/// `update_check()` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// Running version.
    pub current: String,
    /// Newer release, or `null`.
    pub available: Option<AvailableUpdate>,
    /// `in_app` | `manual`.
    pub install_mode: &'static str,
    /// Set when `installMode` is `manual`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_reason: Option<ManualReason>,
    /// RFC 3339 time of this check.
    pub checked_at: String,
}

/// `update_settings_get()` result / stored shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateSettings {
    /// Opt-in background check (once ≥ 60 s after start, then at most once per 24 h).
    pub background_check: bool,
    /// Release channel; only `stable` exists.
    pub channel: String,
    /// RFC 3339 time of the last network check (manual or background).
    pub last_check: Option<String>,
    /// Review 7 L-39: the highest version whose package this install verified (signature
    /// and signed version) — the floor below which no later offer is accepted
    /// (`update.downgrade`), so a manifest cannot walk the user back to an older signed
    /// release after a failed or reverted install.
    pub last_verified: Option<String>,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self { background_check: false, channel: CHANNEL.to_owned(), last_check: None, last_verified: None }
    }
}

impl UpdateSettings {
    /// The stored floor as a version (an unparsable value is ignored, not trusted).
    fn verified_floor(&self) -> Option<Version> {
        self.last_verified.as_deref().and_then(|v| Version::parse(v).ok())
    }
}

/// `update_settings_set` input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSettingsInput {
    /// Background check on or off.
    pub background_check: bool,
    /// Must be `stable` when given.
    #[serde(default)]
    pub channel: Option<String>,
}

/// `update_install` input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallInput {
    /// The version shown by the last check; the install re-checks and refuses any other.
    pub version: String,
    /// Close every open session first (otherwise `update.sessions_open`).
    #[serde(default)]
    pub close_sessions: bool,
}

// ------------------------------------------------------------------ settings

/// The stored settings, or the default when none are stored or the row is unreadable. Not
/// gated: the background loop reads it at start (like the auto-lock policy).
pub fn stored(state: &AppState) -> UpdateSettings {
    let raw = match state.store.lock() {
        Ok(slot) => slot.store.as_ref().map(|s| s.app_setting(KEY)),
        Err(_) => None,
    };
    match raw {
        Some(Ok(Some(json))) => serde_json::from_str::<UpdateSettings>(&json).unwrap_or_else(|_| {
            tracing::warn!("stored update settings unreadable; using the default");
            UpdateSettings::default()
        }),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "update settings could not be read; using the default");
            UpdateSettings::default()
        }
        _ => UpdateSettings::default(),
    }
}

fn store(state: &AppState, settings: &UpdateSettings) -> IpcResult<()> {
    let json = serde_json::to_string(settings)
        .map_err(|_| IpcError::new("state.internal", "internal error"))?;
    state.with_ready(|_, store| Ok(store.set_app_setting(KEY, &json)?))
}

/// L-39: refuse an offer below the verified floor (`update.downgrade`, audited as a refusal).
/// The running version is checked separately (`is_newer`); this guards the window in which
/// `current < last_verified` (an install that failed after verification, a manual downgrade).
fn check_floor(state: &AppState, offered: &Version) -> IpcResult<()> {
    if stored(state).verified_floor().is_some_and(|floor| *offered < floor) {
        return Err(refused(state, "update.downgrade", "older than a release this install already verified"));
    }
    Ok(())
}

/// L-39: raise the verified floor to `version` once its package verified. Runs from the
/// source's `before_install` hook with the store handle only (the state is not `'static`).
pub(crate) fn raise_floor(store_slot: &std::sync::Mutex<crate::state::StoreSlot>, version: &Version) {
    let Ok(slot) = store_slot.lock() else { return };
    let Some(store) = slot.store.as_ref() else { return };
    let mut settings = match store.app_setting(KEY) {
        Ok(Some(json)) => serde_json::from_str::<UpdateSettings>(&json).unwrap_or_default(),
        _ => UpdateSettings::default(),
    };
    if settings.verified_floor().is_some_and(|floor| floor >= *version) {
        return;
    }
    settings.last_verified = Some(version.to_string());
    match serde_json::to_string(&settings) {
        Ok(json) => {
            if let Err(e) = store.set_app_setting(KEY, &json) {
                tracing::warn!(error = %e, "update floor not stored");
            }
        }
        Err(_) => tracing::warn!("update floor not stored"),
    }
}

/// `update_settings_get()`.
pub fn settings_get(state: &AppState) -> IpcResult<UpdateSettings> {
    state.with_ready(|_, _| Ok(()))?;
    Ok(stored(state))
}

/// `update_settings_set({ backgroundCheck, channel? })`: validate, persist, audit.
pub fn settings_set(state: &AppState, input: UpdateSettingsInput) -> IpcResult<UpdateSettings> {
    if input.channel.as_deref().is_some_and(|c| c != CHANNEL) {
        return Err(IpcError::invalid("channel", "only `stable` exists"));
    }
    state.with_ready(|_, _| Ok(()))?;
    let mut settings = stored(state);
    let changed = settings.background_check != input.background_check;
    settings.background_check = input.background_check;
    CHANNEL.clone_into(&mut settings.channel);
    store(state, &settings)?;
    if changed {
        state.audit(AuditEvent::UpdateSettingsChanged { background_check: settings.background_check });
    }
    Ok(settings)
}

// ------------------------------------------------------------------ check

/// `update_check()`. `manual` enforces the 60 s gap; the background loop passes `false`
/// (its 24 h schedule is the gap). Nothing is downloaded.
pub async fn check(
    state: &AppState,
    rt: &UpdateRuntime,
    now: std::time::Instant,
    manual: bool,
) -> IpcResult<UpdateInfo> {
    state.with_ready(|_, _| Ok(()))?;
    let source = rt.source()?;
    let _flight = rt.begin_check(now, manual)?;
    let offered = source.check().await.map_err(|e| IpcError::new(e.code(), e.message()))?;
    // Downgrades and re-offers of the running version are "nothing new" (ADR-0018 §3).
    let offered = offered.filter(|r| rt.is_newer(&r.version));
    if let Some(r) = &offered {
        check_floor(state, &r.version)?;
    }
    let available = offered.as_ref().map(AvailableUpdate::from);
    rt.set_last_available(offered);
    let checked_at = ts(OffsetDateTime::now_utc());
    let mut settings = stored(state);
    settings.last_check = Some(checked_at.clone());
    store(state, &settings)?;
    state.audit(AuditEvent::UpdateCheck {
        current: rt.current().to_string(),
        available: available.as_ref().map(|a| a.version.clone()),
    });
    let (install_mode, manual_reason) = match rt.install_mode() {
        InstallMode::InApp => ("in_app", None),
        InstallMode::Manual(r) => ("manual", Some(r)),
    };
    Ok(UpdateInfo {
        current: rt.current().to_string(),
        available,
        install_mode,
        manual_reason,
        checked_at,
    })
}

// ------------------------------------------------------------------ install

fn refused(state: &AppState, code: &'static str, message: &str) -> IpcError {
    state.audit(AuditEvent::UpdateRefused { code: code.to_owned() });
    IpcError::new(code, message)
}

/// `update_install({ version, closeSessions })`: the matrix, the sessions, the single flight,
/// then the source re-checks, verifies and installs exactly `version` and restarts the app.
pub async fn install(
    state: &AppState,
    rt: &UpdateRuntime,
    now: std::time::Instant,
    input: InstallInput,
) -> IpcResult<()> {
    state.with_ready(|_, _| Ok(()))?;
    let source = rt.source()?;
    let version =
        Version::parse(input.version.trim()).map_err(|_| IpcError::invalid("version", "not semver"))?;
    if !rt.is_newer(&version) {
        return Err(refused(state, "update.none", "not newer than the running version"));
    }
    check_floor(state, &version)?;
    if let InstallMode::Manual(reason) = rt.install_mode() {
        return Err(refused(state, reason.code(), reason.message()));
    }
    let open: Vec<String> = state
        .sessions
        .lock()
        .map_err(|_| IpcError::poisoned())?
        .keys()
        .cloned()
        .collect();
    if !open.is_empty() {
        if !input.close_sessions {
            return Err(refused(state, "update.sessions_open", "close the open sessions first"));
        }
        for id in open {
            // A session that is already gone is fine; the registry is re-read below.
            let _ = crate::commands::sessions::close(state, &id).await;
        }
    }
    let _flight = rt.begin_install(now)?;
    let from = rt.current().to_string();
    let to = version.to_string();
    let audit = state.audit.clone();
    let store_slot = state.store.clone();
    let verified = version.clone();
    let before_install: crate::updater::source::BeforeInstall = Box::new(move || {
        // The package verified (signature + signed version): raise the floor, then the row.
        raise_floor(&store_slot, &verified);
        crate::state::record_audit(&audit, AuditEvent::UpdateInstall { from, to });
    });
    source.install(&version, before_install).await.map_err(|e| {
        tracing::warn!(code = e.code(), "update install failed");
        refused(state, e.code(), e.message())
    })
}

// ------------------------------------------------------------------ Tauri wrappers

/// `update_check()`.
#[tauri::command]
pub async fn update_check(
    state: State<'_, AppState>,
    rt: State<'_, UpdateRuntime>,
) -> IpcResult<UpdateInfo> {
    check(&state, &rt, std::time::Instant::now(), true).await
}

/// `update_install({ version, closeSessions })`.
#[tauri::command(rename_all = "camelCase")]
pub async fn update_install(
    state: State<'_, AppState>,
    rt: State<'_, UpdateRuntime>,
    version: String,
    close_sessions: Option<bool>,
) -> IpcResult<()> {
    let input = InstallInput { version, close_sessions: close_sessions.unwrap_or(false) };
    install(&state, &rt, std::time::Instant::now(), input).await
}

/// `update_settings_get()`.
#[tauri::command]
pub fn update_settings_get(state: State<'_, AppState>) -> IpcResult<UpdateSettings> {
    settings_get(&state)
}

/// `update_settings_set({ backgroundCheck, channel? })`.
#[tauri::command(rename_all = "camelCase")]
pub fn update_settings_set(
    state: State<'_, AppState>,
    background_check: bool,
    channel: Option<String>,
) -> IpcResult<UpdateSettings> {
    settings_set(&state, UpdateSettingsInput { background_check, channel })
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
