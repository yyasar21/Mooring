//! `autolock_get` / `autolock_set` (ADR-0010 §Auto-lock). The policy is persisted as JSON under
//! `app.autolock` in the store's `setting` table and loaded at startup.

use std::time::Duration;

use mooring_audit::AuditEvent;
use mooring_vault::AutoLockPolicy;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::autolock::AutoLock;
use crate::error::{IpcError, IpcResult};
use crate::state::AppState;

/// Setting key.
pub const KEY: &str = "app.autolock";
/// Largest idle timeout (24 h).
pub const MAX_IDLE_MINUTES: i64 = 1440;

/// Wire shape: `{ idleMinutes: number|null, onScreenLock, onSleep, onWindowHidden }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutoLockPolicyDto {
    /// 1..=1440, or `null` to disable the idle trigger. `i64` so out-of-range numbers reach
    /// validation instead of failing deserialisation with an untyped error.
    pub idle_minutes: Option<i64>,
    /// Lock on OS screen lock.
    pub on_screen_lock: bool,
    /// Lock on OS sleep.
    pub on_sleep: bool,
    /// Lock when the main window loses focus.
    pub on_window_hidden: bool,
}

impl From<AutoLockPolicy> for AutoLockPolicyDto {
    fn from(p: AutoLockPolicy) -> Self {
        Self {
            idle_minutes: p.idle.map(|d| i64::try_from(d.as_secs() / 60).unwrap_or(MAX_IDLE_MINUTES)),
            on_screen_lock: p.on_screen_lock,
            on_sleep: p.on_sleep,
            on_window_hidden: p.on_window_hidden,
        }
    }
}

impl AutoLockPolicyDto {
    /// Validate and convert.
    pub fn to_policy(self) -> IpcResult<AutoLockPolicy> {
        let idle = match self.idle_minutes {
            None => None,
            Some(m @ 1..=MAX_IDLE_MINUTES) => {
                Some(Duration::from_secs(u64::try_from(m).unwrap_or(1) * 60))
            }
            Some(_) => return Err(IpcError::invalid("idleMinutes", "must be 1..=1440 or null")),
        };
        Ok(AutoLockPolicy {
            idle,
            on_screen_lock: self.on_screen_lock,
            on_sleep: self.on_sleep,
            on_window_hidden: self.on_window_hidden,
        })
    }
}

/// The persisted policy, or the ADR-0006 default when none is stored or the stored value is
/// unreadable (logged; never fails startup).
pub fn load_policy(state: &AppState) -> AutoLockPolicy {
    let raw = match state.store.lock() {
        Ok(slot) => slot.store.as_ref().map(|s| s.app_setting(KEY)),
        Err(_) => None,
    };
    match raw {
        Some(Ok(Some(json))) => serde_json::from_str::<AutoLockPolicyDto>(&json)
            .ok()
            .and_then(|d| d.to_policy().ok())
            .unwrap_or_else(|| {
                tracing::warn!("stored auto-lock policy unreadable; using the default");
                AutoLockPolicy::default()
            }),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "auto-lock policy could not be read; using the default");
            AutoLockPolicy::default()
        }
        _ => AutoLockPolicy::default(),
    }
}

/// Current policy. Allowed while locked (it is not inventory).
pub fn get(al: &AutoLock) -> AutoLockPolicyDto {
    al.policy().into()
}

/// Validate, persist, apply and audit a new policy. Requires an unlocked vault: weakening the
/// auto-lock must not be possible from a locked screen.
pub fn set(state: &AppState, al: &AutoLock, dto: AutoLockPolicyDto) -> IpcResult<AutoLockPolicyDto> {
    let policy = dto.to_policy()?;
    let canonical = AutoLockPolicyDto::from(policy);
    let json = serde_json::to_string(&canonical)
        .map_err(|_| IpcError::new("state.internal", "internal error"))?;
    state.with_ready(|_, store| Ok(store.set_app_setting(KEY, &json)?))?;
    al.set_policy(policy);
    state.audit(AuditEvent::VaultPolicyChanged {
        idle_minutes: canonical.idle_minutes.and_then(|m| u32::try_from(m).ok()),
        on_screen_lock: policy.on_screen_lock,
        on_sleep: policy.on_sleep,
        on_window_hidden: policy.on_window_hidden,
    });
    Ok(canonical)
}

// ------------------------------------------------------------------ Tauri wrappers

/// `autolock_get()`.
#[tauri::command]
pub fn autolock_get(al: State<'_, AutoLock>) -> AutoLockPolicyDto {
    get(&al)
}

/// `autolock_set({ policy })`.
#[tauri::command(rename_all = "camelCase")]
pub fn autolock_set(
    state: State<'_, AppState>,
    al: State<'_, AutoLock>,
    policy: AutoLockPolicyDto,
) -> IpcResult<AutoLockPolicyDto> {
    set(&state, &al, policy)
}

#[cfg(test)]
mod tests {
    use std::time::{Instant, SystemTime};

    use super::*;
    use crate::state::testing::*;

    fn dto(idle: Option<i64>) -> AutoLockPolicyDto {
        AutoLockPolicyDto {
            idle_minutes: idle,
            on_screen_lock: true,
            on_sleep: false,
            on_window_hidden: true,
        }
    }

    fn clock() -> AutoLock {
        AutoLock::new(AutoLockPolicy::default(), Instant::now(), SystemTime::now())
    }

    #[test]
    fn validation_table() {
        for (idle, ok) in [
            (None, true),
            (Some(1), true),
            (Some(15), true),
            (Some(1440), true),
            (Some(0), false),
            (Some(-1), false),
            (Some(1441), false),
            (Some(i64::MAX), false),
            (Some(i64::MIN), false),
        ] {
            let r = dto(idle).to_policy();
            assert_eq!(r.is_ok(), ok, "{idle:?}");
            if let Err(e) = r {
                assert_eq!(e.code, "input.invalid");
                assert!(e.message.contains("idleMinutes"));
            }
        }
    }

    #[test]
    fn wire_shape_and_unknown_fields() {
        let d: AutoLockPolicyDto = AutoLockPolicy::default().into();
        assert_eq!(
            serde_json::to_string(&d).expect("json"),
            r#"{"idleMinutes":15,"onScreenLock":true,"onSleep":true,"onWindowHidden":true}"#
        );
        let extra = r#"{"idleMinutes":5,"onScreenLock":true,"onSleep":true,"onWindowHidden":true,"x":1}"#;
        assert!(serde_json::from_str::<AutoLockPolicyDto>(extra).is_err());
        let null = r#"{"idleMinutes":null,"onScreenLock":false,"onSleep":false,"onWindowHidden":false}"#;
        assert_eq!(serde_json::from_str::<AutoLockPolicyDto>(null).expect("null").idle_minutes, None);
    }

    #[test]
    fn set_persists_applies_and_audits() {
        let f = unlocked();
        let al = clock();
        let out = set(&f.state, &al, dto(Some(5))).expect("set");
        assert_eq!(out, dto(Some(5)));
        assert_eq!(get(&al), dto(Some(5)));
        assert_eq!(load_policy(&f.state), dto(Some(5)).to_policy().expect("p"), "persisted");
        assert!(audit_events(&f.state).contains(&"vault_policy_changed".to_owned()));
        let audit =
            std::fs::read_to_string(f.dir.path().join(AppState::AUDIT_FILE)).expect("audit");
        assert!(audit.contains(r#""idle_minutes":5,"on_screen_lock":true,"on_sleep":false"#));
        set(&f.state, &al, dto(None)).expect("disable idle");
        assert_eq!(load_policy(&f.state).idle, None);
    }

    #[test]
    fn set_is_refused_while_locked_and_invalid_input_changes_nothing() {
        let f = unlocked();
        let al = clock();
        assert_eq!(set(&f.state, &al, dto(Some(0))).expect_err("range").code, "input.invalid");
        crate::commands::vault::lock(&f.state, None).expect("lock");
        assert_eq!(set(&f.state, &al, dto(None)).expect_err("locked").code, "vault.locked");
        assert_eq!(al.policy(), AutoLockPolicy::default(), "unchanged");
        assert_eq!(load_policy(&f.state), AutoLockPolicy::default(), "nothing stored");
        assert!(!audit_events(&f.state).contains(&"vault_policy_changed".to_owned()));
    }

    #[test]
    fn corrupt_stored_policy_falls_back_to_default() {
        let f = empty();
        for bad in ["not json", r#"{"idleMinutes":99999,"onScreenLock":true,"onSleep":true,"onWindowHidden":true}"#] {
            let slot = f.state.store.lock().expect("lock");
            slot.store.as_ref().expect("s").set_app_setting(KEY, bad).expect("write");
            drop(slot);
            assert_eq!(load_policy(&f.state), AutoLockPolicy::default(), "{bad}");
        }
    }
}
