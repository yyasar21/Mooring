//! ADR-0013: every `web-*` and `detached-*` window is hidden while the vault is locked and
//! shown again after unlock. Sessions survive a lock (ADR-0010), but an OS window outside the
//! lock screen would bypass it.

use std::sync::{Arc, Mutex};

use tauri::{App, Manager, Runtime};

use crate::guard::{DETACHED_PREFIX, WEB_PREFIX};

/// Whether a window label belongs to a web or detached window.
pub fn is_secondary(label: &str) -> bool {
    label.starts_with(WEB_PREFIX) || label.starts_with(DETACHED_PREFIX)
}

/// Called with `true` after a vault lock and `false` after an unlock.
pub type Observer = Arc<dyn Fn(bool) + Send + Sync>;

/// The lock hook held by `AppState` (`vault::lock` / `vault::unlock` call [`Self::notify`]).
#[derive(Default)]
pub struct LockObserver(Mutex<Option<Observer>>);

impl std::fmt::Debug for LockObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockObserver").finish_non_exhaustive()
    }
}

impl LockObserver {
    /// Install the hook.
    pub fn set(&self, observer: Observer) {
        if let Ok(mut g) = self.0.lock() {
            *g = Some(observer);
        }
    }

    /// Report a lock (`true`) or an unlock (`false`).
    pub fn notify(&self, locked: bool) {
        let hook = self.0.lock().ok().and_then(|g| g.clone());
        if let Some(h) = hook {
            h(locked);
        }
    }
}

/// Install the hook that hides / shows the secondary windows.
pub fn install<R: Runtime>(app: &App<R>) {
    let handle = app.handle().clone();
    let state = app.state::<crate::state::AppState>();
    state.lock_observer.set(Arc::new(move |locked| {
        for (label, window) in handle.webview_windows() {
            if !is_secondary(&label) {
                continue;
            }
            let done = if locked { window.hide() } else { window.show() };
            if let Err(e) = done {
                tracing::warn!(error = %e, locked, "secondary window visibility");
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use secrecy::SecretString;

    use super::*;
    use crate::commands::vault;
    use crate::state::testing::{unlocked, MASTER};

    #[test]
    fn secondary_labels() {
        for yes in ["web-0b1e", "detached-7f9c", "web-", "detached-"] {
            assert!(is_secondary(yes), "{yes}");
        }
        for no in ["main", "Main", "webx", "detached", "x-web-1", ""] {
            assert!(!is_secondary(no), "{no}");
        }
    }

    #[test]
    fn lock_hides_and_unlock_shows() {
        let f = unlocked();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&seen);
        f.state.lock_observer.set(Arc::new(move |locked| rec.lock().expect("m").push(locked)));
        vault::lock(&f.state, Some("idle")).expect("lock");
        let bad = vault::unlock(&f.state, SecretString::from("wrong password".to_owned()));
        assert!(bad.is_err());
        vault::unlock(&f.state, SecretString::from(MASTER.to_owned())).expect("unlock");
        assert_eq!(*seen.lock().expect("m"), [true, false], "a failed unlock shows nothing");
    }
}
