//! Move to Applications (ADR-0028 §2): the start-up flows. Elsewhere than macOS every entry
//! point is the plain behaviour (create the main window / show the M-18 refusal).
//!
//! * [`start_main`]: a normally started release process on a disk image or in Downloads gets
//!   the three-slot dialog **before** the main window exists (nothing can be unlocked while it
//!   is open). Move → copy, relaunch, exit 0; Not now → remembered for this version; Cancel →
//!   this run only. A failed move is a message box, then the window.
//! * [`translocated`]: the same dialog before the M-18 refusal; both refusing answers and a
//!   failed move end in that refusal (exit 2); nothing is remembered (no data dir here).
//! * [`after_relaunch`]: the copy started with `--mooring-moved` detaches the old disk image
//!   (validated: `/Volumes/<name>`, an image mount, our app, no vault) and audits
//!   `install.moved`.

use std::path::PathBuf;

use tauri::{AppHandle, Runtime};

use crate::startup::Refusal;
use crate::state::AppState;

/// Create the main window, or first offer the move (see the module doc).
pub fn start_main<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    webview_dir: Option<PathBuf>,
) -> tauri::Result<()> {
    #[cfg(target_os = "macos")]
    if macos::offer(app, state, webview_dir.clone()) {
        return Ok(());
    }
    let _ = state;
    crate::navigation::create_main_window(app, webview_dir)
}

/// A translocated launch: the dialog first (release builds), then the M-18 refusal.
pub fn translocated<R: Runtime>(app: &AppHandle<R>, refusal: &Refusal) {
    #[cfg(target_os = "macos")]
    if macos::offer_translocated(app, refusal) {
        return;
    }
    crate::startup::refuse(app, refusal);
}

/// In a copy relaunched by a move: detach the old image, audit `install.moved`.
pub fn after_relaunch<R: Runtime>(app: &AppHandle<R>) {
    #[cfg(target_os = "macos")]
    macos::after_relaunch(app);
    let _ = app;
}

// Compiled everywhere so Linux CI type-checks it; only macOS calls it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos {
    use std::path::{Path, PathBuf};

    use mooring_audit::AuditEvent;
    use tauri::{AppHandle, Manager, Runtime};
    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

    use crate::build_identity::Channel;
    use crate::install_location::{self as loc, Choice, Location, OfferFacts, Roots, Target, BUNDLE_NAME};
    use crate::install_move::{self as mv, OsTools};
    use crate::startup::Refusal;
    use crate::state::AppState;
    use crate::updater::install_mode::{cask_present_in, dir_writable, CASKROOMS, CASK_TOKEN};

    fn writable(p: &Path) -> bool {
        dir_writable(Some(p))
    }

    /// The running `.app` bundle, canonical.
    fn bundle() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?; // nosemgrep: locates the bundle only
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        crate::dirs::app_bundle(&exe).map(Path::to_path_buf)
    }

    fn moved_args() -> loc::MovedArgs {
        loc::parse_args(std::env::args_os().skip(1))
    }

    fn declined(state: &AppState) -> Option<String> {
        let slot = state.store.lock().ok()?;
        slot.store.as_ref()?.app_setting(loc::DECLINED_KEY).ok().flatten()
    }

    fn remember_decline(state: &AppState, version: &str) {
        let stored = state.store.lock().ok().and_then(|slot| slot.store.as_ref().map(|s| s.set_app_setting(loc::DECLINED_KEY, version)));
        if !matches!(stored, Some(Ok(()))) {
            tracing::warn!("install: the Not now answer was not stored");
        }
    }

    fn ask<R: Runtime>(app: &AppHandle<R>, text: String, then: impl FnOnce(Choice) + Send + 'static) {
        app.dialog()
            .message(text)
            .title(loc::DIALOG_TITLE)
            .kind(MessageDialogKind::Info)
            .buttons(loc::buttons())
            .show_with_result(move |r| then(loc::choice(&r)));
    }

    fn tell<R: Runtime>(app: &AppHandle<R>, e: loc::MoveError, then: impl FnOnce() + Send + 'static) {
        app.dialog()
            .message(e.message())
            .title("Mooring was not moved")
            .kind(MessageDialogKind::Warning)
            .show(move |_| then());
    }

    /// Text of the dialog for `location` (the target and an existing copy, read-only).
    fn text<R: Runtime>(app: &AppHandle<R>, location: &Location, home: &Path) -> String {
        let target = Target::choose(writable(&Target::Applications.dir(home)));
        let found = mv::existing(&OsTools, &target.dir(home).join(BUNDLE_NAME), &app.config().identifier);
        loc::dialog_text(location, target, &found)
    }

    /// Copy + relaunch on a worker thread; `Ok` after a successful `open`.
    fn move_and_relaunch<R: Runtime>(app: &AppHandle<R>, src: &Path, home: &Path, detach: Option<&Path>) -> Result<(), loc::MoveError> {
        let ours = app.package_info().version.clone();
        let moved = mv::perform(&OsTools, src, home, &app.config().identifier, &ours, &writable)?;
        mv::relaunch(&OsTools, &moved, detach)
    }

    /// Show the offer when it applies; `true` = the dialog owns the main window now.
    pub fn offer<R: Runtime>(app: &AppHandle<R>, state: &AppState, webview_dir: Option<PathBuf>) -> bool {
        let (Some(src), Ok(home)) = (bundle(), app.path().home_dir()) else { return false };
        let downloads = app.path().download_dir().ok().map(|d| std::fs::canonicalize(&d).unwrap_or(d));
        let roots = Roots::production(Some(&home), downloads);
        let mut location = loc::classify(&src, &roots);
        if matches!(location, Location::Volume(_)) {
            location = loc::confirm_image(location, &mv::image_mounts(&OsTools));
        }
        let version = app.package_info().version.to_string();
        let caskrooms: Vec<&Path> = CASKROOMS.iter().map(Path::new).collect();
        let declined = declined(state);
        let facts = OfferFacts {
            channel: state.settings.channel,
            location: &location,
            portable: state.portable_root.is_some(),
            moved: moved_args().moved,
            cask_present: cask_present_in(&caskrooms, CASK_TOKEN),
            declined: declined.as_deref(),
            version: &version,
        };
        if !loc::should_offer(&facts) {
            return false;
        }
        state.audit(AuditEvent::InstallMoveOffered { location: location.wire().to_owned() });
        let detach = match &location {
            Location::DiskImage(m) => Some(m.clone()),
            _ => None,
        };
        let handle = app.clone();
        ask(app, text(app, &location, &home), move |choice| {
            let open_window = move |h: &AppHandle<R>| {
                if let Err(e) = crate::navigation::create_main_window(h, webview_dir) {
                    tracing::error!(error = %e, "main window not created");
                    h.exit(1);
                }
            };
            let state = handle.state::<AppState>();
            match choice {
                Choice::Move => {
                    let h = handle.clone();
                    std::thread::spawn(move || match move_and_relaunch(&h, &src, &home, detach.as_deref()) {
                        Ok(()) => h.exit(0),
                        Err(e) => {
                            h.state::<AppState>().audit(AuditEvent::InstallMoveFailed { code: e.code().to_owned() });
                            let w = h.clone();
                            tell(&h, e, move || open_window(&w));
                        }
                    });
                }
                Choice::NotNow => {
                    remember_decline(&state, &version);
                    state.audit(AuditEvent::InstallMoveDeclined { remember: true });
                    open_window(&handle);
                }
                Choice::Cancel => {
                    state.audit(AuditEvent::InstallMoveDeclined { remember: false });
                    open_window(&handle);
                }
            }
        });
        true
    }

    /// The translocated dialog; `true` = it owns the refusal now.
    pub fn offer_translocated<R: Runtime>(app: &AppHandle<R>, refusal: &Refusal) -> bool {
        if refusal.code != "portable.translocated" || !loc::offer_translocated(Channel::CURRENT, moved_args().moved) {
            return false;
        }
        let (Some(src), Ok(home)) = (bundle(), app.path().home_dir()) else { return false };
        let (handle, refusal) = (app.clone(), refusal.clone());
        ask(app, text(app, &Location::Translocated, &home), move |choice| {
            if choice != Choice::Move {
                crate::startup::refuse(&handle, &refusal);
                return;
            }
            std::thread::spawn(move || match move_and_relaunch(&handle, &src, &home, None) {
                Ok(()) => handle.exit(0),
                Err(e) => {
                    let h = handle.clone();
                    tell(&handle, e, move || crate::startup::refuse(&h, &refusal));
                }
            });
        });
        true
    }

    /// Detach + `install.moved` in the relaunched copy (off the setup thread).
    pub fn after_relaunch<R: Runtime>(app: &AppHandle<R>) {
        let args = moved_args();
        if !args.moved {
            return;
        }
        let handle = app.clone();
        std::thread::spawn(move || {
            let id = handle.config().identifier.clone();
            let detached = args.detach.as_deref().is_some_and(|v| mv::detach_if_ours(&OsTools, v, &id));
            let home = handle.path().home_dir().ok();
            let target = bundle()
                .and_then(|b| Target::of_bundle(&b, home.as_deref()))
                .map_or("other", Target::wire);
            handle.state::<AppState>().audit(AuditEvent::InstallMoved {
                target: target.to_owned(),
                replaced: args.replaced,
                detached,
            });
        });
    }
}
