//! A4.1 Q1 (ADR-0021 §Test plan): the hostile resolver cases the implementers did not write —
//! FIFO / socket markers, pre-existing world-writable subdirs, `..` and trailing-slash exe
//! paths, non-UTF-8 and very long paths, nested `.app` bundles, a bogus `$APPIMAGE`, two
//! threads resolving the same folder at once. Helpers come from [`crate::a4_1_portable`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::a4_1_portable::{mode_of, never_os, portable_app, probe, tree_of};
use crate::commands::vault;
use crate::dirs::{Dirs, DirsError};
use crate::state::testing;
use crate::state::AppState;

// ------------------------------------------------------- hostile resolver

#[cfg(unix)]
#[test]
fn fifo_and_socket_markers_are_invalid_not_absent() {
    let tmp = tempfile::tempdir().expect("tmp");
    // FIFO
    let app = tmp.path().join("fifo");
    std::fs::create_dir_all(&app).expect("mkdir");
    let exe = app.join("mooring");
    std::fs::write(&exe, b"").expect("exe");
    let status =
        std::process::Command::new("mkfifo").arg(app.join(Dirs::MARKER)).status().expect("mkfifo");
    assert!(status.success());
    let e = Dirs::resolve(&exe, None, &never_os, &probe).expect_err("fifo");
    assert!(matches!(&e, DirsError::MarkerInvalid(p) if *p == app.join(Dirs::MARKER)), "{e:?}");
    assert_eq!(e.code(), "portable.marker_invalid");
    assert!(!app.join(Dirs::ROOT).exists(), "nothing created next to a FIFO marker");
    // Unix socket (short path: sun_path is limited).
    let app = tmp.path().join("sock");
    std::fs::create_dir_all(&app).expect("mkdir");
    let exe = app.join("mooring");
    std::fs::write(&exe, b"").expect("exe");
    let _listener = std::os::unix::net::UnixListener::bind(app.join(Dirs::MARKER)).expect("socket");
    let e = Dirs::resolve(&exe, None, &never_os, &probe).expect_err("socket");
    assert_eq!(e.code(), "portable.marker_invalid");
    assert!(!app.join(Dirs::ROOT).exists());
    // A FIFO where `Mooring Data` should be is a bad data dir, not a marker problem.
    let app = tmp.path().join("fifo-root");
    let exe = portable_app(&app);
    let status =
        std::process::Command::new("mkfifo").arg(app.join(Dirs::ROOT)).status().expect("mkfifo");
    assert!(status.success());
    let e = Dirs::resolve(&exe, None, &never_os, &probe).expect_err("fifo root");
    assert!(matches!(&e, DirsError::DataDirInvalid(p) if *p == app.join(Dirs::ROOT)), "{e:?}");
    assert_eq!(e.code(), "portable.data_dir_invalid");
}

#[test]
fn file_named_mooring_data_is_refused_and_left_alone() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = portable_app(&app);
    std::fs::write(app.join(Dirs::ROOT), b"keep me").expect("file");
    let e = Dirs::resolve(&exe, None, &never_os, &probe).expect_err("file root");
    assert_eq!(e.code(), "portable.data_dir_invalid");
    assert_eq!(std::fs::read(app.join(Dirs::ROOT)).expect("still a file"), b"keep me");
}

#[cfg(unix)]
#[test]
fn pre_existing_world_writable_dirs_are_tightened_to_0700() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = portable_app(&app);
    let root = app.join(Dirs::ROOT);
    for d in [root.clone(), root.join("data"), root.join("cache")] {
        std::fs::create_dir_all(&d).expect("mkdir");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        assert_eq!(mode_of(&d), 0o777, "precondition");
    }
    let d = Dirs::resolve(&exe, None, &never_os, &probe).expect("resolve");
    for p in [&root, &d.data, &d.cache] {
        assert_eq!(mode_of(p), 0o700, "{} tightened", p.display());
    }
}

/// ADR-0021 §1 refuses a linked **root** so the data cannot be redirected; a linked `data`
/// or `cache` subdir inside a genuine root redirects it just the same (the resolver only
/// `create_dir_all`s and chmods through the link). BUG a4-1-qa-1: run with `--ignored`; the
/// test asserts the ADR's intent (refused, nothing written through the link) and fails today.
#[cfg(unix)]
#[test]
#[ignore = "BUG a4-1-qa-1: a symlinked `Mooring Data/data` is followed, not refused (rust-core)"]
fn symlinked_data_subdir_is_refused_like_the_root() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = portable_app(&app);
    let root = app.join(Dirs::ROOT);
    std::fs::create_dir_all(&root).expect("root");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("mkdir");
    std::os::unix::fs::symlink(&elsewhere, root.join("data")).expect("symlink");
    let r = Dirs::resolve(&exe, None, &never_os, &probe);
    assert!(matches!(&r, Err(DirsError::DataDirInvalid(_))), "linked data subdir accepted: {r:?}");
    assert_eq!(mode_of(&elsewhere), 0o755, "chmod went through the link");
}

#[test]
fn dot_dot_components_and_trailing_slash_resolve_to_the_same_folder() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    portable_app(&app);
    let dotted = tmp.path().join("app").join("..").join("app").join(".").join("mooring");
    let d = Dirs::resolve(&dotted, None, &never_os, &probe).expect("dotted");
    let canon = |p: &Path| std::fs::canonicalize(p).expect("canon");
    assert_eq!(canon(d.portable_root.as_deref().expect("root")), canon(&app.join(Dirs::ROOT)));
    // A trailing separator on the exe path (`Path` drops it; the marker is still next to it).
    let trailing = PathBuf::from(format!("{}/", app.join("mooring").display()));
    let d2 = Dirs::resolve(&trailing, None, &never_os, &probe).expect("trailing slash");
    assert_eq!(canon(d2.portable_root.as_deref().expect("root")), canon(&app.join(Dirs::ROOT)));
    // Only one root was created.
    assert_eq!(tree_of(&app).iter().filter(|p| p.ends_with(Dirs::ROOT)).count(), 1);
}

#[cfg(unix)]
#[test]
fn non_utf8_path_does_not_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join(OsStr::from_bytes(b"app-\xff\xfe-\xc3"));
    let exe = portable_app(&app);
    let d = Dirs::resolve(&exe, None, &never_os, &probe).expect("resolve");
    assert!(d.portable());
    assert!(d.data.is_dir());
    // The error texts and `app_info` go through `display()` (lossy), never `to_str().unwrap()`.
    for e in [
        DirsError::MarkerInvalid(app.join(Dirs::MARKER)),
        DirsError::DataDirInvalid(app.join(Dirs::ROOT)),
        DirsError::Unwritable(app.clone()),
    ] {
        let text = e.to_string();
        assert!(text.contains("app-"), "{text}");
        let r: crate::startup::Refusal = e.into();
        assert!(r.message.contains('\u{FFFD}'), "lossy, not dropped: {}", r.message);
    }
    let clipboard = Arc::new(crate::clipboard::MemoryClipboard::default());
    let st = AppState::new(d, testing::settings(clipboard)).expect("state");
    let info = serde_json::to_value(vault::info(&st)).expect("json");
    assert!(info["portableDataDir"].as_str().expect("string").contains('\u{FFFD}'));
    // Marker invalid in a non-UTF-8 folder: still refused, still no panic.
    std::fs::remove_file(app.join(Dirs::MARKER)).expect("rm");
    std::fs::create_dir(app.join(Dirs::MARKER)).expect("dir");
    assert_eq!(
        Dirs::resolve(&exe, None, &never_os, &probe).expect_err("dir").code(),
        "portable.marker_invalid"
    );
}

#[test]
fn very_long_path_does_not_panic() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut app = tmp.path().to_path_buf();
    for i in 0..4 {
        app.push(format!("{i}-{}", "x".repeat(90)));
    }
    assert!(app.as_os_str().len() > 300, "{}", app.as_os_str().len());
    let exe = portable_app(&app);
    let d = Dirs::resolve(&exe, None, &never_os, &probe).expect("long path");
    assert!(d.data.is_dir() && d.cache.is_dir());
    assert!(d.data.as_os_str().len() > 260);
    let e = DirsError::Unwritable(d.data.clone()).to_string();
    assert!(e.len() > 260);
}

#[test]
fn nested_app_bundles_pick_the_nearest_one() {
    let inner = Path::new("/Users/u/Outer.app/Contents/MacOS/Inner.app/Contents/MacOS/mooring");
    assert_eq!(
        Dirs::marker_dir(inner, None),
        Some(PathBuf::from("/Users/u/Outer.app/Contents/MacOS"))
    );
    let helper =
        Path::new("/Users/u/Outer.app/Contents/Resources/Mooring.app/Contents/MacOS/mooring");
    assert_eq!(
        Dirs::marker_dir(helper, None),
        Some(PathBuf::from("/Users/u/Outer.app/Contents/Resources"))
    );
    // A `.app` higher up without the exact shape at the exe is not a bundle for us.
    let loose = Path::new("/Users/u/Mooring.app/Contents/MacOS/helpers/mooring");
    assert_eq!(
        Dirs::marker_dir(loose, None),
        Some(PathBuf::from("/Users/u/Mooring.app/Contents/MacOS/helpers"))
    );
    // `.app` at the root of the filesystem: the bundle's parent is `/`.
    let at_root = Path::new("/Mooring.app/Contents/MacOS/mooring");
    assert_eq!(Dirs::marker_dir(at_root, None), Some(PathBuf::from("/")));
    // Case matters for the shape (`MacOS`, `Contents`); `.APP` is not `.app`.
    let wrong_case = Path::new("/Users/u/Mooring.APP/Contents/MacOS/mooring");
    assert_eq!(
        Dirs::marker_dir(wrong_case, None),
        Some(PathBuf::from("/Users/u/Mooring.APP/Contents/MacOS"))
    );
}

#[test]
fn bogus_appimage_values_never_panic() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = portable_app(&app);
    let os = tmp.path().join("os");
    let os_default = || Ok((os.join("data"), os.join("cache")));
    // $APPIMAGE names a file that does not exist: its parent is the marker dir (no marker
    // there) → OS directories, the marker next to the mounted exe is not consulted.
    let missing = tmp.path().join("nowhere").join("Mooring.AppImage");
    let d = Dirs::resolve(&exe, Some(&missing), &os_default, &probe).expect("missing appimage");
    assert!(!d.portable());
    assert!(!tmp.path().join("nowhere").exists(), "nothing created for a bogus $APPIMAGE");
    // Degenerate values: empty, `/`, `.`, `..`.
    for weird in ["", "/", ".", ".."] {
        let r = Dirs::resolve(&exe, Some(Path::new(weird)), &os_default, &probe);
        assert!(r.is_ok(), "{weird:?}: {r:?}");
    }
    assert_eq!(Dirs::marker_dir(&exe, Some(Path::new(""))), None);
    assert_eq!(Dirs::marker_dir(&exe, Some(Path::new("/"))), None);
    // A marker next to the AppImage wins over the exe's own folder.
    let image_dir = tmp.path().join("Applications");
    std::fs::create_dir_all(&image_dir).expect("mkdir");
    std::fs::write(image_dir.join(Dirs::MARKER), b"").expect("marker");
    let image = image_dir.join("Mooring.AppImage");
    let d = Dirs::resolve(&exe, Some(&image), &never_os, &probe).expect("appimage marker");
    assert_eq!(d.portable_root.as_deref(), Some(image_dir.join(Dirs::ROOT).as_path()));
}

#[test]
fn two_threads_resolving_the_same_folder_both_succeed() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = portable_app(&app);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let (exe, barrier) = (exe.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                Dirs::resolve(&exe, None, &never_os, &probe)
            })
        })
        .collect();
    let results: Vec<Dirs> =
        handles.into_iter().map(|h| h.join().expect("thread").expect("resolve")).collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(mode_of(&results[0].data), 0o700);
    // No probe file was left behind by either thread.
    let leftovers: Vec<PathBuf> =
        tree_of(&app).into_iter().filter(|p| p.to_string_lossy().contains("probe")).collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
