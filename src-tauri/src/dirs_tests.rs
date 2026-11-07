//! ADR-0021 §1 test plan: marker absent / present / invalid, unwritable, bundle shapes.

use std::path::{Path, PathBuf};

use super::{Dirs, DirsError, Located};
use crate::Mode;
use crate::updater::install_mode::dir_writable;

fn os_default_in(base: &Path) -> impl Fn() -> tauri::Result<(PathBuf, PathBuf)> {
    let base = base.to_path_buf();
    move || Ok((base.join("os-data"), base.join("os-cache")))
}

fn never_os() -> tauri::Result<(PathBuf, PathBuf)> {
    panic!("the OS directories must not be consulted in portable mode")
}

fn writable(p: &Path) -> bool {
    dir_writable(Some(p))
}

fn exe_in(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let exe = dir.join("mooring");
    std::fs::write(&exe, b"").expect("exe");
    exe
}

#[test]
fn marker_absent_uses_os_dirs_and_creates_them() {
    let tmp = tempfile::tempdir().expect("tmp");
    let exe = exe_in(&tmp.path().join("app"));
    let d = Dirs::resolve(&exe, None, &os_default_in(tmp.path()), &writable).expect("dirs");
    assert_eq!(d, Dirs::plain(tmp.path().join("os-data"), tmp.path().join("os-cache")));
    assert!(d.data.is_dir() && d.cache.is_dir());
    assert!(!d.portable());
    assert_eq!(d.webview_dir(), None);
    assert!(!tmp.path().join("app").join(Dirs::ROOT).exists(), "no portable root");
}

#[test]
fn marker_present_creates_private_root_and_subdirs() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"anything, ignored\n").expect("marker");
    let d = Dirs::resolve(&exe, None, &never_os, &writable).expect("dirs");
    let root = app.join(Dirs::ROOT);
    assert_eq!(d.portable_root.as_deref(), Some(root.as_path()));
    assert_eq!(d.data, root.join("data"));
    assert_eq!(d.cache, root.join("cache"));
    assert_eq!(d.webview_dir(), Some(root.join("cache").join("webview")));
    assert!(d.data.is_dir() && d.cache.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&root, &d.data, &d.cache] {
            let mode = std::fs::metadata(p).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", p.display());
        }
    }
    // A second start reuses the root.
    let again = Dirs::resolve(&exe, None, &never_os, &writable).expect("again");
    assert_eq!(again, d);
}

#[test]
fn unwritable_marker_dir_is_refused_without_fallback() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let e = Dirs::resolve(&exe, None, &never_os, &|_| false).expect_err("unwritable");
    assert!(matches!(&e, DirsError::Unwritable(p) if *p == app), "{e:?}");
    assert_eq!(e.code(), "portable.unwritable");
    assert_eq!(e.path(), Some(app.as_path()));
    assert!(e.to_string().contains(&app.display().to_string()));
    assert!(!app.join(Dirs::ROOT).exists(), "nothing created");
}

#[test]
fn unwritable_existing_root_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let root = app.join(Dirs::ROOT);
    std::fs::create_dir_all(root.join("data")).expect("root");
    // The marker dir itself is writable; the data subdir is not.
    let probe = |p: &Path| !p.ends_with("data");
    let e = Dirs::resolve(&exe, None, &never_os, &probe).expect_err("unwritable");
    assert!(matches!(&e, DirsError::Unwritable(p) if *p == root), "{e:?}");
}

#[test]
fn directory_named_portable_is_invalid_not_absent() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::create_dir(app.join(Dirs::MARKER)).expect("dir marker");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("dir");
    assert!(matches!(&e, DirsError::MarkerInvalid(p) if *p == app.join(Dirs::MARKER)), "{e:?}");
    assert_eq!(e.code(), "portable.marker_invalid");
}

#[cfg(unix)]
#[test]
fn symlinked_marker_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    let target = tmp.path().join("real-marker");
    std::fs::write(&target, b"").expect("target");
    std::os::unix::fs::symlink(&target, app.join(Dirs::MARKER)).expect("symlink");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("symlink");
    assert_eq!(e.code(), "portable.marker_invalid");
    // A dangling link is refused the same way (not "absent").
    std::fs::remove_file(&target).expect("rm");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("dangling");
    assert_eq!(e.code(), "portable.marker_invalid");
}

#[cfg(unix)]
#[test]
fn symlinked_data_root_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("mkdir");
    std::os::unix::fs::symlink(&elsewhere, app.join(Dirs::ROOT)).expect("symlink");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("link root");
    assert!(matches!(&e, DirsError::DataDirInvalid(p) if *p == app.join(Dirs::ROOT)), "{e:?}");
    assert_eq!(e.code(), "portable.data_dir_invalid");
    assert!(std::fs::read_dir(&elsewhere).expect("ls").next().is_none(), "nothing written through the link");
}

#[cfg(unix)]
#[test]
fn symlinked_data_subdir_is_refused_and_not_followed() {
    for sub in ["data", "cache"] {
        let tmp = tempfile::tempdir().expect("tmp");
        let app = tmp.path().join("app");
        let exe = exe_in(&app);
        std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
        let root = app.join(Dirs::ROOT);
        std::fs::create_dir_all(&root).expect("root");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        std::os::unix::fs::symlink(&elsewhere, root.join(sub)).expect("symlink");
        let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("link subdir");
        assert!(matches!(&e, DirsError::DataDirInvalid(p) if *p == root), "{sub}: {e:?}");
        assert!(std::fs::read_dir(&elsewhere).expect("ls").next().is_none(), "{sub}: written through the link");
        assert!(!root.join(["data", "cache"].iter().find(|s| **s != sub).expect("other")).exists(), "{sub}: sibling created");
    }
}

#[test]
fn file_named_data_subdir_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let root = app.join(Dirs::ROOT);
    std::fs::create_dir_all(&root).expect("root");
    std::fs::write(root.join("cache"), b"not a dir").expect("file");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("file subdir");
    assert_eq!(e.code(), "portable.data_dir_invalid");
}

#[test]
fn file_named_mooring_data_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    std::fs::write(app.join(Dirs::ROOT), b"not a dir").expect("file");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("file root");
    assert_eq!(e.code(), "portable.data_dir_invalid");
}

#[test]
fn marker_dir_shapes() {
    // Windows / Linux: next to the executable.
    assert_eq!(
        Dirs::marker_dir(Path::new("/opt/mooring/mooring"), None),
        Some(PathBuf::from("/opt/mooring"))
    );
    // macOS: the parent of the bundle, never inside it.
    assert_eq!(
        Dirs::marker_dir(Path::new("/Users/u/Desktop/Mooring/Mooring.app/Contents/MacOS/mooring"), None),
        Some(PathBuf::from("/Users/u/Desktop/Mooring"))
    );
    // Only the exact bundle shape counts.
    assert_eq!(
        Dirs::marker_dir(Path::new("/Users/u/Mooring.app/bin/mooring"), None),
        Some(PathBuf::from("/Users/u/Mooring.app/bin"))
    );
    // AppImage: the parent of the image file, not of the squashfs mount.
    assert_eq!(
        Dirs::marker_dir(
            Path::new("/tmp/.mount_MoorinAbC/usr/bin/mooring"),
            Some(Path::new("/home/u/Applications/Mooring.AppImage"))
        ),
        Some(PathBuf::from("/home/u/Applications"))
    );
    assert_eq!(Dirs::marker_dir(Path::new("mooring"), None), Some(PathBuf::new()));
}

#[test]
fn errors_name_the_directory_only() {
    let p = PathBuf::from("/media/usb/Mooring");
    let os = DirsError::Os(tauri::Error::WindowNotFound);
    assert_eq!(os.code(), "app.data_dir");
    assert_eq!(os.path(), None);
    for e in [DirsError::MarkerInvalid(p.clone()), DirsError::DataDirInvalid(p.clone()), DirsError::Unwritable(p.clone())] {
        assert_eq!(e.path(), Some(p.as_path()));
        assert!(e.to_string().contains("/media/usb/Mooring"));
    }
}

// ------------------------------------------------------------ review 8 fixes

#[test]
fn locate_creates_nothing_and_create_finishes_the_job() {
    // N-65: the WebView2 check runs between the two halves, so a refusal leaves no root.
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    assert_eq!(Dirs::locate(&exe, None).expect("locate"), Located::Os);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let located = Dirs::locate(&exe, None).expect("locate");
    assert_eq!(located, Located::Portable(app.clone()));
    assert!(located.portable());
    assert!(!app.join(Dirs::ROOT).exists(), "locate must not create the root");
    let d = Dirs::create(located, &never_os, &writable).expect("create");
    assert_eq!(d, Dirs::resolve(&exe, None, &never_os, &writable).expect("resolve"));
    assert!(d.data.is_dir() && !d.mode_unavailable);
}

#[test]
fn translocated_paths_are_detected_by_component() {
    // M-18: LaunchServices' copy lives under /private/var/folders/<xx>/<yyy>/T/AppTranslocation.
    for p in [
        "/private/var/folders/9q/abc/T/AppTranslocation/2E5B-4A1C/d/Mooring.app/Contents/MacOS/Mooring",
        "/var/folders/9q/abc/T/AppTranslocation/2E5B-4A1C/d/Mooring.app/Contents/MacOS/Mooring",
        "/AppTranslocation/x",
    ] {
        assert!(Dirs::translocated(Path::new(p)), "{p}");
    }
    for p in [
        "/Users/u/Desktop/Mooring/Mooring.app/Contents/MacOS/Mooring",
        "/Users/u/AppTranslocation.app/Contents/MacOS/Mooring",
        "/Users/u/MyAppTranslocation/Mooring.app/Contents/MacOS/Mooring",
        "/private/var/folders/9q/abc/T/apptranslocation/x/d/Mooring.app/Contents/MacOS/Mooring",
        "/Volumes/USB/Mooring/Mooring.app/Contents/MacOS/Mooring",
    ] {
        assert!(!Dirs::translocated(Path::new(p)), "{p}");
    }
    let e = DirsError::Translocated(PathBuf::from("/private/var/folders/x/AppTranslocation/u/d/Mooring.app"));
    assert_eq!(e.code(), "portable.translocated");
    assert!(e.path().is_some());
    assert!(e.to_string().contains("Finder") && !e.to_string().contains("xattr"));
}

#[cfg(target_os = "macos")]
#[test]
fn translocated_exe_is_refused_before_the_marker_is_looked_up() {
    let tmp = tempfile::tempdir().expect("tmp");
    let d = tmp.path().join("T").join(Dirs::TRANSLOCATION).join("uuid").join("d");
    let exe = exe_in(&d.join("Mooring.app").join("Contents").join("MacOS"));
    // Even with a marker in the copy (it never has one) the answer is the refusal.
    std::fs::write(d.join(Dirs::MARKER), b"").expect("marker");
    let e = Dirs::locate(&exe, None).expect_err("translocated");
    assert!(matches!(&e, DirsError::Translocated(p) if *p == d.join("Mooring.app")), "{e:?}");
    let e = Dirs::resolve(&exe, None, &never_os, &writable).expect_err("translocated");
    assert_eq!(e.code(), "portable.translocated");
    assert!(!d.join(Dirs::ROOT).exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn translocation_component_is_an_ordinary_folder_name_elsewhere() {
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join(Dirs::TRANSLOCATION).join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let d = Dirs::resolve(&exe, None, &never_os, &writable).expect("not macOS");
    assert!(d.portable());
}

// AppImage mounts are POSIX paths; the check only runs on Linux (L-44), so not on Windows.
#[cfg(unix)]
#[test]
fn exe_in_appimage_mount_shapes() {
    let exe = Path::new("/tmp/.mount_MoorinAbC/usr/bin/mooring");
    assert!(Dirs::exe_in_appimage_mount(exe, None));
    assert!(Dirs::exe_in_appimage_mount(Path::new("/home/u/x/mooring"), Some(Path::new("/home/u/x"))));
    assert!(!Dirs::exe_in_appimage_mount(Path::new("/home/u/x/mooring"), Some(Path::new("/home/u/y"))));
    // A degenerate `$APPDIR` never matches: relative, root, or empty.
    assert!(!Dirs::exe_in_appimage_mount(Path::new("/home/u/x/mooring"), Some(Path::new("home/u/x"))));
    assert!(!Dirs::exe_in_appimage_mount(Path::new("/home/u/x/mooring"), Some(Path::new("/"))));
    assert!(!Dirs::exe_in_appimage_mount(Path::new("/home/u/x/mooring"), Some(Path::new(""))));
    for p in ["/tmp/.mount_", "/tmp/mount_x/mooring", "/var/tmp/.mount_x/mooring", "/home/u/.mount_x/mooring", "tmp/.mount_x/m"] {
        assert!(!Dirs::exe_in_appimage_mount(Path::new(p), None), "{p}");
    }
}

#[test]
fn appimage_env_is_validated_before_it_relocates_the_marker() {
    // L-44: a real image file, the exe inside its mount, Linux → honoured.
    let tmp = tempfile::tempdir().expect("tmp");
    let image = tmp.path().join("Mooring.AppImage");
    std::fs::write(&image, b"").expect("image");
    let mount = tmp.path().join("mount");
    let exe = exe_in(&mount.join("usr").join("bin"));
    let ok = Dirs::appimage_from_env(&exe, Some(&image), Some(&mount), true);
    assert_eq!(ok.as_deref(), Some(image.as_path()));
    // Not Linux: ignored, whatever the value.
    assert_eq!(Dirs::appimage_from_env(&exe, Some(&image), Some(&mount), false), None);
    // The exe is not under $APPDIR / a mount: an inherited value from another AppImage.
    assert_eq!(Dirs::appimage_from_env(&exe, Some(&image), None, true), None);
    assert_eq!(Dirs::appimage_from_env(&exe, Some(&image), Some(&tmp.path().join("other")), true), None);
    // The image does not exist, is a directory, or is relative: ignored.
    assert_eq!(Dirs::appimage_from_env(&exe, Some(&tmp.path().join("missing")), Some(&mount), true), None);
    assert_eq!(Dirs::appimage_from_env(&exe, Some(&mount), Some(&mount), true), None);
    assert_eq!(Dirs::appimage_from_env(&exe, Some(Path::new("Mooring.AppImage")), Some(&mount), true), None);
    assert_eq!(Dirs::appimage_from_env(&exe, None, Some(&mount), true), None);
    #[cfg(unix)]
    {
        let link = tmp.path().join("link.AppImage");
        std::os::unix::fs::symlink(&image, &link).expect("symlink");
        assert_eq!(Dirs::appimage_from_env(&exe, Some(&link), Some(&mount), true), None);
    }
}

#[test]
fn inherited_appimage_keeps_the_marker_next_to_the_real_exe() {
    // L-44 (a): a terminal that is an AppImage sets $APPIMAGE for Mooring; the marker next to
    // Mooring's own executable must still win, and the other image's folder is never read.
    let tmp = tempfile::tempdir().expect("tmp");
    let other = tmp.path().join("Terminal.AppImage");
    std::fs::write(&other, b"").expect("other image");
    let app = tmp.path().join("app");
    let exe = exe_in(&app);
    std::fs::write(app.join(Dirs::MARKER), b"").expect("marker");
    let appimage = Dirs::appimage_from_env(&exe, Some(&other), None, true);
    assert_eq!(appimage, None);
    let d = Dirs::resolve(&exe, appimage.as_deref(), &never_os, &writable).expect("portable");
    assert_eq!(d.portable_root.as_deref(), Some(app.join(Dirs::ROOT).as_path()));
    assert!(!tmp.path().join(Dirs::ROOT).exists(), "nothing next to the other image");
}

/// Scripted `create_private_dir`: creates the directory and reports `mode`.
fn mkdir_reporting(mode: Mode) -> impl Fn(&Path) -> std::io::Result<Mode> {
    move |p: &Path| std::fs::create_dir_all(p).map(|()| mode)
}

#[test]
fn volume_without_posix_modes_is_not_unwritable() {
    // L-45: vfat / exFAT answer `chmod` with EPERM; the folder is writable all the same.
    let tmp = tempfile::tempdir().expect("tmp");
    let app = tmp.path().join("app");
    exe_in(&app);
    let d = Dirs::portable_under(&app, &writable, &mkdir_reporting(Mode::Unavailable)).expect("usable");
    assert!(d.portable() && d.mode_unavailable);
    assert!(d.data.is_dir() && d.cache.is_dir());
    let d = Dirs::portable_under(&app, &writable, &mkdir_reporting(Mode::Private)).expect("usable");
    assert!(!d.mode_unavailable);
    // A real create failure is still `Unwritable(root)`.
    let failing = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let e = Dirs::portable_under(&app, &writable, &failing).expect_err("create failed");
    assert!(matches!(&e, DirsError::Unwritable(p) if *p == app.join(Dirs::ROOT)), "{e:?}");
}

#[cfg(unix)]
#[test]
fn create_private_dir_reports_the_mode_it_applied() {
    // The real function on a POSIX volume: `Private`, and an existing 0755 is tightened. The
    // `Unavailable` branch (vfat / exFAT: EPERM from chmod) needs such a mount; it is covered
    // by the scripted test above and the macOS USB gate.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tmp");
    let dir = tmp.path().join("d");
    std::fs::create_dir(&dir).expect("mkdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(crate::create_private_dir(&dir).expect("existing dir"), Mode::Private);
    assert_eq!(std::fs::metadata(&dir).expect("m").permissions().mode() & 0o777, 0o700);
}

#[cfg(unix)]
#[test]
fn entry_swapped_between_check_and_create_is_refused() {
    // N-68: the scripted `mkdir` plays the co-located writer who swaps `Mooring Data` (or a
    // subdir) for a link to elsewhere after the pre-check passed.
    let tmp = tempfile::tempdir().expect("tmp");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("mkdir");
    for victim in ["", "data", "cache"] {
        let app = tmp.path().join(format!("app-{victim}"));
        exe_in(&app);
        let root = app.join(Dirs::ROOT);
        let target = if victim.is_empty() { root.clone() } else { root.join(victim) };
        let swap = |p: &Path| -> std::io::Result<Mode> {
            std::fs::create_dir_all(p)?;
            if p == target {
                std::fs::remove_dir(p)?;
                std::os::unix::fs::symlink(&elsewhere, p)?;
            }
            Ok(Mode::Private)
        };
        let e = Dirs::portable_under(&app, &writable, &swap).expect_err("swapped");
        assert!(matches!(&e, DirsError::DataDirInvalid(p) if *p == root), "{victim:?}: {e:?}");
        assert!(std::fs::read_dir(&elsewhere).expect("ls").next().is_none(), "{victim:?}: written through the link");
    }
    // A plain directory replaced by another plain directory is only caught when the inode
    // differs (ext4 / tmpfs reuse it at once), so that case is best-effort and not pinned.
}

#[test]
fn invalid_texts_mention_cloud_sync_placeholders() {
    // L-46: a OneDrive / iCloud "files on demand" placeholder is a reparse point; the user
    // must be able to tell why the folder was refused.
    let p = PathBuf::from("/x");
    for e in [DirsError::MarkerInvalid(p.clone()), DirsError::DataDirInvalid(p)] {
        assert!(e.to_string().contains("cloud-sync placeholder"), "{e}");
    }
}
