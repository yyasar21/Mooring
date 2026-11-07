//! ADR-0021 §1 test plan: marker absent / present / invalid, unwritable, bundle shapes.

use std::path::{Path, PathBuf};

use super::{Dirs, DirsError};
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
