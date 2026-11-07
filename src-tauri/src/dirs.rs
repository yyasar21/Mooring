//! Data and cache directories, resolved once at start (ADR-0021 §1).
//!
//! Portable mode is a **regular file** named [`Dirs::MARKER`] next to the executable (the
//! `.app` bundle on macOS, the `AppImage` file on Linux). Its content is ignored. When present
//! every file location lives under `<marker dir>/Mooring Data/{data,cache}`; when the marker
//! is absent the OS application directories are used. An invalid or unusable marker set-up is
//! an error and **never** falls back to the OS directories (owner decision 2026-11-07): a user
//! who put the vault on a USB stick must know where it went.
//!
//! Resolution is two steps (review 8 N-65): [`Dirs::locate`] decides *where* the marker is
//! looked up and whether it is there, without touching the filesystem beyond that one
//! `symlink_metadata`; [`Dirs::create`] then creates and checks the directories. The Windows
//! `WebView2` check runs between the two, so a refused start leaves the folder as it found it.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::{create_private_dir, Mode};

/// Resolved directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    /// Vault header, audit log, `mooring.db`, `known_hosts`, web stores.
    pub data: PathBuf,
    /// Ephemeral web profiles; in portable mode also the main window's `WebView` profile.
    pub cache: PathBuf,
    /// `<marker dir>/Mooring Data` when portable, else `None`.
    pub portable_root: Option<PathBuf>,
    /// The volume refused the owner-only mode (`chmod 0700` → `EPERM` / `ENOTSUP` on vfat or
    /// exFAT, review 8 L-45). The directories exist and are writable; the caller audits
    /// `portable.acl_unavailable`, the same semantics Windows gives FAT.
    pub mode_unavailable: bool,
}

/// Where [`Dirs::locate`] found the marker: the first half of [`Dirs::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    /// A regular `portable` file lives in this directory; nothing has been created yet.
    Portable(PathBuf),
    /// No marker: the OS application directories apply.
    Os,
}

impl Located {
    /// Whether the marker was found.
    pub fn portable(&self) -> bool {
        matches!(self, Self::Portable(_))
    }
}

/// Why the directories could not be resolved. Each maps to one startup error code
/// ([`DirsError::code`]); the message names the directory and nothing else.
#[derive(Debug)]
pub enum DirsError {
    /// The marker exists but is not a regular file (symlink, reparse point, directory).
    MarkerInvalid(PathBuf),
    /// `Mooring Data` exists but is not a plain directory (symlink, junction, file).
    DataDirInvalid(PathBuf),
    /// The marker directory or the data root cannot be written.
    Unwritable(PathBuf),
    /// macOS App Translocation runs the bundle from a read-only copy (review 8 M-18): the
    /// marker next to the real bundle is out of reach, so nothing can be decided.
    Translocated(PathBuf),
    /// The OS path API failed (no home directory).
    Os(tauri::Error),
}

impl DirsError {
    /// The startup / IPC error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MarkerInvalid(_) => "portable.marker_invalid",
            Self::DataDirInvalid(_) => "portable.data_dir_invalid",
            Self::Unwritable(_) => "portable.unwritable",
            Self::Translocated(_) => "portable.translocated",
            Self::Os(_) => "app.data_dir",
        }
    }

    /// The directory the message box names (the translocated copy's bundle for M-18, which
    /// the message itself does not repeat).
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::MarkerInvalid(p)
            | Self::DataDirInvalid(p)
            | Self::Unwritable(p)
            | Self::Translocated(p) => Some(p),
            Self::Os(_) => None,
        }
    }
}

impl std::fmt::Display for DirsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MarkerInvalid(p) => write!(
                f,
                "The portable marker {} is not a regular file (a link, a folder, or a cloud-sync placeholder). Replace it with an empty file named \"portable\" or remove it.",
                p.display()
            ),
            Self::DataDirInvalid(p) => write!(
                f,
                "{} exists but is not a plain folder (a link, a file, or a cloud-sync placeholder). Mooring will not store data through it.",
                p.display()
            ),
            Self::Unwritable(p) => write!(
                f,
                "{} is not writable. Move the Mooring folder somewhere writable or remove the \"portable\" marker file.",
                p.display()
            ),
            Self::Translocated(_) => f.write_str(
                "Mooring is running from a macOS translocation copy; drag Mooring.app out of its folder and back in with Finder once, then open it again.",
            ),
            Self::Os(e) => write!(f, "The application data directory could not be resolved: {e}"),
        }
    }
}

impl std::error::Error for DirsError {}

/// `FILE_ATTRIBUTE_REPARSE_POINT`: symlinks, junctions, mount points, OneDrive placeholders.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Whether `m` describes a symlink or (Windows) any reparse point.
fn is_link(m: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    m.file_type().is_symlink()
}

/// Whether `exe` sits at `<X>.app/Contents/MacOS/<exe>` (a macOS bundle); returns `<X>.app`.
pub(crate) fn app_bundle(exe: &Path) -> Option<&Path> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    let is = |p: &Path, name: &str| p.file_name().is_some_and(|n| n == name);
    (is(macos, "MacOS") && is(contents, "Contents") && app.extension().is_some_and(|e| e == "app"))
        .then_some(app)
}

/// Whether the same directory entry is described twice (unix `dev` + `ino`; elsewhere always
/// true, the shape check carries the weight).
fn same_entry(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        true
    }
}

/// How a directory is created: [`create_private_dir`] in production, scripted in tests.
type Mkdir<'a> = &'a dyn Fn(&Path) -> std::io::Result<Mode>;

impl Dirs {
    /// Marker file name.
    pub const MARKER: &'static str = "portable";
    /// Data root name under the marker directory for this build's channel (ADR-0028 §1).
    pub const ROOT: &'static str = Self::root_name(crate::build_identity::Channel::CURRENT);
    /// `cache/webview`: the main window's `WebView` profile in portable mode (Windows, Linux).
    pub const WEBVIEW_DIR: &'static str = "webview";
    /// The path component `LaunchServices` uses for App Translocation copies
    /// (`/private/var/folders/…/AppTranslocation/<uuid>/d/<X>.app`).
    pub const TRANSLOCATION: &'static str = "AppTranslocation";

    /// The portable data root of `channel`: `Mooring Data` (release) or `Mooring Dev Data`
    /// (dev), so a dev build next to a release build never opens its vault.
    pub const fn root_name(channel: crate::build_identity::Channel) -> &'static str {
        match channel {
            crate::build_identity::Channel::Release => "Mooring Data",
            crate::build_identity::Channel::Dev => "Mooring Dev Data",
        }
    }

    /// The directory the marker is looked up in (pure). `AppImage`: the parent of `$APPIMAGE`
    /// (the executable itself runs from a squashfs mount); macOS: the parent of the `.app`
    /// bundle, never inside it (read-only, ad-hoc signed); otherwise the executable's parent.
    /// `appimage` is the already-validated value from [`Dirs::appimage_from_env`].
    pub fn marker_dir(exe: &Path, appimage: Option<&Path>) -> Option<PathBuf> {
        if let Some(image) = appimage {
            return image.parent().map(Path::to_path_buf);
        }
        if let Some(app) = app_bundle(exe) {
            return app.parent().map(Path::to_path_buf);
        }
        exe.parent().map(Path::to_path_buf)
    }

    /// Whether `exe` runs from a macOS App Translocation copy (pure, review 8 M-18): any path
    /// component equals [`Dirs::TRANSLOCATION`]. Such a copy holds only the bundle, so the
    /// marker next to the real bundle is invisible and a lookup there would silently take
    /// the OS directories.
    pub fn translocated(exe: &Path) -> bool {
        exe.components().any(|c| c.as_os_str() == Self::TRANSLOCATION)
    }

    /// Validate `$APPIMAGE` (review 8 L-44): honoured only on Linux (`linux`), only when it
    /// is an absolute path to a regular file (`symlink_metadata`, no link) **and** `exe` lies
    /// under `$APPDIR` or a `/tmp/.mount_*` directory (the `AppImage` runtime's mount). An
    /// inherited or forged value (a terminal that is itself an `AppImage` sets it for its
    /// children; a logon script could too) is ignored, so the marker is looked up next to the
    /// real executable instead of silently next to another file.
    pub fn appimage_from_env(
        exe: &Path,
        appimage: Option<&Path>,
        appdir: Option<&Path>,
        linux: bool,
    ) -> Option<PathBuf> {
        let image = appimage?;
        let accepted = linux
            && image.is_absolute()
            && std::fs::symlink_metadata(image).is_ok_and(|m| m.is_file() && !is_link(&m))
            && Self::exe_in_appimage_mount(exe, appdir);
        if accepted {
            Some(image.to_path_buf())
        } else {
            tracing::warn!("APPIMAGE is set but not usable here; ignored");
            None
        }
    }

    /// Whether `exe` is under a non-empty absolute `$APPDIR` or `/tmp/.mount_*` (pure).
    pub fn exe_in_appimage_mount(exe: &Path, appdir: Option<&Path>) -> bool {
        if appdir.is_some_and(|d| d.is_absolute() && d.parent().is_some() && exe.starts_with(d)) {
            return true;
        }
        let mut c = exe.components();
        let root = c.next().is_some_and(|c| matches!(c, std::path::Component::RootDir));
        let tmp = c.next().is_some_and(|c| c.as_os_str() == "tmp");
        let mount = c.next().is_some_and(|c| {
            c.as_os_str().to_str().is_some_and(|s| s.len() > ".mount_".len() && s.starts_with(".mount_"))
        });
        root && tmp && mount
    }

    /// OS application directories, both created owner-only.
    pub fn plain(data: PathBuf, cache: PathBuf) -> Self {
        Self { data, cache, portable_root: None, mode_unavailable: false }
    }

    /// Whether this is a portable install.
    pub fn portable(&self) -> bool {
        self.portable_root.is_some()
    }

    /// The main window's `WebView` profile directory in portable mode (Windows, Linux).
    pub fn webview_dir(&self) -> Option<PathBuf> {
        self.portable_root.as_ref().map(|_| self.cache.join(Self::WEBVIEW_DIR))
    }

    /// Resolve: the marker decides, `os_default` supplies the OS directories when it is
    /// absent, `probe` says whether a directory is writable (create-and-remove, see
    /// `install_mode::dir_writable`). Every directory returned exists and went through
    /// `create_private_dir`. Equals [`Dirs::locate`] followed by [`Dirs::create`].
    pub fn resolve(
        exe: &Path,
        appimage: Option<&Path>,
        os_default: &dyn Fn() -> tauri::Result<(PathBuf, PathBuf)>,
        probe: &dyn Fn(&Path) -> bool,
    ) -> Result<Self, DirsError> {
        Self::create(Self::locate(exe, appimage)?, os_default, probe)
    }

    /// Find the marker (one `symlink_metadata`, nothing created). On macOS a translocated
    /// `exe` is refused first (M-18): its marker directory is the temporary copy's.
    pub fn locate(exe: &Path, appimage: Option<&Path>) -> Result<Located, DirsError> {
        if cfg!(target_os = "macos") && Self::translocated(exe) {
            let bundle = app_bundle(exe).or_else(|| exe.parent()).unwrap_or(exe);
            return Err(DirsError::Translocated(bundle.to_path_buf()));
        }
        let marker_dir = Self::marker_dir(exe, appimage);
        let marker = marker_dir.as_ref().map(|d| d.join(Self::MARKER));
        match marker.as_ref().map(std::fs::symlink_metadata) {
            // No marker directory at all (a bare executable path) or no marker: OS dirs.
            None => return Ok(Located::Os),
            Some(Err(e)) if e.kind() == ErrorKind::NotFound => return Ok(Located::Os),
            Some(Ok(m)) if m.is_file() && !is_link(&m) => {}
            // A symlink, reparse point, directory or something unreadable: refused.
            Some(_) => return Err(DirsError::MarkerInvalid(marker.unwrap_or_default())),
        }
        marker_dir
            .map(Located::Portable)
            .ok_or_else(|| DirsError::MarkerInvalid(PathBuf::from(Self::MARKER)))
    }

    /// Create and check the directories a [`Located`] names.
    pub fn create(
        located: Located,
        os_default: &dyn Fn() -> tauri::Result<(PathBuf, PathBuf)>,
        probe: &dyn Fn(&Path) -> bool,
    ) -> Result<Self, DirsError> {
        match located {
            Located::Os => Self::os_dirs(os_default),
            Located::Portable(dir) => Self::portable_under(&dir, probe, &create_private_dir),
        }
    }

    fn os_dirs(os_default: &dyn Fn() -> tauri::Result<(PathBuf, PathBuf)>) -> Result<Self, DirsError> {
        let (data, cache) = os_default().map_err(DirsError::Os)?;
        let mut d = Self::plain(data, cache);
        for p in [&d.data, &d.cache] {
            let mode = create_private_dir(p).map_err(|_| DirsError::Unwritable(p.clone()))?;
            d.mode_unavailable |= mode == Mode::Unavailable;
        }
        Ok(d)
    }

    /// `<dir>/Mooring Data/{data,cache}`, created with `mkdir` and checked. Every entry is
    /// inspected before creation (a link, reparse point or file is refused, nothing is written
    /// through it) and **again after** (review 8 N-68): a swap between the check and the
    /// create, which only a co-located writer can do, is refused instead of followed.
    fn portable_under(dir: &Path, probe: &dyn Fn(&Path) -> bool, mkdir: Mkdir<'_>) -> Result<Self, DirsError> {
        let root = dir.join(Self::ROOT);
        let plain_dir = |p: &Path| -> Result<Option<std::fs::Metadata>, DirsError> {
            match std::fs::symlink_metadata(p) {
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                Ok(m) if m.is_dir() && !is_link(&m) => Ok(Some(m)),
                _ => Err(DirsError::DataDirInvalid(root.clone())),
            }
        };
        let root_before = plain_dir(&root)?;
        if root_before.is_none() && !probe(dir) {
            return Err(DirsError::Unwritable(dir.to_path_buf()));
        }
        let data = root.join("data");
        let cache = root.join("cache");
        // The root is refused when linked so the data cannot be redirected (ADR-0021 §1);
        // a linked `data` / `cache` inside a genuine root would redirect it one level down.
        let data_before = plain_dir(&data)?;
        let cache_before = plain_dir(&cache)?;
        let mut mode_unavailable = false;
        for (d, before) in [(&root, root_before), (&data, data_before), (&cache, cache_before)] {
            let mode = mkdir(d).map_err(|_| DirsError::Unwritable(root.clone()))?;
            mode_unavailable |= mode == Mode::Unavailable;
            // N-68: still the plain directory that was checked (or a fresh one).
            let after = plain_dir(d)?.ok_or_else(|| DirsError::DataDirInvalid(root.clone()))?;
            if before.is_some_and(|b| !same_entry(&b, &after)) {
                return Err(DirsError::DataDirInvalid(root.clone()));
            }
        }
        if !probe(&data) || !probe(&cache) {
            return Err(DirsError::Unwritable(root));
        }
        Ok(Self { data, cache, portable_root: Some(root), mode_unavailable })
    }
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
