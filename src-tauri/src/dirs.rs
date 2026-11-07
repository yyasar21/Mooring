//! Data and cache directories, resolved once at start (ADR-0021 §1).
//!
//! Portable mode is a **regular file** named [`Dirs::MARKER`] next to the executable (the
//! `.app` bundle on macOS, the `AppImage` file on Linux). Its content is ignored. When present
//! every file location lives under `<marker dir>/Mooring Data/{data,cache}`; when the marker
//! is absent the OS application directories are used. An invalid or unusable marker set-up is
//! an error and **never** falls back to the OS directories (owner decision 2026-11-07): a user
//! who put the vault on a USB stick must know where it went.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::create_private_dir;

/// Resolved directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    /// Vault header, audit log, `mooring.db`, `known_hosts`, web stores.
    pub data: PathBuf,
    /// Ephemeral web profiles; in portable mode also the main window's `WebView` profile.
    pub cache: PathBuf,
    /// `<marker dir>/Mooring Data` when portable, else `None`.
    pub portable_root: Option<PathBuf>,
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
            Self::Os(_) => "app.data_dir",
        }
    }

    /// The directory the message box names.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::MarkerInvalid(p) | Self::DataDirInvalid(p) | Self::Unwritable(p) => Some(p),
            Self::Os(_) => None,
        }
    }
}

impl std::fmt::Display for DirsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MarkerInvalid(p) => write!(
                f,
                "The portable marker {} is not a regular file (a link or a folder). Replace it with an empty file named \"portable\" or remove it.",
                p.display()
            ),
            Self::DataDirInvalid(p) => write!(
                f,
                "{} exists but is not a plain folder (a link or a file). Mooring will not store data through it.",
                p.display()
            ),
            Self::Unwritable(p) => write!(
                f,
                "{} is not writable. Move the Mooring folder somewhere writable or remove the \"portable\" marker file.",
                p.display()
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
fn app_bundle(exe: &Path) -> Option<&Path> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    let is = |p: &Path, name: &str| p.file_name().is_some_and(|n| n == name);
    (is(macos, "MacOS") && is(contents, "Contents") && app.extension().is_some_and(|e| e == "app"))
        .then_some(app)
}

impl Dirs {
    /// Marker file name.
    pub const MARKER: &'static str = "portable";
    /// Data root name under the marker directory.
    pub const ROOT: &'static str = "Mooring Data";
    /// `cache/webview`: the main window's `WebView` profile in portable mode (Windows, Linux).
    pub const WEBVIEW_DIR: &'static str = "webview";

    /// The directory the marker is looked up in (pure). `AppImage`: the parent of `$APPIMAGE`
    /// (the executable itself runs from a squashfs mount); macOS: the parent of the `.app`
    /// bundle, never inside it (read-only, ad-hoc signed); otherwise the executable's parent.
    pub fn marker_dir(exe: &Path, appimage: Option<&Path>) -> Option<PathBuf> {
        if let Some(image) = appimage {
            return image.parent().map(Path::to_path_buf);
        }
        if let Some(app) = app_bundle(exe) {
            return app.parent().map(Path::to_path_buf);
        }
        exe.parent().map(Path::to_path_buf)
    }

    /// OS application directories, both created owner-only.
    pub fn plain(data: PathBuf, cache: PathBuf) -> Self {
        Self { data, cache, portable_root: None }
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
    /// `create_private_dir`.
    pub fn resolve(
        exe: &Path,
        appimage: Option<&Path>,
        os_default: &dyn Fn() -> tauri::Result<(PathBuf, PathBuf)>,
        probe: &dyn Fn(&Path) -> bool,
    ) -> Result<Self, DirsError> {
        let marker_dir = Self::marker_dir(exe, appimage);
        let marker = marker_dir.as_ref().map(|d| d.join(Self::MARKER));
        match marker.as_ref().map(std::fs::symlink_metadata) {
            // No marker directory at all (a bare executable path) or no marker: OS dirs.
            None => return Self::os_dirs(os_default),
            Some(Err(e)) if e.kind() == ErrorKind::NotFound => return Self::os_dirs(os_default),
            Some(Ok(m)) if m.is_file() && !is_link(&m) => {}
            // A symlink, reparse point, directory or something unreadable: refused.
            Some(_) => return Err(DirsError::MarkerInvalid(marker.unwrap_or_default())),
        }
        let Some(dir) = marker_dir else {
            return Err(DirsError::MarkerInvalid(PathBuf::from(Self::MARKER)));
        };
        Self::portable_under(&dir, probe)
    }

    fn os_dirs(os_default: &dyn Fn() -> tauri::Result<(PathBuf, PathBuf)>) -> Result<Self, DirsError> {
        let (data, cache) = os_default().map_err(DirsError::Os)?;
        create_private_dir(&data).map_err(|_| DirsError::Unwritable(data.clone()))?;
        create_private_dir(&cache).map_err(|_| DirsError::Unwritable(cache.clone()))?;
        Ok(Self::plain(data, cache))
    }

    /// `<dir>/Mooring Data/{data,cache}`, created and checked.
    fn portable_under(dir: &Path, probe: &dyn Fn(&Path) -> bool) -> Result<Self, DirsError> {
        let root = dir.join(Self::ROOT);
        match std::fs::symlink_metadata(&root) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if !probe(dir) {
                    return Err(DirsError::Unwritable(dir.to_path_buf()));
                }
            }
            Ok(m) if m.is_dir() && !is_link(&m) => {}
            _ => return Err(DirsError::DataDirInvalid(root)),
        }
        let data = root.join("data");
        let cache = root.join("cache");
        for d in [&root, &data, &cache] {
            create_private_dir(d).map_err(|_| DirsError::Unwritable(root.clone()))?;
        }
        if !probe(&data) || !probe(&cache) {
            return Err(DirsError::Unwritable(root));
        }
        Ok(Self { data, cache, portable_root: Some(root) })
    }
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
