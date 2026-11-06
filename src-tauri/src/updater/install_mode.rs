//! Install-mode matrix (ADR-0018 §3): in-app install only where no elevation is needed.
//!
//! Mooring never elevates. The plugin would fall back to `pkexec` / a sudo-password dialog
//! (deb, rpm), `msiexec` (MSI) or `AppleScript` "with administrator privileges" (a root-owned
//! `.app`); every such case is decided **here, before the plugin is asked**, so those paths are
//! never reached. The decision is a pure function of [`InstallFacts`]; the facts come from an
//! [`InstallProbe`] so the matrix is unit-tested on every OS with a scripted probe.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// How the running binary was installed (`tauri::utils::platform::bundle_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bundle {
    /// Linux `AppImage`: the file replaces itself in place.
    AppImage,
    /// Debian package: the plugin would run `dpkg` through `pkexec` / `sudo`.
    Deb,
    /// RPM package: same as deb.
    Rpm,
    /// macOS `.app` (also DMG installs): replaced by rename inside its parent directory.
    MacApp,
    /// Windows `WiX` MSI: `msiexec` is per-machine.
    Msi,
    /// Windows NSIS: per-user when installed with `installMode: currentUser` (our bundle).
    Nsis,
    /// Not a bundle (`cargo run`, a bare binary): nothing to replace.
    Unknown,
}

impl Bundle {
    /// Wire name, used in `manualReason` text and tests.
    pub fn name(self) -> &'static str {
        match self {
            Self::AppImage => "appimage",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::MacApp => "app",
            Self::Msi => "msi",
            Self::Nsis => "nsis",
            Self::Unknown => "unknown",
        }
    }
}

/// Why an install is manual (the UI shows the release page / a package-manager command).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualReason {
    /// deb / rpm / MSI: the package manager owns the files and needs elevation.
    PackageManager,
    /// A Homebrew cask: `brew upgrade --cask mooring` keeps the tap consistent.
    Homebrew,
    /// The install location is not writable by this user (root-owned `/Applications`, a
    /// per-machine NSIS install, a read-only `AppImage` directory).
    NotWritable,
    /// Not an installed bundle (development build).
    NotBundled,
}

impl ManualReason {
    /// The IPC error code `update_install` answers with.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotWritable => "update.not_writable",
            Self::PackageManager | Self::Homebrew | Self::NotBundled => "update.manual_only",
        }
    }

    /// One safe sentence for the UI.
    pub fn message(self) -> &'static str {
        match self {
            Self::PackageManager => "installed by a package manager: update it there",
            Self::Homebrew => "installed by Homebrew: run `brew upgrade --cask mooring`",
            Self::NotWritable => "the install location is not writable by this user",
            Self::NotBundled => "not an installed bundle",
        }
    }
}

/// The matrix result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    /// The plugin can replace the install without elevation.
    InApp,
    /// Shown as `installMode: "manual"` with `manualReason`.
    Manual(ManualReason),
}

/// What the matrix needs to know; gathered once per decision by an [`InstallProbe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFacts {
    /// Bundle kind.
    pub bundle: Bundle,
    /// What would be replaced: the `AppImage` file, the `.app` bundle, the NSIS install
    /// directory. Shown nowhere; used for the Homebrew check.
    pub install_path: PathBuf,
    /// Whether this user can write `install_path` **and** its parent (the plugin renames the
    /// old install aside and the new one into place).
    pub writable: bool,
}

/// Homebrew cask locations (Apple silicon and Intel prefixes).
const HOMEBREW_PREFIXES: &[&str] = &["/opt/homebrew/", "/usr/local/Caskroom/", "/usr/local/Homebrew/"];

/// Whether the path is inside a Homebrew prefix, or is a symlink target of one (casks link
/// `/Applications/Mooring.app` to the Caskroom; the probe resolves symlinks first).
fn under_homebrew(path: &Path) -> bool {
    let s = path.to_string_lossy();
    HOMEBREW_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// The matrix (ADR-0018 §3). Pure.
pub fn decide(facts: &InstallFacts) -> InstallMode {
    use ManualReason as R;
    match facts.bundle {
        Bundle::Deb | Bundle::Rpm | Bundle::Msi => InstallMode::Manual(R::PackageManager),
        Bundle::Unknown => InstallMode::Manual(R::NotBundled),
        Bundle::MacApp if under_homebrew(&facts.install_path) => InstallMode::Manual(R::Homebrew),
        Bundle::AppImage | Bundle::MacApp | Bundle::Nsis => {
            if facts.writable {
                InstallMode::InApp
            } else {
                InstallMode::Manual(R::NotWritable)
            }
        }
    }
}

/// Gathers [`InstallFacts`] for the running process. Injected so the matrix is testable.
pub trait InstallProbe: Send + Sync {
    /// The facts, or `None` when the executable path cannot be resolved (treated as
    /// [`Bundle::Unknown`] by the caller).
    fn facts(&self) -> Option<InstallFacts>;
}

/// The real probe: bundle type from the build, executable path from the OS, writability by
/// trying to create and remove a probe file next to the install (no `access(2)` guesswork
/// with ACLs, SIP or network mounts).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsProbe;

impl OsProbe {
    fn bundle() -> Bundle {
        use tauri::utils::config::BundleType as B;
        match tauri::utils::platform::bundle_type() {
            Some(B::Deb) => Bundle::Deb,
            Some(B::Rpm) => Bundle::Rpm,
            Some(B::AppImage) => Bundle::AppImage,
            Some(B::Msi) => Bundle::Msi,
            Some(B::Nsis) => Bundle::Nsis,
            Some(B::App | B::Dmg) => Bundle::MacApp,
            _ => Bundle::Unknown,
        }
    }

    /// What the plugin replaces for `bundle`, from the executable path.
    fn install_path(bundle: Bundle, exe: &Path) -> Option<PathBuf> {
        match bundle {
            Bundle::AppImage => std::env::var_os("APPIMAGE").map(PathBuf::from),
            // `Mooring.app/Contents/MacOS/mooring` → `Mooring.app`.
            Bundle::MacApp => exe.ancestors().find(|p| p.extension().is_some_and(|e| e == "app")).map(Path::to_path_buf),
            Bundle::Nsis => exe.parent().map(Path::to_path_buf),
            _ => Some(exe.to_path_buf()),
        }
    }
}

impl InstallProbe for OsProbe {
    fn facts(&self) -> Option<InstallFacts> {
        let bundle = Self::bundle();
        let exe = std::env::current_exe().ok()?;
        let install_path = Self::install_path(bundle, &exe)?;
        // Casks symlink into /Applications; the Caskroom is what Homebrew owns.
        let resolved = std::fs::canonicalize(&install_path).unwrap_or_else(|_| install_path.clone());
        let writable = match bundle {
            Bundle::AppImage => file_writable(&resolved) && dir_writable(resolved.parent()),
            Bundle::MacApp | Bundle::Nsis => dir_writable(Some(&resolved)) && dir_writable(resolved.parent()),
            _ => false,
        };
        Some(InstallFacts { bundle, install_path: resolved, writable })
    }
}

/// Open for append without writing: fails with `EACCES` / `EROFS` when not writable.
pub(crate) fn file_writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

/// Create and remove a uniquely named empty file in `dir`.
pub(crate) fn dir_writable(dir: Option<&Path>) -> bool {
    let Some(dir) = dir else { return false };
    let mut nonce = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let probe = dir.join(format!(".mooring-update-probe-{}", hex::encode(nonce)));
    let ok = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).is_ok();
    if ok {
        let _ = std::fs::remove_file(&probe);
    }
    ok
}
