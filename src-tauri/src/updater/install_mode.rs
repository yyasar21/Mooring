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
    /// A portable folder (ADR-0021 §2): the user replaces the folder with the new zip.
    Portable,
    /// A development build (ADR-0028 §1): no updater, the user builds the next one.
    DevBuild,
    /// A Windows install made by winget (ADR-0018 A2): `winget upgrade` keeps winget's view
    /// of the installed version consistent.
    Winget,
}

impl ManualReason {
    /// The IPC error code `update_install` answers with.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotWritable => "update.not_writable",
            Self::PackageManager
            | Self::Homebrew
            | Self::NotBundled
            | Self::Portable
            | Self::DevBuild
            | Self::Winget => {
                "update.manual_only"
            }
        }
    }

    /// One safe sentence for the UI.
    pub fn message(self) -> &'static str {
        match self {
            Self::PackageManager => "installed by a package manager: update it there",
            Self::Homebrew => "installed by Homebrew: run `brew upgrade --cask mooring`",
            Self::NotWritable => "the install location is not writable by this user",
            Self::NotBundled => "not an installed bundle",
            Self::Portable => "portable build: download the new zip and replace the folder",
            Self::DevBuild => "development build: updates come from your own builds",
            Self::Winget => "installed by winget: run `winget upgrade yyasar21.Mooring`",
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
#[allow(clippy::struct_excessive_bools)] // independent facts the matrix reads in a fixed order
pub struct InstallFacts {
    /// Bundle kind.
    pub bundle: Bundle,
    /// What would be replaced: the `AppImage` file, the `.app` bundle, the NSIS install
    /// directory. Shown nowhere; used for the Homebrew check.
    pub install_path: PathBuf,
    /// Whether this user can write `install_path` **and** its parent (the plugin renames the
    /// old install aside and the new one into place).
    pub writable: bool,
    /// A Homebrew `Caskroom/mooring` directory exists (N-55): the cask owns the install even
    /// when its `.app` was moved to `/Applications`.
    pub cask_present: bool,
    /// Portable mode (ADR-0021, `Dirs::portable_root.is_some()`): checked before the bundle.
    pub portable: bool,
    /// A development build (ADR-0028, `Channel::Dev`): checked before everything else.
    pub dev_build: bool,
    /// A winget install (ADR-0018 A2, [`winget_marker`]): read for NSIS only.
    pub winget: bool,
}

/// Homebrew Caskroom roots (Apple silicon and Intel prefixes). Review 7 N-55: a cask
/// `app` stanza **moves** `Mooring.app` into `/Applications` (older casks and `brew link`
/// symlink it), so the bundle path alone does not identify a cask install; the probe also
/// reports whether a `Caskroom/mooring` directory exists under either root.
pub const CASKROOMS: &[&str] = &["/opt/homebrew/Caskroom/", "/usr/local/Caskroom/"];

/// The cask token Homebrew installs this app under.
pub const CASK_TOKEN: &str = "mooring";

/// Whether `path` (already canonicalised by the probe, so a symlinked `/Applications/…`
/// resolves to its Caskroom target) lies under one of `roots`.
pub(crate) fn under_roots(path: &Path, roots: &[&Path]) -> bool {
    roots.iter().any(|r| path.starts_with(r))
}

/// [`under_roots`] with the production Caskroom roots.
fn under_homebrew(path: &Path) -> bool {
    let roots: Vec<&Path> = CASKROOMS.iter().map(Path::new).collect();
    under_roots(path, &roots)
}

/// Whether `<root>/<token>` exists under any of `roots` (the cask is installed, wherever its
/// `.app` was moved to).
pub(crate) fn cask_present_in(roots: &[&Path], token: &str) -> bool {
    roots.iter().any(|r| r.join(token).is_dir())
}

/// Marker file next to the executable of a NSIS install (ADR-0018 A2). winget runs the same
/// per-user NSIS installer as a direct download, so no install path tells them apart; the
/// installer is to write this file with the content `winget` when winget runs it. No
/// installer writes it yet (inert by design; release-engineer contract in
/// `docs/handoff/a5-rust-core-r6.md`).
pub const INSTALL_SOURCE_FILE: &str = "install-source";
/// Largest marker read; anything bigger is not a marker.
pub const INSTALL_SOURCE_MAX: u64 = 64;

/// Whether `dir/install-source` exists and its trimmed content is exactly `winget`. Read with
/// a [`INSTALL_SOURCE_MAX`] cap; a missing, oversized, non-UTF-8 or different file is `false`.
pub fn winget_marker(dir: &Path) -> bool {
    use std::io::Read as _;
    let Ok(file) = std::fs::File::open(dir.join(INSTALL_SOURCE_FILE)) else { return false };
    let mut buf = Vec::new();
    if file.take(INSTALL_SOURCE_MAX + 1).read_to_end(&mut buf).is_err()
        || buf.len() as u64 > INSTALL_SOURCE_MAX
    {
        return false;
    }
    std::str::from_utf8(&buf).is_ok_and(|t| t.trim() == "winget")
}

/// The matrix (ADR-0018 §3). Pure.
pub fn decide(facts: &InstallFacts) -> InstallMode {
    use ManualReason as R;
    if facts.dev_build {
        return InstallMode::Manual(R::DevBuild);
    }
    if facts.portable {
        return InstallMode::Manual(R::Portable);
    }
    // After portable, before writability (orchestrator decision): NSIS only.
    if facts.winget && facts.bundle == Bundle::Nsis {
        return InstallMode::Manual(R::Winget);
    }
    match facts.bundle {
        Bundle::Deb | Bundle::Rpm | Bundle::Msi => InstallMode::Manual(R::PackageManager),
        Bundle::Unknown => InstallMode::Manual(R::NotBundled),
        Bundle::MacApp if facts.cask_present || under_homebrew(&facts.install_path) => {
            InstallMode::Manual(R::Homebrew)
        }
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
pub struct OsProbe {
    /// Portable mode (from `Dirs` at setup).
    pub portable: bool,
    /// Development build (`Channel::CURRENT`, ADR-0028).
    pub dev_build: bool,
}

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
        // The path only picks the install *mode* (in-app vs manual); it never decides whether
        // an update is trusted — the plugin verifies the signature regardless (ADR-0018 §3).
        let exe = std::env::current_exe().ok()?; // nosemgrep
        let install_path = Self::install_path(bundle, &exe)?;
        // A symlinked `.app` resolves to its Caskroom target; a moved one is caught by
        // `cask_present` (N-55).
        let resolved = std::fs::canonicalize(&install_path).unwrap_or_else(|_| install_path.clone());
        let roots: Vec<&Path> = CASKROOMS.iter().map(Path::new).collect();
        let cask_present = bundle == Bundle::MacApp && cask_present_in(&roots, CASK_TOKEN);
        let writable = match bundle {
            Bundle::AppImage => file_writable(&resolved) && dir_writable(resolved.parent()),
            Bundle::MacApp | Bundle::Nsis => dir_writable(Some(&resolved)) && dir_writable(resolved.parent()),
            _ => false,
        };
        // NSIS: `install_path` is `exe.parent()`, where the installer would put the marker.
        let winget = bundle == Bundle::Nsis && winget_marker(&install_path);
        Some(InstallFacts {
            bundle,
            install_path: resolved,
            writable,
            cask_present,
            portable: self.portable,
            dev_build: self.dev_build,
            winget,
        })
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

#[cfg(test)]
#[path = "winget_tests.rs"]
mod winget_tests;
