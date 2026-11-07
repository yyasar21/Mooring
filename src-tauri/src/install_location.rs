//! Move to Applications (ADR-0028 §2): the pure half — where the running bundle lives, whether
//! the move is offered, what the dialog says, what the copy plan is, and the exact argv of
//! every fixed-path OS tool. The I/O half (macOS only) is `install_move`.
//!
//! * Offered only on the release channel (owner decision 47), only without a `portable`
//!   marker, only without a Homebrew cask, never in the copy relaunched by a move
//!   (`--mooring-moved`) and not again for a version the user answered "Not now" to.
//! * A translocated launch gets the same dialog first; both refusing answers end in the M-18
//!   refusal (a translocated copy cannot see its marker, so "portable or not" is unknowable).
//! * Never elevated, quarantine kept, an existing `Mooring.app` is replaced only when its
//!   `CFBundleIdentifier` is ours, it is older and not running.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use semver::Version;

use crate::build_identity::Channel;
use crate::commands::vsphere_confirm;
use crate::dirs::Dirs;

/// The installed bundle name (release `productName`).
pub const BUNDLE_NAME: &str = "Mooring.app";
/// Where macOS mounts disk images.
pub const VOLUMES: &str = "/Volumes";
/// Settings key of the version the user answered "Not now" for.
pub const DECLINED_KEY: &str = "app.install.move_declined";

/// Fixed absolute tool paths (ADR-0020 pattern: no `PATH`, no shell, cleared environment).
pub const DITTO: &str = "/usr/bin/ditto";
/// Signature check of the copy before the swap.
pub const CODESIGN: &str = "/usr/bin/codesign";
/// Relaunch.
pub const OPEN: &str = "/usr/bin/open";
/// Disk-image listing and detach.
pub const HDIUTIL: &str = "/usr/bin/hdiutil";
/// `CFBundleIdentifier` / `CFBundleShortVersionString` (binary and XML plists alike).
pub const PLIST_BUDDY: &str = "/usr/libexec/PlistBuddy";
/// Running-process check.
pub const PS: &str = "/bin/ps";

/// Relaunch flags (no data except the volume the new copy may detach).
pub const MOVED_FLAG: &str = "--mooring-moved";
/// The move replaced an older copy.
pub const REPLACED_FLAG: &str = "--mooring-replaced";
/// `--mooring-detach=/Volumes/<name>`: the disk image the old copy ran from.
pub const DETACH_PREFIX: &str = "--mooring-detach=";

/// The dialog's confirming label (middle slot, ADR-0013 / B-6).
pub const MOVE_LABEL: &str = "Move to Applications";
/// Dialog title.
pub const DIALOG_TITLE: &str = "Move Mooring to Applications?";

/// Where the running bundle lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// An App Translocation copy (M-18).
    Translocated,
    /// Under `/Volumes/<name>/`, not yet confirmed as a disk image.
    Volume(PathBuf),
    /// Under `/Volumes/<name>/` and `<name>` is a mounted disk image.
    DiskImage(PathBuf),
    /// Under the user's Downloads folder.
    Downloads,
    /// `/Applications` or `~/Applications` (any depth).
    Applications,
    /// Anywhere else, or not a bundle.
    Other,
}

impl Location {
    /// Audit / log name (no path).
    pub fn wire(&self) -> &'static str {
        match self {
            Self::Translocated => "translocated",
            Self::Volume(_) => "volume",
            Self::DiskImage(_) => "disk_image",
            Self::Downloads => "downloads",
            Self::Applications => "applications",
            Self::Other => "other",
        }
    }
}

/// The roots [`classify`] compares against (canonical paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    /// `/Applications` and `~/Applications`.
    pub applications: Vec<PathBuf>,
    /// The Downloads folder (Tauri `download_dir()`), when known.
    pub downloads: Option<PathBuf>,
    /// `/Volumes`.
    pub volumes: PathBuf,
}

impl Roots {
    /// The macOS roots for `home` and `downloads`.
    pub fn production(home: Option<&Path>, downloads: Option<PathBuf>) -> Self {
        let mut applications = vec![PathBuf::from("/Applications")];
        applications.extend(home.map(|h| h.join("Applications")));
        Self { applications, downloads, volumes: PathBuf::from(VOLUMES) }
    }
}

/// Whether `path` is absolute and free of `.` / `..` components.
fn plain_absolute(path: &Path) -> bool {
    path.is_absolute() && path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Classify a (canonical) `.app` bundle path. Pure.
pub fn classify(bundle: &Path, roots: &Roots) -> Location {
    if Dirs::translocated(bundle) {
        return Location::Translocated;
    }
    if !plain_absolute(bundle) || bundle.extension().is_none_or(|e| e != "app") {
        return Location::Other;
    }
    if roots.applications.iter().any(|r| bundle.starts_with(r)) {
        return Location::Applications;
    }
    if let Ok(rest) = bundle.strip_prefix(&roots.volumes) {
        let mut parts = rest.components();
        // `/Volumes/<name>/…/X.app`: the bundle must sit *inside* the volume.
        if let (Some(Component::Normal(name)), Some(_)) = (parts.next(), parts.next()) {
            return Location::Volume(roots.volumes.join(name));
        }
        return Location::Other;
    }
    if roots.downloads.as_deref().is_some_and(|d| bundle.starts_with(d)) {
        return Location::Downloads;
    }
    Location::Other
}

/// Confirm a [`Location::Volume`] against the image mounts (`hdiutil info`): a disk image
/// becomes [`Location::DiskImage`], any other volume (USB stick, network share) `Other`.
pub fn confirm_image(location: Location, image_mounts: &[PathBuf]) -> Location {
    match location {
        Location::Volume(m) if image_mounts.contains(&m) => Location::DiskImage(m),
        Location::Volume(_) => Location::Other,
        other => other,
    }
}

/// Mount points of disk images in `hdiutil info` text output: device lines are
/// `/dev/diskNsM<TAB>content hint<TAB>mount point`; only mount points under `/Volumes/`
/// count. Bounded by the runner's output cap; never panics on odd input.
pub fn parse_hdiutil_info(text: &str) -> Vec<PathBuf> {
    let mut mounts: Vec<PathBuf> = text
        .lines()
        .filter(|l| l.starts_with("/dev/disk"))
        .filter_map(|l| l.splitn(3, '\t').nth(2))
        .map(|m| m.trim_end_matches(['\r', '\n']))
        .filter(|m| m.starts_with("/Volumes/") && Path::new(m).components().count() == 3)
        .map(PathBuf::from)
        .filter(|p| plain_absolute(p))
        .collect();
    mounts.sort();
    mounts.dedup();
    mounts
}

/// Everything [`should_offer`] looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferFacts<'a> {
    /// Build channel.
    pub channel: Channel,
    /// Where the bundle runs from (after [`confirm_image`]).
    pub location: &'a Location,
    /// A `portable` marker sits next to the bundle (`Located::Portable`).
    pub portable: bool,
    /// This process was relaunched by a move.
    pub moved: bool,
    /// A Homebrew `Caskroom/mooring` exists (N-55).
    pub cask_present: bool,
    /// The stored "Not now" version.
    pub declined: Option<&'a str>,
    /// The running version.
    pub version: &'a str,
}

/// Whether the move is offered to a normally started process. Pure.
pub fn should_offer(f: &OfferFacts<'_>) -> bool {
    f.channel == Channel::Release
        && !f.portable
        && !f.moved
        && !f.cask_present
        && f.declined != Some(f.version)
        && matches!(f.location, Location::DiskImage(_) | Location::Downloads)
}

/// Whether a translocated launch gets the dialog before the M-18 refusal (release only,
/// never in a relaunched copy that was translocated again).
pub fn offer_translocated(channel: Channel, moved: bool) -> bool {
    channel == Channel::Release && !moved
}

/// The copy that would be replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    /// No `Mooring.app` in the target directory.
    Absent,
    /// Ours (`CFBundleIdentifier` matches), with its version when readable.
    Ours(Option<Version>),
    /// Another bundle id, or unreadable: never touched.
    Foreign,
}

/// What the move does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Copy; `replace` = an older copy of ours is swapped out.
    Copy {
        /// An existing copy is replaced.
        replace: bool,
    },
    /// The same or a newer copy is already installed: open that one, copy nothing.
    OpenExisting,
}

/// Why a move did not happen (`install.*` codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveError {
    /// The existing `Mooring.app` is not ours.
    NotOurs,
    /// The copy to replace is running.
    Running,
    /// `ditto` / `codesign` / rename / relaunch failed.
    CopyFailed,
    /// Neither `/Applications` nor `~/Applications` is writable.
    NotWritable,
}

impl MoveError {
    /// The code (audit `install.move_failed`, ipc-codes.json).
    pub fn code(self) -> &'static str {
        match self {
            Self::NotOurs => "install.not_ours",
            Self::Running => "install.running",
            Self::CopyFailed => "install.copy_failed",
            Self::NotWritable => "install.not_writable",
        }
    }

    /// One sentence for the message box.
    pub fn message(self) -> &'static str {
        match self {
            Self::NotOurs => "Another app named Mooring.app is already in Applications; Mooring left it alone.",
            Self::Running => "The Mooring in Applications is running. Quit it and try again.",
            Self::CopyFailed => "Mooring could not be copied to Applications. Drag it there with Finder instead.",
            Self::NotWritable => "Applications is not writable for this user. Drag Mooring there with Finder instead.",
        }
    }
}

/// The copy plan. Pure.
pub fn plan(existing: &Existing, ours: &Version, running: bool) -> Result<Plan, MoveError> {
    match existing {
        Existing::Absent => Ok(Plan::Copy { replace: false }),
        Existing::Foreign => Err(MoveError::NotOurs),
        Existing::Ours(Some(v)) if v >= ours => Ok(Plan::OpenExisting),
        Existing::Ours(_) if running => Err(MoveError::Running),
        Existing::Ours(_) => Ok(Plan::Copy { replace: true }),
    }
}

/// Where the copy goes (decision 44: `~/Applications` when `/Applications` is not writable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `/Applications`.
    Applications,
    /// `~/Applications` (created 0755).
    UserApplications,
}

impl Target {
    /// The writable target. Pure.
    pub fn choose(system_writable: bool) -> Self {
        if system_writable {
            Self::Applications
        } else {
            Self::UserApplications
        }
    }

    /// Absolute directory.
    pub fn dir(self, home: &Path) -> PathBuf {
        match self {
            Self::Applications => PathBuf::from("/Applications"),
            Self::UserApplications => home.join("Applications"),
        }
    }

    /// Dialog text name.
    pub fn display(self) -> &'static str {
        match self {
            Self::Applications => "/Applications",
            Self::UserApplications => "~/Applications",
        }
    }

    /// Audit value (`install.moved.target`).
    pub fn wire(self) -> &'static str {
        match self {
            Self::Applications => "applications",
            Self::UserApplications => "user_applications",
        }
    }

    /// Which target a relaunched copy runs from (`None`: not in either).
    pub fn of_bundle(bundle: &Path, home: Option<&Path>) -> Option<Self> {
        if bundle.parent() == Some(Path::new("/Applications")) {
            return Some(Self::Applications);
        }
        home.filter(|h| bundle.parent() == Some(h.join("Applications").as_path())).map(|_| Self::UserApplications)
    }
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// The middle slot.
    Move,
    /// The cancel slot (Escape / close box too, B-6): remembered for this version.
    NotNow,
    /// The first slot (Return): this run only.
    Cancel,
}

/// The three ADR-0013 slots: Cancel / Move to Applications / Not now.
pub fn buttons() -> tauri_plugin_dialog::MessageDialogButtons {
    vsphere_confirm::buttons(MOVE_LABEL)
}

/// Map a dialog result by label only; positions never confirm.
pub fn choice(r: &tauri_plugin_dialog::MessageDialogResult) -> Choice {
    use tauri_plugin_dialog::MessageDialogResult as R;
    match r {
        R::Custom(s) if vsphere_confirm::confirmed(r, MOVE_LABEL) && s == MOVE_LABEL => Choice::Move,
        R::Custom(s) if s == vsphere_confirm::NOT_NOW => Choice::NotNow,
        _ => Choice::Cancel,
    }
}

/// Dialog body: where Mooring runs, the target, and what an existing copy means.
pub fn dialog_text(location: &Location, target: Target, existing: &Existing) -> String {
    let from = match location {
        Location::DiskImage(m) => {
            let name = m.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            format!("Mooring is running from the disk image “{name}”.")
        }
        Location::Downloads => "Mooring is running from your Downloads folder.".to_owned(),
        Location::Translocated => "macOS is running Mooring from a temporary read-only copy.".to_owned(),
        _ => "Mooring is not in Applications.".to_owned(),
    };
    let to = target.display();
    let what = match existing {
        Existing::Ours(Some(v)) => format!(" This replaces Mooring {v} in {to}; your data stays where it is."),
        Existing::Ours(None) => format!(" This replaces the Mooring in {to}; your data stays where it is."),
        _ => String::new(),
    };
    let tail = if *location == Location::Translocated {
        " If this is a portable copy, choose Cancel and drag Mooring.app out of its folder and back in with Finder."
    } else {
        ""
    };
    format!("{from} Move it to {to} so it runs from a permanent place and can update itself.{what}{tail}")
}

/// What a relaunched copy was told.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MovedArgs {
    /// `--mooring-moved` was given.
    pub moved: bool,
    /// `--mooring-replaced` was given.
    pub replaced: bool,
    /// `--mooring-detach=<volume>` (unvalidated).
    pub detach: Option<PathBuf>,
}

/// Parse the relaunch flags; anything else (`-psn_…`, unknown) is ignored.
pub fn parse_args(args: impl IntoIterator<Item = OsString>) -> MovedArgs {
    let mut out = MovedArgs::default();
    for a in args {
        let Some(s) = a.to_str() else { continue };
        match s {
            MOVED_FLAG => out.moved = true,
            REPLACED_FLAG => out.replaced = true,
            _ => {
                if let Some(v) = s.strip_prefix(DETACH_PREFIX).filter(|v| !v.is_empty()) {
                    out.detach = Some(PathBuf::from(v));
                }
            }
        }
    }
    out
}

/// The flags the old copy passes to the new one.
pub fn relaunch_args(replaced: bool, detach: Option<&Path>) -> Vec<OsString> {
    let mut v = vec![OsString::from(MOVED_FLAG)];
    if replaced {
        v.push(REPLACED_FLAG.into());
    }
    if let Some(d) = detach {
        let mut s = OsString::from(DETACH_PREFIX);
        s.push(d.as_os_str());
        v.push(s);
    }
    v
}

/// Whether `volume` may be detached: exactly `/Volumes/<name>` and a listed image mount
/// (the bundle-id and no-vault checks are I/O, in `install_move`). Pure.
pub fn detach_candidate(volume: &Path, image_mounts: &[PathBuf]) -> bool {
    plain_absolute(volume)
        && volume.parent() == Some(Path::new(VOLUMES))
        && image_mounts.iter().any(|m| m == volume)
}

/// Whether a `ps -axww -o comm=` listing runs something inside `bundle`.
pub fn running_from(ps_output: &str, bundle: &Path) -> bool {
    let prefix = format!("{}/", bundle.display());
    ps_output.lines().any(|l| l.trim_start().starts_with(&prefix))
}

fn os(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

/// `ditto <src> <tmp>`: copies the bundle with its extended attributes (quarantine kept).
pub fn ditto_argv(src: &Path, tmp: &Path) -> Vec<OsString> {
    vec![src.into(), tmp.into()]
}

/// `codesign --verify --deep --strict <copy>`.
pub fn codesign_argv(copy: &Path) -> Vec<OsString> {
    let mut v = os(&["--verify", "--deep", "--strict"]);
    v.push(copy.into());
    v
}

/// `open [-n] <app> [--args …]`.
pub fn open_argv(app: &Path, new_instance: bool, args: &[OsString]) -> Vec<OsString> {
    let mut v = Vec::new();
    if new_instance {
        v.push("-n".into());
    }
    v.push(app.into());
    if !args.is_empty() {
        v.push("--args".into());
        v.extend(args.iter().cloned());
    }
    v
}

/// `hdiutil info` (text form).
pub fn hdiutil_info_argv() -> Vec<OsString> {
    os(&["info"])
}

/// `hdiutil detach <volume> -quiet` (no `-force`).
pub fn detach_argv(volume: &Path) -> Vec<OsString> {
    vec!["detach".into(), volume.into(), "-quiet".into()]
}

/// `PlistBuddy -c "Print :<key>" <app>/Contents/Info.plist`.
pub fn plist_argv(app: &Path, key: &str) -> Vec<OsString> {
    vec!["-c".into(), format!("Print :{key}").into(), app.join("Contents/Info.plist").into()]
}

/// `ps -axww -o comm=`.
pub fn ps_argv() -> Vec<OsString> {
    os(&["-axww", "-o", "comm="])
}

#[cfg(test)]
#[path = "install_location_tests.rs"]
mod tests;
