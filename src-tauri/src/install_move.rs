//! Move to Applications (ADR-0028 §2): the I/O half. Fixed-path OS tools run through
//! [`Tools`] (production [`OsTools`]: no shell, cleared environment, null stdin, capped stdout,
//! wall-clock deadline, killed when it passes — the ADR-0020 pattern), so the copy, swap and
//! detach logic is tested on every OS with a scripted runner. The macOS start-up flows (dialog,
//! copy, relaunch, detach in the relaunched copy) live in `install_flow`.

use std::ffi::OsString;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use semver::Version;

use crate::build_identity::Channel;
use crate::dirs::Dirs;
use crate::install_location::{
    self as loc, Existing, MoveError, Plan, Target, BUNDLE_NAME, CODESIGN, DITTO, HDIUTIL, OPEN, PLIST_BUDDY, PS,
};

/// Deadline of `ditto`, `codesign` and `hdiutil detach` (ADR: 60 s).
pub const COPY_DEADLINE: Duration = Duration::from_secs(60);
/// Deadline of the read-only queries (`PlistBuddy`, `ps`, `hdiutil info`, `open`).
pub const QUERY_DEADLINE: Duration = Duration::from_secs(10);
/// Captured stdout per run; more is `truncated` (and the child killed).
pub const MAX_OUTPUT: usize = 256 * 1024;

/// What one tool run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolOutput {
    /// Stdout (lossy UTF-8), at most [`MAX_OUTPUT`] bytes.
    pub stdout: String,
    /// Exit status 0.
    pub success: bool,
    /// The cap was hit.
    pub truncated: bool,
}

/// Runs one fixed-path tool; `None` when it could not be spawned or passed its deadline.
pub trait Tools: Send + Sync {
    /// Run `tool` (one of the `install_location` constants) with `args`.
    fn run(&self, tool: &'static str, args: &[OsString], deadline: Duration) -> Option<ToolOutput>;
}

/// The real runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsTools;

impl Tools for OsTools {
    fn run(&self, tool: &'static str, args: &[OsString], deadline: Duration) -> Option<ToolOutput> {
        let mut child = Command::new(tool)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| tracing::warn!(tool, error = %e.kind(), "install tool spawn failed"))
            .ok()?;
        let reader = child.stdout.take().map(|out| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = out.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf);
                buf
            })
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if started.elapsed() < deadline => std::thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let mut bytes = reader.and_then(|r| r.join().ok()).unwrap_or_default();
        let Some(status) = status else {
            tracing::warn!(tool, "install tool passed its deadline; killed");
            return None;
        };
        let truncated = bytes.len() > MAX_OUTPUT;
        bytes.truncate(MAX_OUTPUT);
        Some(ToolOutput { stdout: String::from_utf8_lossy(&bytes).into_owned(), success: status.success(), truncated })
    }
}

/// A plist string value of `app` (`None` when unreadable, empty or absurdly long).
fn plist_value(tools: &dyn Tools, app: &Path, key: &str) -> Option<String> {
    let out = tools.run(PLIST_BUDDY, &loc::plist_argv(app, key), QUERY_DEADLINE)?;
    let v = out.stdout.trim();
    (out.success && !out.truncated && !v.is_empty() && v.len() <= 255).then(|| v.to_owned())
}

/// `CFBundleIdentifier` of `app`.
pub fn bundle_id(tools: &dyn Tools, app: &Path) -> Option<String> {
    plist_value(tools, app, "CFBundleIdentifier")
}

/// What sits at `dst`: absent, ours (with its version) or anything else (a link, a file, a
/// bundle with another or an unreadable identifier).
pub fn existing(tools: &dyn Tools, dst: &Path, our_id: &str) -> Existing {
    match std::fs::symlink_metadata(dst) {
        Err(e) if e.kind() == ErrorKind::NotFound => Existing::Absent,
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
            if bundle_id(tools, dst).as_deref() == Some(our_id) {
                let version = plist_value(tools, dst, "CFBundleShortVersionString").and_then(|v| Version::parse(&v).ok());
                Existing::Ours(version)
            } else {
                Existing::Foreign
            }
        }
        _ => Existing::Foreign,
    }
}

/// Whether something runs from inside `bundle`; fails closed (an unreadable or truncated
/// listing counts as running).
pub fn running(tools: &dyn Tools, bundle: &Path) -> bool {
    match tools.run(PS, &loc::ps_argv(), QUERY_DEADLINE) {
        Some(out) if out.success && !out.truncated => loc::running_from(&out.stdout, bundle),
        _ => true,
    }
}

/// Mounted disk images under `/Volumes/` (`hdiutil info`); empty when unreadable, so nothing
/// counts as a disk image (no offer, no detach).
pub fn image_mounts(tools: &dyn Tools) -> Vec<PathBuf> {
    match tools.run(HDIUTIL, &loc::hdiutil_info_argv(), QUERY_DEADLINE) {
        Some(out) if out.success && !out.truncated => loc::parse_hdiutil_info(&out.stdout),
        _ => Vec::new(),
    }
}

/// The target directory: `/Applications` when writable, else `~/Applications` (created 0755).
pub fn target_dir(home: &Path, writable: &dyn Fn(&Path) -> bool) -> Result<(Target, PathBuf), MoveError> {
    let target = Target::choose(writable(&Target::Applications.dir(home)));
    let dir = target.dir(home);
    if target == Target::UserApplications {
        create_0755(&dir).map_err(|_| MoveError::NotWritable)?;
        if !writable(&dir) {
            return Err(MoveError::NotWritable);
        }
    }
    Ok((target, dir))
}

fn create_0755(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o755).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// A random suffix for the temporary and the set-aside bundle.
pub fn nonce() -> String {
    let mut b = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    hex::encode(b)
}

fn remove(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok() && std::fs::remove_dir_all(path).is_err() {
        tracing::warn!("install: a temporary bundle could not be removed");
    }
}

/// `ditto` into `<dir>/.Mooring.app.<nonce>`, `codesign --verify` the copy, then [`swap`].
/// Any failure removes the temporary copy and leaves an existing install as it was.
pub fn copy_into(tools: &dyn Tools, src: &Path, dir: &Path, replace: bool, nonce: &str) -> Result<PathBuf, MoveError> {
    let dst = dir.join(BUNDLE_NAME);
    let tmp = dir.join(format!(".{BUNDLE_NAME}.{nonce}"));
    let ok = |o: Option<ToolOutput>| o.is_some_and(|o| o.success);
    if !ok(tools.run(DITTO, &loc::ditto_argv(src, &tmp), COPY_DEADLINE)) {
        remove(&tmp);
        return Err(MoveError::CopyFailed);
    }
    if !ok(tools.run(CODESIGN, &loc::codesign_argv(&tmp), COPY_DEADLINE)) {
        tracing::warn!("install: the copy failed its signature check");
        remove(&tmp);
        return Err(MoveError::CopyFailed);
    }
    swap(&dst, &tmp, replace, nonce)?;
    Ok(dst)
}

/// Put `tmp` at `dst`. Replacing: the old bundle is renamed aside first and renamed back when
/// the second rename fails (rollback), then removed. Not replacing: `dst` must still be free.
pub fn swap(dst: &Path, tmp: &Path, replace: bool, nonce: &str) -> Result<(), MoveError> {
    let fail = || {
        remove(tmp);
        Err(MoveError::CopyFailed)
    };
    if !replace {
        if std::fs::symlink_metadata(dst).is_ok() {
            return fail();
        }
        return std::fs::rename(tmp, dst).or_else(|_| fail());
    }
    let aside = dst.with_file_name(format!(".{BUNDLE_NAME}.old.{nonce}"));
    if std::fs::rename(dst, &aside).is_err() {
        return fail();
    }
    if std::fs::rename(tmp, dst).is_err() {
        if std::fs::rename(&aside, dst).is_err() {
            tracing::error!("install: rollback rename failed; the previous copy is set aside");
        }
        return fail();
    }
    remove(&aside);
    Ok(())
}

/// The result of a move the old copy relaunches from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// The bundle to open.
    pub app: PathBuf,
    /// An older copy was replaced.
    pub replaced: bool,
    /// `open -n` (a fresh copy) or plain `open` (an existing same-or-newer one).
    pub new_instance: bool,
}

/// The whole move, from the running bundle `src` (ours: `our_id`, `ours`).
pub fn perform(
    tools: &dyn Tools,
    src: &Path,
    home: &Path,
    our_id: &str,
    ours: &Version,
    writable: &dyn Fn(&Path) -> bool,
) -> Result<Moved, MoveError> {
    let (_, dir) = target_dir(home, writable)?;
    let dst = dir.join(BUNDLE_NAME);
    let found = existing(tools, &dst, our_id);
    let busy = matches!(found, Existing::Ours(_)) && running(tools, &dst);
    match loc::plan(&found, ours, busy)? {
        Plan::OpenExisting => Ok(Moved { app: dst, replaced: false, new_instance: false }),
        Plan::Copy { replace } => {
            let app = copy_into(tools, src, &dir, replace, &nonce())?;
            Ok(Moved { app, replaced: replace, new_instance: true })
        }
    }
}

/// `open [-n] <app> --args --mooring-moved …`.
pub fn relaunch(tools: &dyn Tools, moved: &Moved, detach: Option<&Path>) -> Result<(), MoveError> {
    let args = loc::relaunch_args(moved.replaced, detach);
    match tools.run(OPEN, &loc::open_argv(&moved.app, moved.new_instance, &args), QUERY_DEADLINE) {
        Some(o) if o.success => Ok(()),
        _ => Err(MoveError::CopyFailed),
    }
}

/// The I/O half of the detach check: `volume` holds our `Mooring.app` and no vault (no
/// portable data root of either channel, no marker).
pub fn volume_is_ours(tools: &dyn Tools, volume: &Path, our_id: &str) -> bool {
    let free = |name: &str| {
        matches!(std::fs::symlink_metadata(volume.join(name)), Err(e) if e.kind() == ErrorKind::NotFound)
    };
    let no_vault = [Dirs::root_name(Channel::Release), Dirs::root_name(Channel::Dev), Dirs::MARKER]
        .iter()
        .all(|n| free(n));
    no_vault && bundle_id(tools, &volume.join(BUNDLE_NAME)).as_deref() == Some(our_id)
}

/// Detach `volume` when it passes every check (`/Volumes/<name>`, an image mount, ours, no
/// vault). Returns whether it was detached; a failure is logged, never fatal.
pub fn detach_if_ours(tools: &dyn Tools, volume: &Path, our_id: &str) -> bool {
    let mounts = image_mounts(tools);
    if !loc::detach_candidate(volume, &mounts) || !volume_is_ours(tools, volume, our_id) {
        tracing::info!("install: the old volume was not detached (not an image of ours)");
        return false;
    }
    let ok = tools.run(HDIUTIL, &loc::detach_argv(volume), COPY_DEADLINE).is_some_and(|o| o.success);
    if !ok {
        tracing::warn!("install: hdiutil detach failed");
    }
    ok
}

#[cfg(test)]
#[path = "install_move_tests.rs"]
mod tests;
