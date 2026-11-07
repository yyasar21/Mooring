//! Windows ACL for the portable data root (ADR-0021 "Security consequences", owner decision
//! 2026-11-07). `create_private_dir` is 0700 on unix and relies on the per-user `%APPDATA%`
//! ACL on Windows; a portable `Mooring Data` on the Desktop or a USB stick inherits whatever
//! its parent grants (often `Users: read`). This runs `icacls.exe` **once per start** to
//! remove inheritance and grant full control to the directory's **owner** only.
//!
//! The grantee is the well-known `OWNER RIGHTS` SID (`S-1-3-4`), which an ACE binds to whoever
//! owns the object at access-check time: the user who created `Mooring Data` (unelevated, so
//! never the Administrators group), and after a copy to another machine the copying user. It
//! needs no account name (no `%USERNAME%` trust, no `whoami`, no Win32 crate) and a subdir or
//! file created later inherits it (`(OI)(CI)`) with the same creator as owner.
//!
//! ADR-0020 pattern: fixed absolute tool path, fixed argv, no shell, cleared environment, null
//! stdin, output capped, 10 s wall clock after which the child is killed. Failure (FAT32 /
//! exFAT media have no ACLs; policy may block `icacls`) is reported to the caller, who audits
//! `portable.acl_unavailable`; it is never fatal — the vault is encrypted at rest regardless.

use std::path::Path;
use std::time::Duration;

/// Wall clock for one `icacls` run.
pub const DEADLINE: Duration = Duration::from_secs(10);
/// Output kept from the child (per stream), for the log only.
pub const MAX_OUTPUT: usize = 4096;
/// `icacls`'s fixed location.
pub const ICACLS: &str = "C:\\Windows\\System32\\icacls.exe";
/// `OWNER RIGHTS` (well-known SID `S-1-3-4`) with full control, inherited by children.
pub const GRANT: &str = "*S-1-3-4:(OI)(CI)F";

/// The exact argv (after the program) for `root` (pure; tested).
pub fn argv(root: &Path) -> [std::ffi::OsString; 4] {
    [
        root.as_os_str().to_owned(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        GRANT.into(),
    ]
}

/// Why the ACL could not be applied (logged by kind only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclError {
    /// `icacls.exe` could not be started.
    Spawn,
    /// The deadline passed; the child was killed.
    Timeout,
    /// `icacls` exited non-zero (no ACL support on the volume, policy, …).
    Failed(Option<i32>),
}

/// Make `root` owner-only. Not Windows: nothing to do (unix mode 0700 already applies).
#[cfg(not(windows))]
pub fn apply(root: &Path) -> Result<(), AclError> {
    let _ = root;
    Ok(())
}

/// Make `root` owner-only with `icacls` (see the module doc).
#[cfg(windows)]
pub fn apply(root: &Path) -> Result<(), AclError> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(ICACLS);
    cmd.args(argv(root))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // CREATE_NO_WINDOW: no console flashes up behind the app.
        .creation_flags(0x0800_0000);
    if let Some(sys) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", sys);
    }
    let mut child = cmd.spawn().map_err(|e| {
        tracing::warn!(error = %e.kind(), "icacls spawn failed");
        AclError::Spawn
    })?;
    let out = child.stdout.take().map(capped_reader);
    let err = child.stderr.take().map(capped_reader);
    let status = wait_with_deadline(&mut child, DEADLINE);
    let (out, err) = (out.map(join).unwrap_or_default(), err.map(join).unwrap_or_default());
    match status {
        Some(s) if s.success() => Ok(()),
        Some(s) => {
            tracing::warn!(code = ?s.code(), stdout = %out, stderr = %err, "icacls failed");
            Err(AclError::Failed(s.code()))
        }
        None => {
            tracing::warn!("icacls did not finish within the deadline; killed");
            Err(AclError::Timeout)
        }
    }
}

/// Read at most [`MAX_OUTPUT`] bytes of `r` on its own thread (the child never blocks on a
/// full pipe while the deadline loop waits).
#[cfg(windows)]
fn capped_reader<R: std::io::Read + Send + 'static>(r: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = r.take(MAX_OUTPUT as u64).read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).trim().to_owned()
    })
}

#[cfg(windows)]
fn join(h: std::thread::JoinHandle<String>) -> String {
    h.join().unwrap_or_default()
}

/// Poll `child` until it exits or `deadline` passes (then kill it). `None` = killed.
#[cfg(windows)]
fn wait_with_deadline(child: &mut std::process::Child, deadline: Duration) -> Option<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if start.elapsed() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => {
                let _ = child.kill();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_fixed_and_names_only_the_root() {
        let root = Path::new("D:\\Mooring\\Mooring Data");
        let a = argv(root);
        assert_eq!(a[0], root.as_os_str());
        assert_eq!(a[1], "/inheritance:r");
        assert_eq!(a[2], "/grant:r");
        assert_eq!(a[3], "*S-1-3-4:(OI)(CI)F");
        assert_eq!(ICACLS, "C:\\Windows\\System32\\icacls.exe");
        assert_eq!(DEADLINE, Duration::from_secs(10));
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_is_a_no_op() {
        assert_eq!(apply(Path::new("/nonexistent/Mooring Data")), Ok(()));
    }

    /// On the CI Windows runner the temp directory is NTFS: the grant applies, and the
    /// directory stays usable by its owner.
    #[cfg(windows)]
    #[test]
    fn ntfs_root_becomes_owner_only_and_stays_writable() {
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("Mooring Data");
        std::fs::create_dir(&root).expect("mkdir");
        apply(&root).expect("icacls on NTFS");
        std::fs::write(root.join("probe"), b"x").expect("owner still writes");
        let sub = root.join("data");
        std::fs::create_dir(&sub).expect("child");
        std::fs::write(sub.join("probe"), b"x").expect("child writable");
        let missing = apply(Path::new("Z:\\no\\such\\dir"));
        assert!(matches!(missing, Err(AclError::Failed(_))), "{missing:?}");
    }
}
