//! Local side of SFTP transfers: a path confined to a caller-chosen base directory.
//!
//! The relative part may only contain normal components (no `..`, no root, no drive prefix),
//! and the resolved path must stay under the canonical base after following symlinks.
//! On every platform a component may not contain `:` (a Windows alternate data stream) or be
//! a reserved DOS device name (`CON`, `NUL`, `COM1`, ...), so a path accepted on one OS is
//! safe on all of them (security review 2, L-7). Errors never contain local paths.

use std::path::{Component, Path, PathBuf};

use mooring_core::MooringError;

/// Longest relative local path accepted, in bytes.
pub const MAX_LOCAL_PATH: usize = 4096;

/// A local file path `base/relative`, confined to `base`.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalPath {
    base: PathBuf,
    relative: PathBuf,
}

impl std::fmt::Debug for LocalPath {
    // Only the relative part: the base may reveal the user's home directory layout.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalPath").field("relative", &self.relative).finish_non_exhaustive()
    }
}

fn invalid(reason: &str) -> MooringError {
    MooringError::Invalid { field: "local path", reason: reason.to_owned() }
}

/// Reserved DOS device names; Windows maps them to devices with any extension.
const RESERVED: [&str; 8] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "COM0"];

/// Whether `name` is a Windows device name: [`RESERVED`], `COM1`..`COM9`, `LPT0`..`LPT9`
/// (also with superscript digits), compared case-insensitively on the stem before the first
/// `.`, with trailing spaces ignored as Windows does.
fn is_reserved_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) || stem == "LPT0" {
        return true;
    }
    let (prefix, digit) = (stem.get(..3), stem.get(3..));
    matches!(prefix, Some("COM" | "LPT"))
        && matches!(
            digit,
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        )
}

/// Component rules beyond the lexical ones: no stream separator, no device name.
fn check_component(part: &std::ffi::OsStr) -> Result<(), MooringError> {
    let text = part.to_string_lossy();
    if text.contains(':') {
        return Err(invalid("must not contain ':' (alternate data stream)"));
    }
    if is_reserved_device(&text) {
        return Err(invalid("must not be a reserved device name"));
    }
    Ok(())
}

impl LocalPath {
    /// Validate the relative part lexically. Symlinks are checked when the path is used.
    pub fn new(base: impl Into<PathBuf>, relative: impl AsRef<Path>) -> Result<Self, MooringError> {
        let relative = relative.as_ref();
        if relative.as_os_str().len() > MAX_LOCAL_PATH {
            return Err(invalid("too long"));
        }
        let mut clean = PathBuf::new();
        for component in relative.components() {
            match component {
                Component::Normal(part) => {
                    check_component(part)?;
                    clean.push(part);
                }
                Component::CurDir => {}
                Component::ParentDir => return Err(invalid("must not contain '..'")),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(invalid("must be relative to the base directory"));
                }
            }
        }
        if clean.as_os_str().is_empty() {
            return Err(invalid("names no file"));
        }
        Ok(Self { base: base.into(), relative: clean })
    }

    /// The relative part, safe to show.
    pub fn relative(&self) -> &Path {
        &self.relative
    }

    fn canonical_base(&self) -> Result<PathBuf, MooringError> {
        std::fs::canonicalize(&self.base).map_err(|_| invalid("base directory not found"))
    }

    /// Resolve an existing regular file to read (upload source).
    pub(crate) fn resolve_existing_file(&self) -> Result<PathBuf, MooringError> {
        let base = self.canonical_base()?;
        let full = std::fs::canonicalize(base.join(&self.relative))
            .map_err(|_| invalid("file not found"))?;
        if !full.starts_with(&base) {
            return Err(invalid("escapes the base directory"));
        }
        if !std::fs::metadata(&full).is_ok_and(|m| m.is_file()) {
            return Err(invalid("not a regular file"));
        }
        Ok(full)
    }

    /// Resolve a file to create or replace (download target). The parent directory must
    /// exist under the base; an existing target must not be a symlink or a directory.
    /// Returns `(parent, final path)`.
    pub(crate) fn resolve_new_file(&self) -> Result<(PathBuf, PathBuf), MooringError> {
        let base = self.canonical_base()?;
        let name = self.relative.file_name().ok_or_else(|| invalid("names no file"))?;
        let parent_rel = self.relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = std::fs::canonicalize(base.join(parent_rel))
            .map_err(|_| invalid("parent directory not found"))?;
        if !parent.starts_with(&base) {
            return Err(invalid("escapes the base directory"));
        }
        if !std::fs::metadata(&parent).is_ok_and(|m| m.is_dir()) {
            return Err(invalid("parent is not a directory"));
        }
        let full = parent.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&full) {
            if meta.file_type().is_symlink() {
                return Err(invalid("target is a symlink"));
            }
            if meta.is_dir() {
                return Err(invalid("target is a directory"));
            }
        }
        Ok((parent, full))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_checks() {
        assert!(LocalPath::new("/b", "a/b.txt").is_ok());
        assert_eq!(LocalPath::new("/b", "./a/./b").expect("ok").relative(), Path::new("a/b"));
        for bad in ["../x", "a/../../x", "a/..", "/etc/passwd", "", ".", "./"] {
            assert!(LocalPath::new("/b", bad).is_err(), "{bad:?} accepted");
        }
        assert!(LocalPath::new("/b", "x".repeat(MAX_LOCAL_PATH + 1)).is_err());
    }

    #[test]
    fn alternate_data_streams_are_rejected() {
        for bad in ["file.txt:stream", "a/b:$DATA", "x::$INDEX_ALLOCATION", "dir:s/f"] {
            assert!(LocalPath::new("/b", bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn reserved_device_names_are_rejected() {
        for bad in [
            "CON",
            "con",
            "Prn.txt",
            "aux.tar.gz",
            "NUL",
            "nul ",
            "COM1",
            "com9.log",
            "LPT1",
            "lpt9",
            "COM\u{b9}",
            "conin$",
            "CONOUT$.x",
            "a/NUL/b",
            "sub/com3.txt",
        ] {
            assert!(LocalPath::new("/b", bad).is_err(), "{bad:?} accepted");
        }
        for ok in ["CONSOLE", "com", "COM10", "LPT", "nul_file", "aux-backup", "x.con", "COMA"] {
            assert!(LocalPath::new("/b", ok).is_ok(), "{ok:?} refused");
        }
    }

    #[test]
    fn debug_hides_base() {
        let p = LocalPath::new("/home/secret-user", "f").expect("ok");
        assert!(!format!("{p:?}").contains("secret-user"));
    }

    #[test]
    fn errors_never_contain_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = LocalPath::new(dir.path(), "missing/file").expect("ok");
        let err = p.resolve_new_file().expect_err("no parent").to_string();
        assert!(!err.contains(&*dir.path().to_string_lossy()), "{err}");
        assert!(!err.contains("missing"), "{err}");
    }

    #[test]
    fn resolves_inside_base() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
        std::fs::write(dir.path().join("sub/f"), b"x").expect("write");
        let p = LocalPath::new(dir.path(), "sub/f").expect("ok");
        assert!(p.resolve_existing_file().is_ok());
        let (_, full) = p.resolve_new_file().expect("new");
        assert!(full.ends_with("sub/f"));
        let d = LocalPath::new(dir.path(), "sub").expect("ok");
        assert!(d.resolve_new_file().is_err(), "directory target");
        assert!(d.resolve_existing_file().is_err(), "directory source");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escapes_are_rejected() {
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret"), b"s").expect("write");
        let dir = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).expect("symlink");
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("f"))
            .expect("symlink");
        let via_dir = LocalPath::new(dir.path(), "link/secret").expect("lexically ok");
        assert!(via_dir.resolve_existing_file().is_err());
        assert!(via_dir.resolve_new_file().is_err());
        let via_file = LocalPath::new(dir.path(), "f").expect("lexically ok");
        assert!(via_file.resolve_existing_file().is_err());
        assert!(via_file.resolve_new_file().is_err());
    }
}
