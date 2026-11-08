//! Persisted SHA-256 pins of the `bws` binary (review 9 L-50). The first trusted run of a path
//! pins its hash; a later run whose binary hashes differently is refused with
//! `secret.tool_changed` until `secret_source_test` re-trusts it. The pins live in one small
//! JSON map (`{ "<path>": "<sha256 hex>" }`) in the app data directory, or in memory when no
//! file is configured (tests). A pin file that cannot be read counts as "changed", never as
//! "no pin": deleting or corrupting it must not silently re-trust a binary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Largest pin file read.
const MAX_PIN_FILE: u64 = 64 * 1024;
/// Most paths pinned; older entries are dropped when a new path is pinned past the cap.
const MAX_PINS: usize = 32;

/// What the pins say about one binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known {
    /// Never pinned (first use).
    New,
    /// The pinned hash.
    Same,
    /// Another hash is pinned, or the pin file is unreadable.
    Changed,
}

/// The pin store of one runner.
#[derive(Debug, Default)]
pub(crate) struct Pins {
    file: Option<PathBuf>,
    mem: Mutex<BTreeMap<String, String>>,
}

fn key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

impl Pins {
    pub(crate) fn new(file: Option<PathBuf>) -> Self {
        Self { file, mem: Mutex::default() }
    }

    fn read(&self) -> Result<BTreeMap<String, String>, ()> {
        let Some(file) = &self.file else {
            return Ok(self.mem.lock().unwrap_or_else(PoisonError::into_inner).clone());
        };
        match std::fs::symlink_metadata(file) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Ok(m) if m.is_file() && m.len() <= MAX_PIN_FILE => {}
            _ => return Err(()),
        }
        let bytes = std::fs::read(file).map_err(|_| ())?;
        serde_json::from_slice(&bytes).map_err(|_| ())
    }

    /// Compare `sha256` with the pin of `path`.
    pub(crate) fn check(&self, path: &Path, sha256: &[u8; 32]) -> Known {
        match self.read() {
            Err(()) => Known::Changed,
            Ok(m) => match m.get(&key(path)) {
                None => Known::New,
                Some(h) if *h == hex::encode(sha256) => Known::Same,
                Some(_) => Known::Changed,
            },
        }
    }

    /// Pin `sha256` for `path` (replacing an old pin). A write failure is logged: the next
    /// run then finds no pin and trusts on first use again, the pre-L-50 behaviour.
    pub(crate) fn pin(&self, path: &Path, sha256: &[u8; 32]) {
        let mut m = self.read().unwrap_or_default();
        let k = key(path);
        if !m.contains_key(&k) && m.len() >= MAX_PINS {
            m.clear();
        }
        m.insert(k, hex::encode(sha256));
        let Some(file) = &self.file else {
            *self.mem.lock().unwrap_or_else(PoisonError::into_inner) = m;
            return;
        };
        if let Err(e) = write(file, &m) {
            tracing::warn!(error = %e.kind(), "bws pin not saved");
        }
    }
}

/// Write `m` next to `file` and rename it into place (owner-only on unix).
fn write(file: &Path, m: &BTreeMap<String, String>) -> std::io::Result<()> {
    use std::io::Write as _;
    let json = serde_json::to_vec(m).map_err(std::io::Error::other)?;
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(format!(".{:016x}.tmp", rand_core::RngCore::next_u64(&mut rand_core::OsRng)));
    let tmp = PathBuf::from(tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let result = o.open(&tmp).and_then(|mut f| {
        f.write_all(&json)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, file)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_persist_compare_and_fail_closed_on_a_bad_file() {
        let dir = tempfile::tempdir().expect("tmp");
        let file = dir.path().join("bws_pins.json");
        let bin = Path::new("/usr/local/bin/bws");
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let pins = Pins::new(Some(file.clone()));
        assert_eq!(pins.check(bin, &a), Known::New);
        pins.pin(bin, &a);
        let again = Pins::new(Some(file.clone()));
        assert_eq!(again.check(bin, &a), Known::Same, "survives a restart");
        assert_eq!(again.check(bin, &b), Known::Changed);
        again.pin(bin, &b);
        assert_eq!(pins.check(bin, &b), Known::Same);
        std::fs::write(&file, b"{not json").expect("corrupt");
        assert_eq!(pins.check(bin, &b), Known::Changed, "unreadable is not 'no pin'");
        let mem = Pins::default();
        assert_eq!(mem.check(bin, &a), Known::New);
        mem.pin(bin, &a);
        assert_eq!(mem.check(bin, &a), Known::Same);
        let leftovers = std::fs::read_dir(dir.path()).expect("dir").count();
        assert_eq!(leftovers, 1, "no temp file left behind");
    }
}
