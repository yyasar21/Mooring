//! Local paths chosen in the native file dialog (ADR-0010 §SFTP, security review 4 B-4).
//!
//! The `WebView` never sees or sends a local path. `sftp_pick_local` opens the dialog from
//! Rust and stores the chosen path here under a random 128-bit `pickId`; the transfer commands
//! name the pick, and the path is looked up and consumed. A pick is
//! * single-use: a successful lookup removes it;
//! * bound to the `sessionId` it was made for and to its mode (`folder` / `file`);
//! * valid for [`PICK_TTL`];
//! * cleared on every vault lock ([`Picks::clear`]). A dialog that was open across a lock
//!   cannot store its pick afterwards: [`Picks::insert`] refuses a stale [`Epoch`].
//!
//! Every refusal is the same `input.invalid "pick"`, so a caller cannot probe which check
//! failed.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::error::{IpcError, IpcResult};

/// How long a pick stays usable.
pub const PICK_TTL: Duration = Duration::from_secs(10 * 60);
/// Most picks held at once (oldest dropped first); bounds memory against a looping caller.
pub const MAX_PICKS: usize = 64;
/// Length of a `pickId`: 128 bits as lower-case hex.
pub const PICK_ID_LEN: usize = 32;

/// What the dialog chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickMode {
    /// A directory (download target).
    Folder,
    /// A regular file (upload source).
    File,
}

impl PickMode {
    /// `"folder"` | `"file"` from the wire.
    pub fn parse(raw: &str) -> IpcResult<Self> {
        match raw {
            "folder" => Ok(Self::Folder),
            "file" => Ok(Self::File),
            _ => Err(IpcError::invalid("mode", "expected folder or file")),
        }
    }
}

/// Lock generation captured before a dialog opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch(u64);

#[derive(Debug)]
struct Pick {
    session_id: String,
    mode: PickMode,
    path: PathBuf,
    created: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    epoch: u64,
    picks: HashMap<String, Pick>,
}

/// The pick store held in `AppState`.
#[derive(Debug, Default)]
pub struct Picks {
    inner: Mutex<Inner>,
}

/// The single refusal for an unknown, reused, foreign, expired or mismatched pick.
pub fn refused() -> IpcError {
    IpcError::invalid("pick", "unknown, already used or expired; pick again")
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

impl Picks {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        // The data is plain (paths and ids); a panic elsewhere cannot leave it half-written.
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Current lock generation; capture it before opening a dialog.
    pub fn epoch(&self) -> Epoch {
        self.with(|i| Epoch(i.epoch))
    }

    /// Store a chosen path and return its new `pickId`. `None` when the vault was locked since
    /// `epoch` was taken (the pick is discarded, as if the user had cancelled).
    pub fn insert(
        &self,
        epoch: Epoch,
        session_id: &str,
        mode: PickMode,
        path: PathBuf,
        now: Instant,
    ) -> Option<String> {
        self.with(|i| {
            if i.epoch != epoch.0 {
                return None;
            }
            i.picks.retain(|_, p| now.saturating_duration_since(p.created) < PICK_TTL);
            if i.picks.len() >= MAX_PICKS {
                let oldest = i.picks.iter().min_by_key(|(_, p)| p.created).map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    i.picks.remove(&k);
                }
            }
            let id = new_id();
            let pick = Pick { session_id: session_id.to_owned(), mode, path, created: now };
            i.picks.insert(id.clone(), pick);
            Some(id)
        })
    }

    /// Look up and consume a pick. A foreign session or the wrong mode is refused without
    /// consuming it (the owner can still use it); an expired pick is removed.
    pub fn take(
        &self,
        pick_id: &str,
        session_id: &str,
        mode: PickMode,
        now: Instant,
    ) -> IpcResult<PathBuf> {
        if pick_id.len() != PICK_ID_LEN || !pick_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(refused());
        }
        self.with(|i| {
            let p = i.picks.get(pick_id).ok_or_else(refused)?;
            if now.saturating_duration_since(p.created) >= PICK_TTL {
                i.picks.remove(pick_id);
                return Err(refused());
            }
            if p.session_id != session_id || p.mode != mode {
                return Err(refused());
            }
            i.picks.remove(pick_id).map(|p| p.path).ok_or_else(refused)
        })
    }

    /// Drop every pick and start a new epoch (vault lock).
    pub fn clear(&self) {
        self.with(|i| {
            i.epoch = i.epoch.wrapping_add(1);
            i.picks.clear();
        });
    }

    /// Number of picks held (tests).
    pub fn len(&self) -> usize {
        self.with(|i| i.picks.len())
    }

    /// Whether no pick is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_one(p: &Picks, sid: &str, mode: PickMode, now: Instant) -> String {
        p.insert(p.epoch(), sid, mode, PathBuf::from("/x"), now).expect("stored")
    }

    #[test]
    fn ids_are_128_bit_hex_and_unique() {
        let p = Picks::default();
        let now = Instant::now();
        let a = store_one(&p, "s", PickMode::File, now);
        let b = store_one(&p, "s", PickMode::File, now);
        assert_eq!(a.len(), PICK_ID_LEN);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn single_use_session_bound_mode_bound_and_expiring() {
        let p = Picks::default();
        let now = Instant::now();
        let id = store_one(&p, "s1", PickMode::Folder, now);
        assert_eq!(p.take(&id, "s2", PickMode::Folder, now).expect_err("foreign").code, "input.invalid");
        assert_eq!(p.take(&id, "s1", PickMode::File, now).expect_err("mode").code, "input.invalid");
        assert_eq!(p.take(&id, "s1", PickMode::Folder, now).expect("owner"), PathBuf::from("/x"));
        let e = p.take(&id, "s1", PickMode::Folder, now).expect_err("reused");
        assert!(e.message.contains("pick"), "{e:?}");

        let id = store_one(&p, "s1", PickMode::File, now);
        let later = now + PICK_TTL;
        assert!(p.take(&id, "s1", PickMode::File, later).is_err(), "expired");
        assert!(p.is_empty(), "expired pick removed");
        for forged in ["", "zz", &"0".repeat(PICK_ID_LEN), &"A".repeat(PICK_ID_LEN), &"a".repeat(64)] {
            assert_eq!(p.take(forged, "s1", PickMode::File, now).expect_err("forged").code, "input.invalid");
        }
    }

    #[test]
    fn clear_drops_picks_and_refuses_stale_dialogs() {
        let p = Picks::default();
        let now = Instant::now();
        let id = store_one(&p, "s", PickMode::File, now);
        let before = p.epoch();
        p.clear();
        assert!(p.is_empty());
        assert!(p.take(&id, "s", PickMode::File, now).is_err());
        assert_eq!(p.insert(before, "s", PickMode::File, PathBuf::from("/y"), now), None);
        assert!(p.insert(p.epoch(), "s", PickMode::File, PathBuf::from("/y"), now).is_some());
    }

    #[test]
    fn store_is_bounded() {
        let p = Picks::default();
        let now = Instant::now();
        for i in 0..(MAX_PICKS as u64 + 10) {
            store_one(&p, "s", PickMode::File, now + Duration::from_millis(i));
        }
        assert_eq!(p.len(), MAX_PICKS);
    }

    #[test]
    fn modes_parse() {
        assert_eq!(PickMode::parse("folder").expect("f"), PickMode::Folder);
        assert_eq!(PickMode::parse("file").expect("f"), PickMode::File);
        assert_eq!(PickMode::parse("dir").expect_err("x").code, "input.invalid");
    }
}
