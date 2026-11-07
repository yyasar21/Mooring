//! Decrypted import documents held between `vault_import_inspect` and `vault_import_age`
//! (ADR-0023 §2, the ADR-0019 plan pattern). The `WebView` sees the `pickId` and counts; the
//! document (plaintext inventory, sealed secrets) stays here. A held document is
//! * single-use: `vault_import_age` takes it;
//! * valid for [`HOLD_TTL`];
//! * capped at [`MAX_HELD`] (oldest dropped first);
//! * swept on every access;
//! * dropped on every vault lock ([`HeldImports::clear`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mooring_sync::Imported;

use crate::error::IpcResult;
use crate::picks::{refused, PICK_ID_LEN};

/// How long an inspected document stays importable.
pub const HOLD_TTL: Duration = Duration::from_secs(10 * 60);
/// Most documents held at once.
pub const MAX_HELD: usize = 4;

/// One inspected document.
#[derive(Debug)]
pub struct HeldImport {
    /// The parsed file.
    pub doc: Imported,
    /// Display name of the file (never the path).
    pub name: String,
    /// The source vault differs from ours (needs the source master password).
    pub foreign: bool,
    created: Instant,
}

/// The hold in `AppState`.
#[derive(Debug, Default)]
pub struct HeldImports {
    inner: Mutex<HashMap<String, HeldImport>>,
}

impl HeldImport {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) >= HOLD_TTL
    }
}

impl HeldImports {
    fn with<T>(&self, now: Instant, f: impl FnOnce(&mut HashMap<String, HeldImport>) -> T) -> T {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.retain(|_, h| !h.expired(now));
        f(&mut g)
    }

    /// Hold `doc` under `pick_id` (the id of the file pick it came from).
    pub fn insert(&self, pick_id: &str, doc: Imported, name: String, foreign: bool, now: Instant) {
        self.with(now, |m| {
            while m.len() >= MAX_HELD {
                let oldest = m.iter().min_by_key(|(_, h)| h.created).map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => m.remove(&k),
                    None => break,
                };
            }
            m.insert(pick_id.to_owned(), HeldImport { doc, name, foreign, created: now });
        });
    }

    /// Take (consume) a held document; unknown, used and expired ids are refused alike
    /// (`input.invalid "pick"`).
    pub fn take(&self, pick_id: &str, now: Instant) -> IpcResult<HeldImport> {
        if pick_id.len() != PICK_ID_LEN
            || !pick_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(refused());
        }
        self.with(now, |m| m.remove(pick_id).ok_or_else(refused))
    }

    /// Drop everything (vault lock).
    pub fn clear(&self) {
        self.with(Instant::now(), HashMap::clear);
    }

    /// Documents held at `now`.
    pub fn len_at(&self, now: Instant) -> usize {
        self.with(now, |m| m.len())
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len_at(Instant::now()) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Imported {
        Imported::V1 { header: header(), credentials: vec![], note: "" }
    }

    fn header() -> mooring_vault::Header {
        let pw = secrecy::SecretString::from("test-only master pw".to_owned());
        mooring_vault::Vault::create(&pw, mooring_vault::KdfParams::TEST)
            .expect("vault")
            .header()
            .clone()
    }

    #[test]
    fn single_use_ttl_cap_and_clear() {
        let h = HeldImports::default();
        let t0 = Instant::now();
        let id = "a".repeat(PICK_ID_LEN);
        h.insert(&id, doc(), "backup.age".into(), false, t0);
        assert_eq!(h.take("zz", t0).expect_err("shape").code, "input.invalid");
        assert_eq!(h.take(&"0".repeat(PICK_ID_LEN), t0).expect_err("unknown").code, "input.invalid");
        let got = h.take(&id, t0 + Duration::from_secs(1)).expect("once");
        assert_eq!((got.name.as_str(), got.foreign), ("backup.age", false));
        assert_eq!(h.take(&id, t0).expect_err("used").code, "input.invalid");
        h.insert(&id, doc(), "b".into(), true, t0);
        assert!(h.take(&id, t0 + HOLD_TTL).is_err(), "expired");
        for i in 0..MAX_HELD + 2 {
            h.insert(&format!("{i:032x}"), doc(), "x".into(), false, t0 + Duration::from_millis(i as u64));
        }
        assert_eq!(h.len_at(t0 + Duration::from_secs(1)), MAX_HELD);
        h.clear();
        assert!(h.is_empty());
    }
}
