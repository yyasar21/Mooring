//! Clipboard access for `credential_copy_password`, from Rust only (no plugin, no capability).
//!
//! The secret is written with `arboard`, asking each OS to keep it out of clipboard history
//! where it can; a timer clears it after 30 s, but only when the clipboard still holds the
//! same value (compared by SHA-256, so the clear task never keeps the plaintext).
//! Tests use [`MemoryClipboard`], so no display server is needed in CI.

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Digest of a clipboard value, so the clear task can compare without holding the secret.
pub type ValueDigest = [u8; 32];

/// SHA-256 of `text`.
pub fn digest(text: &str) -> ValueDigest {
    Sha256::digest(text.as_bytes()).into()
}

/// Clipboard failure. The message is fixed text, never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("clipboard unavailable")]
pub struct ClipboardError;

/// Minimal clipboard surface used by the commands.
pub trait Clipboard: Send + Sync {
    /// Put `text` on the clipboard.
    fn set(&self, text: &str) -> Result<(), ClipboardError>;
    /// Digest of the current text, `None` when empty or not text.
    fn current(&self) -> Result<Option<ValueDigest>, ClipboardError>;
    /// Empty the clipboard.
    fn clear(&self) -> Result<(), ClipboardError>;
}

/// Clear the clipboard if it still holds the value with digest `expected`. Returns whether it
/// cleared. Another value (the user copied something else) is left alone.
pub fn clear_if_unchanged(
    clipboard: &dyn Clipboard,
    expected: &ValueDigest,
) -> Result<bool, ClipboardError> {
    if clipboard.current()?.as_ref() == Some(expected) {
        clipboard.clear()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// The OS clipboard through `arboard`. One handle is created lazily and kept: on X11/Wayland
/// the process that set the value must stay its owner, and dropping the last handle would hand
/// the secret to a clipboard manager. Access is serialised (arboard: Windows allows one thread
/// at a time).
#[derive(Default)]
pub struct SystemClipboard {
    handle: Mutex<Option<arboard::Clipboard>>,
}

impl std::fmt::Debug for SystemClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemClipboard").finish_non_exhaustive()
    }
}

fn sys_err(e: &arboard::Error) -> ClipboardError {
    // arboard errors never contain clipboard contents.
    tracing::warn!(error = %e, "clipboard operation failed");
    ClipboardError
}

impl SystemClipboard {
    fn with<T>(
        &self,
        f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, ClipboardError>,
    ) -> Result<T, ClipboardError> {
        let mut guard = self.handle.lock().map_err(|_| ClipboardError)?;
        if guard.is_none() {
            *guard = Some(arboard::Clipboard::new().map_err(|e| sys_err(&e))?);
        }
        let cb = guard.as_mut().ok_or(ClipboardError)?;
        f(cb)
    }
}

impl Clipboard for SystemClipboard {
    fn set(&self, text: &str) -> Result<(), ClipboardError> {
        self.with(|cb| {
            let set = cb.set();
            #[cfg(all(unix, not(target_os = "macos")))]
            let set = arboard::SetExtLinux::exclude_from_history(set);
            #[cfg(target_os = "macos")]
            let set = arboard::SetExtApple::exclude_from_history(set);
            #[cfg(windows)]
            let set = arboard::SetExtWindows::exclude_from_cloud(
                arboard::SetExtWindows::exclude_from_history(set),
            );
            set.text(text).map_err(|e| sys_err(&e))
        })
    }

    fn current(&self) -> Result<Option<ValueDigest>, ClipboardError> {
        self.with(|cb| match cb.get_text() {
            Ok(text) => Ok(Some(digest(&Zeroizing::new(text)))),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(sys_err(&e)),
        })
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        self.with(|cb| cb.clear().map_err(|e| sys_err(&e)))
    }
}

/// In-memory clipboard for tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct MemoryClipboard {
    value: Mutex<Option<Zeroizing<String>>>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryClipboard {
    /// What is on the clipboard (tests only).
    pub fn peek(&self) -> Option<String> {
        self.value.lock().ok().and_then(|v| v.as_ref().map(|s| s.to_string()))
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clipboard for MemoryClipboard {
    fn set(&self, text: &str) -> Result<(), ClipboardError> {
        *self.value.lock().map_err(|_| ClipboardError)? = Some(Zeroizing::new(text.to_owned()));
        Ok(())
    }

    fn current(&self) -> Result<Option<ValueDigest>, ClipboardError> {
        Ok(self.value.lock().map_err(|_| ClipboardError)?.as_ref().map(|s| digest(s)))
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        *self.value.lock().map_err(|_| ClipboardError)? = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_the_same_value() {
        let cb = MemoryClipboard::default();
        cb.set("pw-1").expect("set");
        let d = digest("pw-1");
        assert!(clear_if_unchanged(&cb, &d).expect("ok"));
        assert_eq!(cb.peek(), None);

        cb.set("pw-1").expect("set");
        cb.set("something the user copied").expect("set");
        assert!(!clear_if_unchanged(&cb, &d).expect("ok"));
        assert_eq!(cb.peek().as_deref(), Some("something the user copied"));
    }
}
