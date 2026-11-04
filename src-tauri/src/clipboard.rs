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
    /// Current text, for `ClipboardOffer` (ADR-0011: read in Rust, never sent over IPC).
    fn text(&self) -> Result<Option<Zeroizing<String>>, ClipboardError> {
        Err(ClipboardError)
    }
    /// Put an RGBA image on the clipboard (`session_screenshot`).
    fn set_image(&self, width: u32, height: u32, rgba: &[u8]) -> Result<(), ClipboardError> {
        let _ = (width, height, rgba);
        Err(ClipboardError)
    }
}

/// After a screenshot: clear the clipboard unless it now holds text (review 5 L-23). Foreign
/// clipboard images are never decoded (any same-user process can put a hostile PNG, BMP or
/// TIFF there, and the decoders run in the process that holds the DEK), so an image the user
/// copied after the screenshot is cleared too: the fail-safe direction. Text is left alone.
pub fn clear_screenshot_unless_text(clipboard: &dyn Clipboard) -> Result<bool, ClipboardError> {
    if clipboard.current()?.is_none() {
        clipboard.clear()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// The clipboard a remote session writes to: every value it sets is remembered (by digest) in
/// `last`, so a vault lock or exit can clear remote text that is still there (ADR-0011).
#[derive(Clone)]
pub struct RemoteClipboard {
    inner: std::sync::Arc<dyn Clipboard>,
    last: std::sync::Arc<Mutex<Option<ValueDigest>>>,
    guard: Option<RemoteGuard>,
}

/// Lock gate and audit for one session's clipboard (review 5 L-25).
#[derive(Clone)]
pub struct RemoteGuard {
    /// Vault state.
    pub ready: crate::state::Ready,
    /// Audit log.
    pub audit: std::sync::Arc<Mutex<mooring_audit::AuditLog>>,
    /// Connection id for the entries.
    pub connection: String,
    /// `AppState::copied_credential`.
    pub copied: std::sync::Arc<Mutex<Option<(ValueDigest, String)>>>,
    /// Set after the first refused write of a locked period (one audit entry per period).
    pub blocked: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for RemoteGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteGuard").field("connection", &self.connection).finish_non_exhaustive()
    }
}

impl RemoteGuard {
    fn record(&self, event: mooring_audit::AuditEvent) {
        crate::state::record_audit(&self.audit, event);
    }
}

impl std::fmt::Debug for RemoteClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteClipboard").finish_non_exhaustive()
    }
}

impl RemoteClipboard {
    /// Wrap `inner`, recording remote writes in `last`.
    pub fn new(
        inner: std::sync::Arc<dyn Clipboard>,
        last: std::sync::Arc<Mutex<Option<ValueDigest>>>,
    ) -> Self {
        Self { inner, last, guard: None }
    }

    /// Refuse remote writes while the vault is locked and audit offers (L-25).
    #[must_use]
    pub fn with_guard(mut self, guard: RemoteGuard) -> Self {
        self.guard = Some(guard);
        self
    }
}

impl Clipboard for RemoteClipboard {
    /// Remote → local. Refused while the vault is locked (pastejacking behind the lock
    /// screen); the first refusal of a locked period is audited `session_clipboard_blocked`.
    fn set(&self, text: &str) -> Result<(), ClipboardError> {
        use std::sync::atomic::Ordering;
        if let Some(g) = &self.guard {
            if !g.ready.unlocked() {
                if !g.blocked.swap(true, Ordering::Relaxed) {
                    g.record(mooring_audit::AuditEvent::SessionClipboardBlocked {
                        connection: g.connection.clone(),
                    });
                }
                return Err(ClipboardError);
            }
            g.blocked.store(false, Ordering::Relaxed);
        }
        self.inner.set(text)?;
        *self.last.lock().map_err(|_| ClipboardError)? = Some(digest(text));
        Ok(())
    }

    fn current(&self) -> Result<Option<ValueDigest>, ClipboardError> {
        self.inner.current()
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        self.inner.clear()
    }

    /// Local → remote (`ClipboardOffer`). Nothing is offered while the vault is locked; each
    /// offer is audited `session_clipboard_offer`, plus `credential_sent_to_remote` when the
    /// text is the secret `credential_copy_*` placed.
    fn text(&self) -> Result<Option<Zeroizing<String>>, ClipboardError> {
        let Some(g) = &self.guard else { return self.inner.text() };
        if !g.ready.unlocked() {
            return Ok(None);
        }
        let text = self.inner.text()?;
        if let Some(t) = &text {
            let connection = g.connection.clone();
            let bytes = u64::try_from(t.len()).unwrap_or(u64::MAX);
            g.record(mooring_audit::AuditEvent::SessionClipboardOffer { connection: connection.clone(), bytes });
            let copied = g.copied.lock().ok().and_then(|c| c.clone());
            if let Some((_, credential)) = copied.filter(|(d, _)| *d == digest(t)) {
                g.record(mooring_audit::AuditEvent::CredentialSentToRemote { credential, connection });
            }
        }
        Ok(text)
    }

    fn set_image(&self, width: u32, height: u32, rgba: &[u8]) -> Result<(), ClipboardError> {
        self.inner.set_image(width, height, rgba)
    }
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

    fn text(&self) -> Result<Option<Zeroizing<String>>, ClipboardError> {
        self.with(|cb| match cb.get_text() {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(sys_err(&e)),
        })
    }

    // arboard `image-data` (src-tauri/Cargo.toml): RGBA in, the OS format out (PNG on
    // X11/Wayland, TIFF on macOS, DIB/PNG on Windows). Kept out of clipboard history like text.
    fn set_image(&self, width: u32, height: u32, rgba: &[u8]) -> Result<(), ClipboardError> {
        let (w, h) = (
            usize::try_from(width).map_err(|_| ClipboardError)?,
            usize::try_from(height).map_err(|_| ClipboardError)?,
        );
        if w.checked_mul(h).and_then(|n| n.checked_mul(4)) != Some(rgba.len()) {
            return Err(ClipboardError);
        }
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
            let image =
                arboard::ImageData { width: w, height: h, bytes: std::borrow::Cow::Borrowed(rgba) };
            set.image(image).map_err(|e| sys_err(&e))
        })
    }
}

/// In-memory clipboard for tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct MemoryClipboard {
    value: Mutex<Option<Zeroizing<String>>>,
    image: Mutex<Option<(u32, u32, ValueDigest)>>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryClipboard {
    /// What is on the clipboard (tests only).
    pub fn peek(&self) -> Option<String> {
        self.value.lock().ok().and_then(|v| v.as_ref().map(|s| s.to_string()))
    }

    /// Size and SHA-256 of the image on the clipboard (tests only).
    pub fn peek_image(&self) -> Option<(u32, u32, ValueDigest)> {
        self.image.lock().ok().and_then(|v| *v)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clipboard for MemoryClipboard {
    fn set(&self, text: &str) -> Result<(), ClipboardError> {
        *self.value.lock().map_err(|_| ClipboardError)? = Some(Zeroizing::new(text.to_owned()));
        *self.image.lock().map_err(|_| ClipboardError)? = None;
        Ok(())
    }

    fn current(&self) -> Result<Option<ValueDigest>, ClipboardError> {
        Ok(self.value.lock().map_err(|_| ClipboardError)?.as_ref().map(|s| digest(s)))
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        *self.value.lock().map_err(|_| ClipboardError)? = None;
        *self.image.lock().map_err(|_| ClipboardError)? = None;
        Ok(())
    }

    fn text(&self) -> Result<Option<Zeroizing<String>>, ClipboardError> {
        Ok(self.value.lock().map_err(|_| ClipboardError)?.clone())
    }

    fn set_image(&self, width: u32, height: u32, rgba: &[u8]) -> Result<(), ClipboardError> {
        let d: ValueDigest = Sha256::digest(rgba).into();
        *self.image.lock().map_err(|_| ClipboardError)? = Some((width, height, d));
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

    #[test]
    fn remote_writes_are_tracked_for_the_lock_clear() {
        let inner = std::sync::Arc::new(MemoryClipboard::default());
        let last = std::sync::Arc::new(Mutex::new(None));
        let remote = RemoteClipboard::new(inner.clone(), std::sync::Arc::clone(&last));
        remote.set("from the remote desktop").expect("set");
        assert_eq!(*last.lock().expect("l"), Some(digest("from the remote desktop")));
        assert_eq!(remote.text().expect("t").as_deref().map(String::as_str), Some("from the remote desktop"));
        let d = last.lock().expect("l").expect("d");
        assert!(clear_if_unchanged(&*inner, &d).expect("clear"));
        assert!(SystemClipboard::default().set_image(2, 2, &[0; 4]).is_err(), "size mismatch");
    }

    #[test]
    fn screenshot_clear_never_reads_images_and_keeps_text() {
        let cb = MemoryClipboard::default();
        cb.set_image(4, 2, &[7; 32]).expect("image");
        assert!(clear_screenshot_unless_text(&cb).expect("ok"));
        assert_eq!(cb.peek_image(), None);
        // A foreign image copied after the screenshot is cleared too (it is never decoded).
        cb.set_image(8, 2, &[1; 64]).expect("image");
        assert!(clear_screenshot_unless_text(&cb).expect("ok"), "fail-safe");
        assert_eq!(cb.peek_image(), None);
        cb.set("the user copied text").expect("set");
        assert!(!clear_screenshot_unless_text(&cb).expect("ok"), "text is left alone");
        assert_eq!(cb.peek().as_deref(), Some("the user copied text"));
    }
}
