//! The OS clipboard as a graphical session sees it (ADR-0011 §Clipboard, ADR-0012).
//!
//! Protocol crates never link a clipboard library: the Tauri layer implements [`Clipboard`]
//! over its `clipboard.rs` (arboard, digest tracking for the lock clear). Text only; clipboard
//! contents never cross IPC and never appear in audit events or logs.

/// Text clipboard bridge shared by `mooring-proto-rdp` (`LocalClipboard`) and
/// `mooring-proto-vnc` (`Clipboard`). Implementations may block: RDP calls them from
/// `spawn_blocking`.
pub trait Clipboard: Send + Sync + std::fmt::Debug {
    /// Current OS clipboard text, if any (local → remote on `ClipboardOffer`).
    fn read_text(&self) -> Option<String>;
    /// Put remote-originated text on the OS clipboard; `true` when it was written.
    fn write_text(&self, text: &str) -> bool;
}

/// A clipboard that holds nothing and accepts nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoClipboard;

impl Clipboard for NoClipboard {
    fn read_text(&self) -> Option<String> {
        None
    }

    fn write_text(&self, _text: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_clipboard_is_empty_and_refuses() {
        let c: &dyn Clipboard = &NoClipboard;
        assert_eq!(c.read_text(), None);
        assert!(!c.write_text("x"));
    }
}
