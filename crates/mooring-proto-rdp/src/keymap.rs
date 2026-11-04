//! W3C `KeyboardEvent.code` → PC/AT set-1 scancode (ADR-0011 §Keyboard).
//!
//! `code` names the physical key, independent of the local layout, so this one table serves
//! every KLID: the server applies `options.keyboardLayout` (en-US, tr-TR Q/F, de, fr, en-GB,
//! it, es, ru) to the scancode. The table covers the full 104/105-key ISO and ANSI blocks
//! (including `IntlBackslash`, the 102nd key that Turkish, German and UK layouts use), the
//! Japanese/Korean extras and the common media keys. Unknown codes (and `Pause`, an E1
//! sequence fast-path input cannot carry) return `None` and are dropped; text the IME composes is sent as Unicode events instead.

use ironrdp_input::Scancode;

/// `(code, extended, scancode)`.
const TABLE: &[(&str, bool, u8)] = &[
    ("Escape", false, 0x01),
    ("Digit1", false, 0x02),
    ("Digit2", false, 0x03),
    ("Digit3", false, 0x04),
    ("Digit4", false, 0x05),
    ("Digit5", false, 0x06),
    ("Digit6", false, 0x07),
    ("Digit7", false, 0x08),
    ("Digit8", false, 0x09),
    ("Digit9", false, 0x0A),
    ("Digit0", false, 0x0B),
    ("Minus", false, 0x0C),
    ("Equal", false, 0x0D),
    ("Backspace", false, 0x0E),
    ("Tab", false, 0x0F),
    ("KeyQ", false, 0x10),
    ("KeyW", false, 0x11),
    ("KeyE", false, 0x12),
    ("KeyR", false, 0x13),
    ("KeyT", false, 0x14),
    ("KeyY", false, 0x15),
    ("KeyU", false, 0x16),
    ("KeyI", false, 0x17),
    ("KeyO", false, 0x18),
    ("KeyP", false, 0x19),
    ("BracketLeft", false, 0x1A),
    ("BracketRight", false, 0x1B),
    ("Enter", false, 0x1C),
    ("ControlLeft", false, 0x1D),
    ("KeyA", false, 0x1E),
    ("KeyS", false, 0x1F),
    ("KeyD", false, 0x20),
    ("KeyF", false, 0x21),
    ("KeyG", false, 0x22),
    ("KeyH", false, 0x23),
    ("KeyJ", false, 0x24),
    ("KeyK", false, 0x25),
    ("KeyL", false, 0x26),
    ("Semicolon", false, 0x27),
    ("Quote", false, 0x28),
    ("Backquote", false, 0x29),
    ("ShiftLeft", false, 0x2A),
    ("Backslash", false, 0x2B),
    ("KeyZ", false, 0x2C),
    ("KeyX", false, 0x2D),
    ("KeyC", false, 0x2E),
    ("KeyV", false, 0x2F),
    ("KeyB", false, 0x30),
    ("KeyN", false, 0x31),
    ("KeyM", false, 0x32),
    ("Comma", false, 0x33),
    ("Period", false, 0x34),
    ("Slash", false, 0x35),
    ("ShiftRight", false, 0x36),
    ("NumpadMultiply", false, 0x37),
    ("AltLeft", false, 0x38),
    ("Space", false, 0x39),
    ("CapsLock", false, 0x3A),
    ("F1", false, 0x3B),
    ("F2", false, 0x3C),
    ("F3", false, 0x3D),
    ("F4", false, 0x3E),
    ("F5", false, 0x3F),
    ("F6", false, 0x40),
    ("F7", false, 0x41),
    ("F8", false, 0x42),
    ("F9", false, 0x43),
    ("F10", false, 0x44),
    ("NumLock", false, 0x45),
    ("ScrollLock", false, 0x46),
    ("Numpad7", false, 0x47),
    ("Numpad8", false, 0x48),
    ("Numpad9", false, 0x49),
    ("NumpadSubtract", false, 0x4A),
    ("Numpad4", false, 0x4B),
    ("Numpad5", false, 0x4C),
    ("Numpad6", false, 0x4D),
    ("NumpadAdd", false, 0x4E),
    ("Numpad1", false, 0x4F),
    ("Numpad2", false, 0x50),
    ("Numpad3", false, 0x51),
    ("Numpad0", false, 0x52),
    ("NumpadDecimal", false, 0x53),
    ("PrintScreen", true, 0x37),
    ("IntlBackslash", false, 0x56),
    ("F11", false, 0x57),
    ("F12", false, 0x58),
    ("NumpadEqual", false, 0x59),
    ("F13", false, 0x64),
    ("F14", false, 0x65),
    ("F15", false, 0x66),
    ("F16", false, 0x67),
    ("F17", false, 0x68),
    ("F18", false, 0x69),
    ("F19", false, 0x6A),
    ("F20", false, 0x6B),
    ("F21", false, 0x6C),
    ("F22", false, 0x6D),
    ("F23", false, 0x6E),
    ("KanaMode", false, 0x70),
    ("Lang2", false, 0x71),
    ("Lang1", false, 0x72),
    ("IntlRo", false, 0x73),
    ("F24", false, 0x76),
    ("Convert", false, 0x79),
    ("NonConvert", false, 0x7B),
    ("IntlYen", false, 0x7D),
    ("NumpadComma", false, 0x7E),
    ("MediaTrackPrevious", true, 0x10),
    ("MediaTrackNext", true, 0x19),
    ("NumpadEnter", true, 0x1C),
    ("ControlRight", true, 0x1D),
    ("AudioVolumeMute", true, 0x20),
    ("LaunchApp2", true, 0x21),
    ("MediaPlayPause", true, 0x22),
    ("MediaStop", true, 0x24),
    ("AudioVolumeDown", true, 0x2E),
    ("AudioVolumeUp", true, 0x30),
    ("BrowserHome", true, 0x32),
    ("NumpadDivide", true, 0x35),
    ("AltRight", true, 0x38),
    ("Home", true, 0x47),
    ("ArrowUp", true, 0x48),
    ("PageUp", true, 0x49),
    ("ArrowLeft", true, 0x4B),
    ("ArrowRight", true, 0x4D),
    ("End", true, 0x4F),
    ("ArrowDown", true, 0x50),
    ("PageDown", true, 0x51),
    ("Insert", true, 0x52),
    ("Delete", true, 0x53),
    ("MetaLeft", true, 0x5B),
    ("MetaRight", true, 0x5C),
    ("ContextMenu", true, 0x5D),
    ("Power", true, 0x5E),
    ("Sleep", true, 0x5F),
    ("WakeUp", true, 0x63),
    ("BrowserSearch", true, 0x65),
    ("BrowserFavorites", true, 0x66),
    ("BrowserRefresh", true, 0x67),
    ("BrowserStop", true, 0x68),
    ("BrowserForward", true, 0x69),
    ("BrowserBack", true, 0x6A),
    ("LaunchApp1", true, 0x6B),
    ("LaunchMail", true, 0x6C),
    ("MediaSelect", true, 0x6D),
];

/// Legacy aliases some browsers still send.
const ALIASES: &[(&str, &str)] = &[
    ("OSLeft", "MetaLeft"),
    ("OSRight", "MetaRight"),
    ("VolumeMute", "AudioVolumeMute"),
    ("VolumeDown", "AudioVolumeDown"),
    ("VolumeUp", "AudioVolumeUp"),
];

/// Scancode for a `KeyboardEvent.code`, or `None` for keys RDP cannot send.
pub fn scancode(code: &str) -> Option<Scancode> {
    let code = ALIASES.iter().find(|(a, _)| *a == code).map_or(code, |(_, c)| c);
    TABLE.iter().find(|(c, _, _)| *c == code).map(|&(_, ext, sc)| Scancode::from_u8(ext, sc))
}

/// Number of mapped codes (for tests and the handoff).
pub fn table_len() -> usize {
    TABLE.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn us_layout_essentials() {
        assert_eq!(scancode("KeyA").map(Scancode::as_u16), Some(0x1E));
        assert_eq!(scancode("Enter").map(Scancode::as_u16), Some(0x1C));
        assert_eq!(scancode("NumpadEnter").map(Scancode::as_u16), Some(0xE01C));
        assert_eq!(scancode("ArrowLeft").map(Scancode::as_u16), Some(0xE04B));
        assert_eq!(scancode("ControlRight").map(Scancode::as_u16), Some(0xE01D));
        assert_eq!(scancode("MetaLeft").map(Scancode::as_u16), Some(0xE05B));
        assert_eq!(scancode("OSLeft"), scancode("MetaLeft"));
        assert_eq!(scancode("F12").map(Scancode::as_u16), Some(0x58));
    }

    #[test]
    fn iso_102nd_key_for_tr_de_uk() {
        assert_eq!(scancode("IntlBackslash").map(Scancode::as_u16), Some(0x56));
        assert_eq!(scancode("IntlRo").map(Scancode::as_u16), Some(0x73));
    }

    #[test]
    fn every_letter_digit_and_function_key_maps() {
        for c in 'A'..='Z' {
            assert!(scancode(&format!("Key{c}")).is_some(), "Key{c}");
        }
        for d in 0..=9 {
            assert!(scancode(&format!("Digit{d}")).is_some(), "Digit{d}");
            assert!(scancode(&format!("Numpad{d}")).is_some(), "Numpad{d}");
        }
        for f in 1..=24 {
            assert!(scancode(&format!("F{f}")).is_some(), "F{f}");
        }
    }

    #[test]
    fn codes_and_scancodes_are_unique() {
        let mut codes = HashSet::new();
        let mut scans = HashSet::new();
        for &(c, ext, sc) in TABLE {
            assert!(codes.insert(c), "duplicate code {c}");
            assert!(scans.insert((ext, sc)), "duplicate scancode for {c}");
        }
        assert!(table_len() >= 140);
    }

    #[test]
    fn unknown_codes_are_dropped() {
        assert_eq!(scancode(""), None);
        assert_eq!(scancode("Fn"), None);
        assert_eq!(scancode("keya"), None);
    }
}
