//! Local input → RFB: X11 keysyms from `KeyboardEvent.key` / `.code`, the pointer button mask
//! and wheel notches (ADR-0012 §Input; U1 input contract).
//!
//! * Printable `key`: Latin-1 code points are their own keysym, any other character is
//!   `0x0100_0000 + code point`. Named keys come from a fixed table; left/right modifiers and
//!   the keypad are told apart by `code`.
//! * A release always sends the keysym its press sent (tracked per `code`), so Shift released
//!   before the letter never leaves a stuck key.
//! * Wheel: DOM sign (positive `dy` = down), 120 per notch, fractional deltas accumulate; each
//!   notch is a press + release of button 4/5 (vertical) or 6/7 (horizontal).

use std::collections::HashMap;

use crate::scancode::xt_scancode;

/// Most keys tracked as pressed at once.
pub const MAX_PRESSED: usize = 64;
/// Wheel delta per notch.
pub const NOTCH: i32 = 120;
/// Most notches emitted for one wheel event.
pub const MAX_NOTCHES: i32 = 10;

const NAMED: &[(&str, u32)] = &[
    ("Backspace", 0xff08),
    ("Tab", 0xff09),
    ("Enter", 0xff0d),
    ("Pause", 0xff13),
    ("ScrollLock", 0xff14),
    ("Escape", 0xff1b),
    ("Home", 0xff50),
    ("ArrowLeft", 0xff51),
    ("ArrowUp", 0xff52),
    ("ArrowRight", 0xff53),
    ("ArrowDown", 0xff54),
    ("PageUp", 0xff55),
    ("PageDown", 0xff56),
    ("End", 0xff57),
    ("PrintScreen", 0xff61),
    ("Insert", 0xff63),
    ("ContextMenu", 0xff67),
    ("NumLock", 0xff7f),
    ("CapsLock", 0xffe5),
    ("Delete", 0xffff),
    ("AltGraph", 0xfe03),
    ("F1", 0xffbe),
    ("F2", 0xffbf),
    ("F3", 0xffc0),
    ("F4", 0xffc1),
    ("F5", 0xffc2),
    ("F6", 0xffc3),
    ("F7", 0xffc4),
    ("F8", 0xffc5),
    ("F9", 0xffc6),
    ("F10", 0xffc7),
    ("F11", 0xffc8),
    ("F12", 0xffc9),
];

/// Modifiers by `code` (left/right differ in X11).
const BY_CODE: &[(&str, u32)] = &[
    ("ShiftLeft", 0xffe1),
    ("ShiftRight", 0xffe2),
    ("ControlLeft", 0xffe3),
    ("ControlRight", 0xffe4),
    ("AltLeft", 0xffe9),
    ("AltRight", 0xffea),
    ("MetaLeft", 0xffeb),
    ("MetaRight", 0xffec),
    ("OSLeft", 0xffeb),
    ("OSRight", 0xffec),
    ("NumpadEnter", 0xff8d),
    ("NumpadMultiply", 0xffaa),
    ("NumpadAdd", 0xffab),
    ("NumpadSubtract", 0xffad),
    ("NumpadDecimal", 0xffae),
    ("NumpadDivide", 0xffaf),
];

/// Keysym of a single character.
pub fn char_keysym(c: char) -> Option<u32> {
    let cp = u32::from(c);
    match cp {
        0x20..=0x7e | 0xa0..=0xff => Some(cp),
        0..=0x1f | 0x7f..=0x9f => None,
        _ => Some(0x0100_0000 + cp),
    }
}

/// The keysym for a `KeyboardEvent` (`code`, `key`), or `None` for keys we do not send
/// (`Dead`, `Unidentified`, unknown names).
pub fn keysym(code: &str, key: &str) -> Option<u32> {
    if let Some((_, k)) = BY_CODE.iter().find(|(c, _)| *c == code) {
        // AltRight on layouts with AltGr reports key "AltGraph": ISO_Level3_Shift.
        if code == "AltRight" && key == "AltGraph" {
            return Some(0xfe03);
        }
        return Some(*k);
    }
    // Keypad digits with NumLock on: KP_0..KP_9.
    if let Some(d) = code.strip_prefix("Numpad") {
        if let (Ok(n), true) =
            (d.parse::<u32>(), key.len() == 1 && key.bytes().all(|b| b.is_ascii_digit()))
        {
            if n <= 9 {
                return Some(0xffb0 + n);
            }
        }
    }
    let mut chars = key.chars();
    if let (Some(c), None) = (chars.next(), chars.clone().next()) {
        return char_keysym(c);
    }
    match key {
        "Shift" => Some(0xffe1),
        "Control" => Some(0xffe3),
        "Alt" => Some(0xffe9),
        "Meta" | "OS" => Some(0xffeb),
        _ => NAMED.iter().find(|(n, _)| *n == key).map(|(_, k)| *k),
    }
}

/// A key event ready to encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyOut {
    /// Down or up.
    pub down: bool,
    /// X11 keysym.
    pub keysym: u32,
    /// XT scancode for QEMU Extended Key Event (0 = unknown).
    pub scancode: u32,
}

/// Tracks pressed keys so releases match presses and `ReleaseAll` can undo everything.
#[derive(Debug, Default)]
pub struct KeyTracker {
    pressed: HashMap<String, (u32, u32)>,
}

impl KeyTracker {
    /// Map one `Key` input. `None` = nothing to send.
    pub fn key(&mut self, code: &str, key: &str, pressed: bool) -> Option<KeyOut> {
        if pressed {
            let keysym = keysym(code, key)?;
            let scancode = xt_scancode(code).unwrap_or(0);
            if !self.pressed.contains_key(code) && self.pressed.len() >= MAX_PRESSED {
                return None;
            }
            self.pressed.insert(code.to_owned(), (keysym, scancode));
            Some(KeyOut { down: true, keysym, scancode })
        } else {
            let (keysym, scancode) = match self.pressed.remove(code) {
                Some(v) => v,
                None => (keysym(code, key)?, xt_scancode(code).unwrap_or(0)),
            };
            Some(KeyOut { down: false, keysym, scancode })
        }
    }

    /// Releases for every held key (blur).
    pub fn release_all(&mut self) -> Vec<KeyOut> {
        let mut out: Vec<KeyOut> = self
            .pressed
            .drain()
            .map(|(_, (keysym, scancode))| KeyOut { down: false, keysym, scancode })
            .collect();
        out.sort_by_key(|k| k.keysym);
        out
    }
}

/// Keysym press/release pairs for IME text (`Unicode`).
pub fn unicode_keys(text: &str) -> Vec<KeyOut> {
    text.chars()
        .filter_map(char_keysym)
        .flat_map(|keysym| [true, false].map(|down| KeyOut { down, keysym, scancode: 0 }))
        .collect()
}

/// RFB button mask from the UI mask (1 left, 2 middle, 4 right; back/forward have no RFB
/// button and are dropped).
pub const fn button_mask(ui: u8) -> u8 {
    ui & 0b111
}

/// Wheel accumulator.
#[derive(Debug, Default)]
pub struct Wheel {
    acc_x: i32,
    acc_y: i32,
}

impl Wheel {
    /// Feed a wheel delta; returns the button bits to press + release, one entry per notch.
    pub fn feed(&mut self, dx: i16, dy: i16) -> Vec<u8> {
        let mut out = Vec::new();
        for (acc, d, neg, pos) in
            [(&mut self.acc_y, dy, 0x08u8, 0x10u8), (&mut self.acc_x, dx, 0x20, 0x40)]
        {
            *acc = (*acc + i32::from(d)).clamp(-NOTCH * MAX_NOTCHES, NOTCH * MAX_NOTCHES);
            let notches = *acc / NOTCH;
            *acc -= notches * NOTCH;
            let bit = if notches < 0 { neg } else { pos };
            for _ in 0..notches.abs() {
                out.push(bit);
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
