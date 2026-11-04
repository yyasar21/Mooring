//! `SessionInput` → RDP fast-path input events (ADR-0011 §Keyboard, U1 input contract).
//!
//! State (pressed keys and buttons, pointer position) lives in `ironrdp_input::Database`, so
//! repeated presses are filtered and `ReleaseAll` (sent by the UI on blur) releases exactly
//! what is down. Pure: no I/O, so the mapping is unit-tested and fuzzed
//! ([`crate::fuzz::input_sequence`]).

use ironrdp_input::{Database, MouseButton, MousePosition, Operation, WheelRotations};
use ironrdp_pdu::input::fast_path::FastPathInputEvent;

use crate::keymap::scancode;

/// One notch in RDP wheel units (Windows `WHEEL_DELTA`).
pub const WHEEL_NOTCH: i16 = 120;

/// Button bits of `SessionInput::Pointer.buttons`, in `MouseButton` order.
const BUTTONS: [(u8, MouseButton); 5] = [
    (1, MouseButton::Left),
    (2, MouseButton::Middle),
    (4, MouseButton::Right),
    (8, MouseButton::X1),
    (16, MouseButton::X2),
];

/// Input state for one session.
pub struct InputMapper {
    db: Database,
}

impl std::fmt::Debug for InputMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print which keys are down (they may spell a password).
        f.debug_struct("InputMapper").finish_non_exhaustive()
    }
}

impl Default for InputMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl InputMapper {
    /// Nothing pressed, pointer at (0, 0).
    pub fn new() -> Self {
        Self { db: Database::new() }
    }

    /// Pointer move plus the button mask. Coordinates are clamped into a `width × height`
    /// desktop; a mask change presses / releases only the buttons that changed.
    pub fn pointer(
        &mut self,
        x: u32,
        y: u32,
        buttons: u8,
        width: u16,
        height: u16,
    ) -> Vec<FastPathInputEvent> {
        let clamp =
            |v: u32, max: u16| u16::try_from(v).unwrap_or(u16::MAX).min(max.saturating_sub(1));
        let mut ops =
            vec![Operation::MouseMove(MousePosition { x: clamp(x, width), y: clamp(y, height) })];
        for (bit, button) in BUTTONS {
            let down = buttons & bit != 0;
            if down != self.db.is_mouse_button_pressed(button) {
                ops.push(if down {
                    Operation::MouseButtonPressed(button)
                } else {
                    Operation::MouseButtonReleased(button)
                });
            }
        }
        self.db.apply(ops).into_vec()
    }

    /// A physical key by W3C `code`; unmapped codes produce nothing.
    pub fn key(&mut self, code: &str, pressed: bool) -> Vec<FastPathInputEvent> {
        let Some(sc) = scancode(code) else {
            return Vec::new();
        };
        let op = if pressed { Operation::KeyPressed(sc) } else { Operation::KeyReleased(sc) };
        self.db.apply([op]).into_vec()
    }

    /// Wheel in the DOM sign (positive `dy` = down, positive `dx` = right), 120 per notch.
    /// RDP's vertical wheel is positive away from the user (up), so `dy` is negated; the
    /// horizontal wheel is positive to the right. Large deltas are split into notch-sized
    /// events so nothing is clamped away by the 9-bit wire field.
    pub fn wheel(&mut self, dx: i16, dy: i16) -> Vec<FastPathInputEvent> {
        let mut ops = Vec::new();
        for (is_vertical, total) in [(true, -i32::from(dy)), (false, i32::from(dx))] {
            let mut left = total;
            while left != 0 {
                let step = left.clamp(-i32::from(WHEEL_NOTCH), i32::from(WHEEL_NOTCH));
                left -= step;
                let rotation_units = i16::try_from(step).unwrap_or(0);
                ops.push(Operation::WheelRotations(WheelRotations { is_vertical, rotation_units }));
            }
        }
        self.db.apply(ops).into_vec()
    }

    /// IME / dead-key text: each character is pressed and released as a Unicode key event.
    pub fn unicode(&mut self, text: &str) -> Vec<FastPathInputEvent> {
        let ops = text
            .chars()
            .filter(|c| !c.is_control())
            .flat_map(|c| [Operation::UnicodeKeyPressed(c), Operation::UnicodeKeyReleased(c)]);
        self.db.apply(ops).into_vec()
    }

    /// Release every key and button that is down (blur).
    pub fn release_all(&mut self) -> Vec<FastPathInputEvent> {
        self.db.release_all().into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_pdu::input::fast_path::KeyboardFlags;
    use ironrdp_pdu::input::mouse::PointerFlags;

    fn wheel_units(events: &[FastPathInputEvent]) -> Vec<(bool, i16)> {
        events
            .iter()
            .filter_map(|e| match e {
                FastPathInputEvent::MouseEvent(m)
                    if m.flags.contains(PointerFlags::VERTICAL_WHEEL) =>
                {
                    Some((true, m.number_of_wheel_rotation_units))
                }
                FastPathInputEvent::MouseEvent(m)
                    if m.flags.contains(PointerFlags::HORIZONTAL_WHEEL) =>
                {
                    Some((false, m.number_of_wheel_rotation_units))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn keys_press_once_and_release_all_releases_them() {
        let mut m = InputMapper::new();
        assert_eq!(m.key("ShiftLeft", true).len(), 1);
        assert!(m.key("ShiftLeft", true).len() <= 2, "auto-repeat: at most release + press");
        assert_eq!(m.key("KeyA", true).len(), 1);
        assert!(m.key("NoSuchKey", true).is_empty());
        let released = m.release_all();
        assert_eq!(released.len(), 2);
        assert!(released.iter().all(|e| matches!(e,
            FastPathInputEvent::KeyboardEvent(f, _) if f.contains(KeyboardFlags::RELEASE))));
        assert!(m.release_all().is_empty());
    }

    #[test]
    fn pointer_buttons_diff_and_clamp() {
        let mut m = InputMapper::new();
        let ev = m.pointer(5000, 5000, 1 | 4, 1024, 768);
        // move + left down + right down
        assert_eq!(ev.len(), 3);
        match &ev[0] {
            FastPathInputEvent::MouseEvent(p) => {
                assert_eq!((p.x_position, p.y_position), (1023, 767));
            }
            other => panic!("expected move, got {other:?}"),
        }
        assert_eq!(m.pointer(10, 10, 1 | 4, 1024, 768).len(), 1, "only the move");
        assert_eq!(m.pointer(10, 10, 0, 1024, 768).len(), 2, "no move (same spot) + two releases");
        assert_eq!(m.pointer(10, 10, 8 | 16, 1024, 768).len(), 2, "back/forward buttons");
        assert_eq!(m.release_all().len(), 2);
    }

    #[test]
    fn wheel_follows_dom_sign_and_splits_notches() {
        let mut m = InputMapper::new();
        assert_eq!(wheel_units(&m.wheel(0, 120)), vec![(true, -120)], "down is negative");
        assert_eq!(wheel_units(&m.wheel(0, -60)), vec![(true, 60)]);
        assert_eq!(wheel_units(&m.wheel(240, 0)), vec![(false, 120), (false, 120)]);
        let big = wheel_units(&m.wheel(0, i16::MIN));
        assert_eq!(big.iter().map(|(_, u)| i32::from(*u)).sum::<i32>(), 32768);
        assert!(m.wheel(0, 0).is_empty());
    }

    #[test]
    fn unicode_is_pressed_and_released() {
        let mut m = InputMapper::new();
        let ev = m.unicode("şğ😀");
        // ş, ğ: one unit each; the emoji is a surrogate pair. Press + release for each.
        assert_eq!(ev.len(), 2 + 2 + 4);
        assert!(m.release_all().is_empty());
    }
}
