use super::*;

#[test]
fn keysym_table() {
    let cases = [
        ("KeyA", "a", 0x61),
        ("KeyA", "A", 0x41),
        ("Digit1", "!", 0x21),
        ("Space", " ", 0x20),
        ("KeyE", "\u{e9}", 0xe9),
        ("KeyG", "\u{11f}", 0x0100_011f), // Turkish g-breve: Unicode keysym
        ("KeyE", "\u{20ac}", 0x0100_20ac),
        ("Enter", "Enter", 0xff0d),
        ("NumpadEnter", "Enter", 0xff8d),
        ("Backspace", "Backspace", 0xff08),
        ("Escape", "Escape", 0xff1b),
        ("ArrowLeft", "ArrowLeft", 0xff51),
        ("F12", "F12", 0xffc9),
        ("ShiftLeft", "Shift", 0xffe1),
        ("ShiftRight", "Shift", 0xffe2),
        ("ControlRight", "Control", 0xffe4),
        ("AltRight", "AltGraph", 0xfe03),
        ("AltRight", "Alt", 0xffea),
        ("MetaLeft", "Meta", 0xffeb),
        ("Numpad5", "5", 0xffb5),
    ];
    for (code, key, want) in cases {
        assert_eq!(keysym(code, key), Some(want), "{code} {key}");
    }
    // Keys we do not send.
    assert_eq!(keysym("Numpad5", "Clear"), None);
    assert_eq!(keysym("KeyA", "Dead"), None);
    assert_eq!(keysym("KeyA", "Unidentified"), None);
    assert_eq!(keysym("KeyA", ""), None);
    assert_eq!(char_keysym('\u{7}'), None);
    assert_eq!(char_keysym('\u{85}'), None);
}

#[test]
fn release_matches_press_and_release_all() {
    let mut t = KeyTracker::default();
    let down = t.key("ShiftLeft", "Shift", true).expect("shift");
    assert_eq!(down, KeyOut { down: true, keysym: 0xffe1, scancode: 0x2a });
    assert_eq!(t.key("KeyA", "A", true).expect("A").keysym, 0x41);
    assert!(!t.key("ShiftLeft", "Shift", false).expect("up").down);
    // Shift is up now, so the browser reports "a" on release: we still release "A".
    assert_eq!(
        t.key("KeyA", "a", false).expect("a up"),
        KeyOut { down: false, keysym: 0x41, scancode: 0x1e }
    );
    t.key("ControlLeft", "Control", true);
    t.key("KeyC", "c", true);
    let rel = t.release_all();
    assert_eq!(rel.len(), 2);
    assert!(rel.iter().all(|k| !k.down));
    assert!(t.release_all().is_empty());
    // Release of a key never seen pressed still maps.
    assert_eq!(t.key("KeyB", "b", false).expect("b").keysym, 0x62);
}

#[test]
fn tracker_is_bounded() {
    let mut t = KeyTracker::default();
    for i in 0..MAX_PRESSED {
        assert!(t.key(&format!("Key{i}"), "x", true).is_some());
    }
    assert!(t.key("KeyOverflow", "x", true).is_none());
    assert!(t.key("Key0", "x", true).is_some(), "repeat of a held key is fine");
}

#[test]
fn unicode_text_and_buttons() {
    let k = unicode_keys("a\u{11f}\u{7}");
    assert_eq!(k.len(), 4);
    assert_eq!((k[0].down, k[0].keysym, k[1].down), (true, 0x61, false));
    assert_eq!(k[2].keysym, 0x0100_011f);
    assert_eq!(button_mask(1 | 4 | 8 | 16), 5);
}

#[test]
fn wheel_notches_accumulate() {
    let mut w = Wheel::default();
    assert_eq!(w.feed(0, 120), vec![0x10], "down = button 5");
    assert_eq!(w.feed(0, -240), vec![0x08, 0x08], "up = button 4");
    assert!(w.feed(0, 60).is_empty(), "half notch");
    assert_eq!(w.feed(0, 60), vec![0x10]);
    assert_eq!(w.feed(120, 0), vec![0x40], "right = button 7");
    assert_eq!(w.feed(-120, 0), vec![0x20], "left = button 6");
    assert_eq!(w.feed(0, i16::MAX).len(), usize::try_from(MAX_NOTCHES).expect("n"));
}
