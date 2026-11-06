//! Tool output is hostile text (ADR-0020 §3): it carries remote-influenced bytes (ICMP error
//! text, and with name lookups, PTR names). Before any line reaches a parser or the UI it is
//! decoded as lossy UTF-8, stripped of ANSI escapes, C0/C1 controls, bidi and other `Cf`
//! characters, and capped: [`MAX_BYTES`] in, [`MAX_LINES`] lines of [`MAX_LINE`] bytes out.

/// Most bytes of stdout + stderr kept from one run.
pub const MAX_BYTES: usize = 64 * 1024;
/// Most lines kept.
pub const MAX_LINES: usize = 200;
/// Longest line (bytes of UTF-8, cut at a character boundary).
pub const MAX_LINE: usize = 512;

/// Decode `raw` and split it into clean lines (see the module doc). `\r\n` and bare `\r`
/// (progress rewrites) both end a line; empty lines are dropped. Never fails.
#[must_use]
pub fn lines(raw: &[u8]) -> Vec<String> {
    let capped = &raw[..raw.len().min(MAX_BYTES)];
    let text = String::from_utf8_lossy(capped);
    let clean = strip(&text);
    clean
        .split(['\n', '\r'])
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .take(MAX_LINES)
        .map(truncate_line)
        .collect()
}

/// Remove ANSI escape sequences, control characters (tabs become spaces; `\n` / `\r` are kept
/// for the line split) and invisible format characters.
#[must_use]
pub fn strip(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => skip_escape(&mut chars),
            '\u{9b}' => skip_csi(&mut chars),
            '\n' | '\r' => out.push(c),
            '\t' => out.push(' '),
            c if c.is_control() || is_format(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// After `ESC`: `[` starts a CSI (parameters, then one final byte `@`..=`~`), `]` / `P` / `X`
/// / `^` / `_` start a string ended by BEL or `ESC \`; anything else is a two-character escape.
fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.next() {
        Some('[') => skip_csi(chars),
        Some(']' | 'P' | 'X' | '^' | '_') => {
            let mut prev_esc = false;
            for c in chars.by_ref() {
                if c == '\u{7}' || (prev_esc && c == '\\') {
                    break;
                }
                prev_esc = c == '\u{1b}';
            }
        }
        _ => {}
    }
}

fn skip_csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            break;
        }
    }
}

/// Unicode `Cf` (format) characters: soft hyphen, Arabic marks, zero-width and bidi controls,
/// word joiners, BOM, interlinear annotation, tags and the rest of the category.
#[must_use]
pub fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{AD}'
            | '\u{600}'..='\u{605}'
            | '\u{61C}'
            | '\u{6DD}'
            | '\u{70F}'
            | '\u{890}'..='\u{891}'
            | '\u{8E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn truncate_line(line: &str) -> String {
    if line.len() <= MAX_LINE {
        return line.to_owned();
    }
    let mut end = MAX_LINE;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].to_owned()
}

/// Whether a produced line respects the caps and carries no control or format character.
/// Used by the fuzz oracles and tests.
#[must_use]
pub fn is_clean(line: &str) -> bool {
    line.len() <= MAX_LINE && !line.chars().any(|c| c.is_control() || is_format(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn strips_escapes_controls_and_bidi() {
        let mut raw = b"\x1b[31mred\x1b[0m \x1b]0;title\x07x\x00y".to_vec();
        raw.extend_from_slice("\u{202e}evil\u{200b}".as_bytes());
        raw.extend_from_slice(b"\tz\r\n\xc2\x9b1mq\r\xff\n");
        let out = lines(&raw);
        assert_eq!(out, vec!["red xyevil z", "q", "\u{fffd}"]);
        assert!(out.iter().all(|l| is_clean(l)));
    }

    #[test]
    fn caps_hold_at_max_and_max_plus_one() {
        let one_line = "a".repeat(MAX_LINE + 1);
        assert_eq!(lines(one_line.as_bytes())[0].len(), MAX_LINE);
        let exact = "a".repeat(MAX_LINE);
        assert_eq!(lines(exact.as_bytes())[0].len(), MAX_LINE);
        let many = "x\n".repeat(MAX_LINES + 1);
        assert_eq!(lines(many.as_bytes()).len(), MAX_LINES);
        let big = vec![b'y'; MAX_BYTES + 10];
        assert_eq!(lines(&big)[0].len(), MAX_LINE);
        // Multi-byte boundary: 'é' is two bytes; the cut never splits it.
        let e = "é".repeat(MAX_LINE);
        let cut = &lines(e.as_bytes())[0];
        assert!(cut.len() <= MAX_LINE && cut.chars().all(|c| c == 'é'));
    }

    #[test]
    fn unterminated_escape_is_dropped_not_panicking() {
        assert!(lines(b"\x1b[").is_empty());
        assert!(lines(b"\x1b]never ends").is_empty());
        assert_eq!(lines(b"a\x1b"), vec!["a"]);
    }

    proptest! {
        #[test]
        fn output_is_always_clean(raw in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let out = lines(&raw);
            prop_assert!(out.len() <= MAX_LINES);
            for l in out {
                prop_assert!(is_clean(&l), "{l:?}");
            }
        }
    }
}
