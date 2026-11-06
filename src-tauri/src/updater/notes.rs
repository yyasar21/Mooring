//! Release notes are untrusted text from `latest.json` (ADR-0018 §3): shown as plain text,
//! capped, with control and bidi-override characters removed so a manifest cannot smuggle
//! terminal escapes, hidden text or reversed strings into the Updates card.

/// Largest sanitised notes text (bytes), per the U0 brief (the ADR's 16 KiB is the ceiling
/// of the raw manifest field; the UI shows at most this much).
pub const MAX_NOTES: usize = 4 * 1024;

/// Unicode bidi controls and other invisible formatting characters that are removed
/// (review 7 N-56: every `Cf` the notes could smuggle — bidi isolates and embeddings,
/// zero-width joiners, word joiner and friends, variation selectors, tag characters —
/// plus the C0/C1 controls other than `\n` / `\t`).
fn is_dropped(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'                // soft hyphen
        | '\u{061C}'              // Arabic letter mark
        | '\u{180B}'..='\u{180F}' // Mongolian free variation selectors + vowel separator
        | '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM, RLM
        | '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
        | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
        | '\u{2066}'..='\u{206F}' // LRI, RLI, FSI, PDI, deprecated format controls
        | '\u{FE00}'..='\u{FE0F}' // variation selectors 1-16
        | '\u{FEFF}'              // BOM / ZWNBSP
        | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
        | '\u{E0000}'..='\u{E007F}' // tag characters
        | '\u{E0100}'..='\u{E01EF}' // variation selectors 17-256
    ) || (c.is_control() && c != '\n' && c != '\t')
}

/// The Unicode line and paragraph separators become plain newlines (they would otherwise
/// pass through as invisible text that still breaks a line in some renderers).
fn normalise_separators(raw: &str) -> String {
    raw.replace(['\u{2028}', '\u{2029}'], "\n")
}

/// Remove whole ANSI escape sequences, not just the `ESC` byte: CSI (`ESC [ … final`), OSC
/// (`ESC ] … BEL` / `ESC \`) and two-byte escapes (`ESC x`). A lone trailing `ESC` is dropped.
fn strip_escapes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                // Parameter / intermediate bytes 0x20..=0x3F, then one final byte 0x40..=0x7E.
                for n in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(n) = chars.next() {
                    if n == '\u{7}' {
                        break;
                    }
                    if n == '\u{1b}' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Strip control / bidi characters, normalise line endings, collapse runs of blank lines and
/// cap at [`MAX_NOTES`] bytes on a character boundary (a cut text ends with `…`).
pub fn sanitise(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_NOTES + 4));
    let mut blank_run = 0usize;
    let text = normalise_separators(&strip_escapes(raw)).replace("\r\n", "\n").replace('\r', "\n");
    for line in text.split('\n') {
        let line: String = line.chars().filter(|c| !is_dropped(*c)).collect();
        let line = line.trim_end();
        if line.is_empty() {
            blank_run += 1;
            if blank_run > 1 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
    }
    let out = out.trim().to_owned();
    if out.len() <= MAX_NOTES {
        return out;
    }
    let mut cut = MAX_NOTES - '…'.len_utf8();
    while !out.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut capped = out[..cut].trim_end().to_owned();
    capped.push('…');
    capped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls_and_bidi_but_keeps_text_newlines_and_tabs() {
        let raw = "Fixed \u{202E}gnihtemos\u{202C} bad\x1b[31m\x07\n\tindented\u{200B}\r\nend\u{FEFF}";
        assert_eq!(sanitise(raw), "Fixed gnihtemos bad\n\tindented\nend");
    }

    #[test]
    fn whole_escape_sequences_go() {
        assert_eq!(sanitise("a\x1b[1;31mb\x1b[0m c"), "ab c");
        assert_eq!(sanitise("x\x1b]8;;https://example.test\x07link\x1b]8;;\x1b\\y"), "xlinky");
        assert_eq!(sanitise("t\x1bMu\x1b"), "tu", "two-byte escape and a trailing ESC");
    }

    #[test]
    fn collapses_blank_runs_and_trims() {
        assert_eq!(sanitise("\n\n a \n\n\n\n b  \n\n"), "a\n\n b", "indentation is kept");
        assert_eq!(sanitise(""), "");
        assert_eq!(sanitise("\u{202A}\u{202B}"), "");
    }

    #[test]
    fn caps_on_a_char_boundary_with_an_ellipsis() {
        let raw = "é".repeat(MAX_NOTES); // 2 bytes each → twice the cap
        let out = sanitise(&raw);
        assert!(out.len() <= MAX_NOTES, "{}", out.len());
        assert!(out.ends_with('…'));
        assert!(out.trim_end_matches('…').chars().all(|c| c == 'é'));
        let exact = "x".repeat(MAX_NOTES);
        assert_eq!(sanitise(&exact), exact, "exactly the cap is untouched");
    }

    /// Review 7 N-56: the remaining `Cf` characters, the line / paragraph separators and
    /// the tag block go too; ordinary non-ASCII text stays.
    #[test]
    fn strips_invisible_format_characters_and_tag_block() {
        let raw = "a\u{2060}b\u{2061}c\u{200B}d\u{200F}e\u{2066}f\u{2069}g\u{FEFF}h\u{061C}i\u{180E}j\u{FE0F}k\u{E0100}l\u{E0001}m\u{E007F}n\u{00AD}o";
        assert_eq!(sanitise(raw), "abcdefghijklmno");
        assert_eq!(sanitise("one\u{2028}two\u{2029}three"), "one\ntwo\nthree");
        assert_eq!(sanitise("x\u{2028}\u{2029}\u{2028}y"), "x\n\ny", "separators collapse like blank lines");
        assert_eq!(sanitise("Türkçe – ok ✓ 日本"), "Türkçe – ok ✓ 日本", "visible text is untouched");
        for c in ['\u{2060}', '\u{206F}', '\u{E0000}', '\u{E007F}', '\u{FE00}', '\u{E01EF}', '\u{180B}'] {
            assert!(is_dropped(c), "{c:?}");
        }
        for c in ['a', 'é', '日', '\n', '\t', ' ', '–'] {
            assert!(!is_dropped(c), "{c:?}");
        }
    }

    #[test]
    fn markdown_and_html_are_left_as_plain_text() {
        let raw = "# Title\n<script>alert(1)</script> **bold**";
        assert_eq!(sanitise(raw), raw, "no rendering: the UI shows it verbatim as text");
    }
}
