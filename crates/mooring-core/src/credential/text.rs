//! Character and size rules shared by every credential field (ADR-0009 §5).

use super::CredentialError;
use crate::model::is_bidi_or_invisible;

/// Control, bidi and invisible format characters: never allowed in single-line credential text.
#[must_use]
pub fn is_forbidden(c: char) -> bool {
    c.is_control() || is_bidi_or_invisible(c)
}

/// Multiline values (PEM, YAML) may keep `\n`, `\r`, `\t`; nothing else that [`is_forbidden`].
fn is_forbidden_multiline(c: char) -> bool {
    !matches!(c, '\n' | '\r' | '\t') && is_forbidden(c)
}

/// Trim and check a single-line text field: `1..=max` bytes after trimming, no forbidden chars.
pub(crate) fn line(field: &'static str, v: &str, max: usize) -> Result<String, CredentialError> {
    let t = v.trim();
    if t.is_empty() {
        return Err(CredentialError::invalid(field, "is required"));
    }
    if t.len() > max {
        return Err(CredentialError::invalid(field, format!("longer than {max} bytes")));
    }
    if t.chars().any(is_forbidden) {
        return Err(CredentialError::invalid(
            field,
            "contains a control or invisible formatting character",
        ));
    }
    Ok(t.to_owned())
}

/// Optional single-line field: blank becomes `None`.
pub(crate) fn opt_line(
    field: &'static str,
    v: Option<&str>,
    max: usize,
) -> Result<Option<String>, CredentialError> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => line(field, s, max).map(Some),
    }
}

/// Multiline text (PEM, YAML, OpenSSH lines): not trimmed inside, `1..=max` bytes.
pub(crate) fn multiline(field: &'static str, v: &str, max: usize) -> Result<(), CredentialError> {
    if v.trim().is_empty() {
        return Err(CredentialError::invalid(field, "is required"));
    }
    if v.len() > max {
        return Err(CredentialError::invalid(field, format!("longer than {max} bytes")));
    }
    if v.chars().any(is_forbidden_multiline) {
        return Err(CredentialError::invalid(
            field,
            "contains a control or invisible formatting character",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_rules() {
        assert_eq!(line("u", "  alice ", 8).expect("ok"), "alice");
        assert!(line("u", "", 8).is_err());
        assert!(line("u", "123456789", 8).is_err());
        assert!(line("u", "12345678", 8).is_ok());
        for bad in ["a\nb", "a\u{202e}b", "a\u{200b}", "\u{7}"] {
            let e = line("u", bad, 64).expect_err("forbidden");
            assert!(!e.to_string().contains(bad), "no echo");
        }
        assert_eq!(opt_line("d", Some("   "), 8).expect("blank"), None);
        assert_eq!(opt_line("d", None, 8).expect("none"), None);
    }

    #[test]
    fn multiline_rules() {
        assert!(multiline("p", "-----BEGIN X-----\r\nAA\tBB\n", 64).is_ok());
        assert!(multiline("p", "a\u{0}b", 64).is_err());
        assert!(multiline("p", "a\u{202e}b", 64).is_err());
        assert!(multiline("p", " \n ", 64).is_err());
        assert!(multiline("p", &"a".repeat(65), 64).is_err());
    }
}
