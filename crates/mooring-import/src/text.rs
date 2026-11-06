//! Text decoding shared by the importers: UTF-8 (with or without BOM) and UTF-16 with a BOM
//! (`PuTTY` `.reg` exports). Anything else is `import.format`, never transcoded by guessing.

use std::borrow::Cow;

use crate::error::{ImportError, Result};

/// Decode `bytes` as text. A UTF-16 input is transcoded (≤ 2× growth, within the input cap
/// the caller already enforced).
pub fn decode<'a>(bytes: &'a [u8], format: &'static str) -> Result<Cow<'a, str>> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return utf8(rest, format);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, format, u16::from_le_bytes).map(Cow::Owned);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, format, u16::from_be_bytes).map(Cow::Owned);
    }
    utf8(bytes, format)
}

fn utf8<'a>(bytes: &'a [u8], format: &'static str) -> Result<Cow<'a, str>> {
    std::str::from_utf8(bytes)
        .map(Cow::Borrowed)
        .map_err(|e| ImportError::format(format, "not UTF-8 text", e.valid_up_to() as u64))
}

fn utf16(bytes: &[u8], format: &'static str, unit: fn([u8; 2]) -> u16) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ImportError::format(format, "odd UTF-16 length", bytes.len() as u64));
    }
    let units = bytes.chunks_exact(2).map(|c| unit([c[0], c[1]]));
    char::decode_utf16(units)
        .enumerate()
        .map(|(i, r)| {
            r.map_err(|_| ImportError::format(format, "invalid UTF-16 surrogate", (i * 2) as u64))
        })
        .collect()
}

/// Split into lines on `\n`, `\r\n` or `\r`, refusing a line longer than `max` bytes.
pub fn lines(text: &str, max: usize) -> impl Iterator<Item = Result<(usize, &str)>> {
    text.lines().flat_map(|l| l.split('\r')).enumerate().map(move |(i, l)| {
        if l.len() > max {
            Err(ImportError::limits("line length"))
        } else {
            Ok((i + 1, l))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_boms() {
        assert_eq!(decode(b"\xEF\xBB\xBFhi", "t").expect("utf8"), "hi");
        assert_eq!(decode(b"hi", "t").expect("utf8"), "hi");
        assert_eq!(decode(b"\xFF\xFEh\x00i\x00", "t").expect("le"), "hi");
        assert_eq!(decode(b"\xFE\xFF\x00h\x00i", "t").expect("be"), "hi");
        assert!(decode(b"\xFF\xFEh\x00i", "t").is_err());
        assert!(decode(b"\xFF\xFE\x00\xD8", "t").is_err());
        assert!(matches!(decode(b"\xFFx", "t"), Err(ImportError::Format { at: 0, .. })));
    }

    #[test]
    fn lines_are_numbered_and_capped() {
        let v: Vec<_> = lines("a\r\nb\rc\n", 10).map(|r| r.expect("line")).collect();
        assert_eq!(v, vec![(1, "a"), (2, "b"), (3, "c")]);
        assert!(lines("abcdef", 3).next().expect("one").is_err());
    }
}
