//! Bounded BER framing for the directory reader. `lber`'s `parse_tag` recurses per nesting
//! level, so a few KiB of nested SEQUENCEs from a hostile server would overflow the stack;
//! [`scan`] walks the TLV structure **iteratively** first (definite lengths only, ≤ 4 length
//! octets, depth ≤ [`MAX_DEPTH`], size ≤ [`MAX_FRAME`]) and only a frame it accepts is handed
//! to the recursive parser. Fuzzed through `ldap_ber_response`.

/// Largest `LDAPMessage` accepted from the server (one entry, one result, one notice).
pub const MAX_FRAME: usize = 256 * 1024;
/// Deepest nesting accepted (an entry is 6 levels deep; controls on a result are 5).
pub const MAX_DEPTH: usize = 32;

/// Outcome of [`scan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// A complete top-level element occupies the first `len` bytes.
    Complete(usize),
    /// More bytes are needed (at least one).
    Incomplete,
    /// The bytes can never become a valid frame.
    Invalid(&'static str),
}

/// Identifier + length header at `pos`: `(header_len, constructed, content_len)`.
fn header(buf: &[u8], pos: usize) -> Result<Option<(usize, bool, usize)>, &'static str> {
    let Some(&first) = buf.get(pos) else { return Ok(None) };
    let constructed = first & 0x20 != 0;
    let mut i = pos + 1;
    if first & 0x1f == 0x1f {
        // High tag number form: up to 4 continuation octets.
        let mut n = 0;
        loop {
            let Some(&b) = buf.get(i) else { return Ok(None) };
            i += 1;
            n += 1;
            if n > 4 {
                return Err("tag number too long");
            }
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let Some(&l) = buf.get(i) else { return Ok(None) };
    i += 1;
    let len = if l < 0x80 {
        usize::from(l)
    } else {
        let n = usize::from(l & 0x7f);
        if n == 0 {
            return Err("indefinite length");
        }
        if n > 4 {
            return Err("length octets exceed 4");
        }
        let Some(bytes) = buf.get(i..i + n) else { return Ok(None) };
        i += n;
        bytes.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
    };
    Ok(Some((i - pos, constructed, len)))
}

/// Iterative structural walk of the first element of `buf`.
#[must_use]
pub fn scan(buf: &[u8]) -> Scan {
    let mut pos = 0usize;
    // Ends of the open constructed elements, outermost first.
    let mut ends: Vec<usize> = Vec::new();
    let mut total: Option<usize> = None;
    loop {
        if let Some(t) = total {
            // Close every constructed element that ends here.
            while ends.last().is_some_and(|e| *e == pos) {
                ends.pop();
            }
            if ends.is_empty() {
                return Scan::Complete(t);
            }
        }
        let outer = ends.last().copied().unwrap_or(MAX_FRAME);
        if pos >= outer {
            return Scan::Invalid("element overruns its parent");
        }
        let (hlen, constructed, len) = match header(buf, pos) {
            Ok(Some(h)) => h,
            Ok(None) => {
                return if pos < MAX_FRAME {
                    Scan::Incomplete
                } else {
                    Scan::Invalid("frame too large")
                }
            }
            Err(e) => return Scan::Invalid(e),
        };
        let Some(end) = pos.checked_add(hlen).and_then(|p| p.checked_add(len)) else {
            return Scan::Invalid("length overflow");
        };
        if end > outer {
            return Scan::Invalid(if outer == MAX_FRAME {
                "frame too large"
            } else {
                "element overruns its parent"
            });
        }
        if total.is_none() {
            total = Some(end);
        }
        pos += hlen;
        if constructed {
            if ends.len() >= MAX_DEPTH {
                return Scan::Invalid("nesting too deep");
            }
            ends.push(end);
        } else {
            pos = end;
        }
        if pos > buf.len() {
            return Scan::Incomplete;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_primitive_constructed_and_partial_frames() {
        assert_eq!(scan(b""), Scan::Incomplete);
        assert_eq!(scan(b"\x04"), Scan::Incomplete);
        assert_eq!(scan(b"\x04\x02a"), Scan::Incomplete);
        assert_eq!(scan(b"\x04\x02ab"), Scan::Complete(4));
        assert_eq!(scan(b"\x04\x02abXYZ"), Scan::Complete(4));
        assert_eq!(scan(b"\x30\x00"), Scan::Complete(2));
        assert_eq!(scan(b"\x30\x05\x02\x01\x01\x05\x00"), Scan::Complete(7));
        assert_eq!(scan(b"\x30\x07\x30\x05\x02\x01\x01\x05\x00"), Scan::Complete(9));
        assert_eq!(
            scan(b"\x30\x04\x02\x01\x01\x05\x00"),
            Scan::Invalid("element overruns its parent")
        );
        assert_eq!(scan(b"\x30\x04\x02\x01\x01"), Scan::Incomplete);
        assert_eq!(
            scan(b"\x30\x03\x02\x03\x01\x02\x03"),
            Scan::Invalid("element overruns its parent")
        );
        assert_eq!(scan(b"\x30\x80"), Scan::Invalid("indefinite length"));
        assert_eq!(scan(b"\x30\x85\x00\x00\x00\x00\x01"), Scan::Invalid("length octets exceed 4"));
        assert_eq!(scan(b"\x30\x84\xff\xff\xff\xff\x00"), Scan::Invalid("frame too large"));
        assert_eq!(scan(b"\x30\x82\x01\x00"), Scan::Incomplete);
        // Long-form length within the cap, high tag number form.
        let mut long = vec![0x04, 0x82, 0x01, 0x00];
        long.extend(std::iter::repeat_n(0u8, 256));
        assert_eq!(scan(&long), Scan::Complete(260));
        assert_eq!(scan(b"\x5f\x81\x01\x01\x00"), Scan::Complete(5));
        assert_eq!(scan(b"\x7f\x81\x01\x01\x00"), Scan::Incomplete);
        assert_eq!(scan(b"\x5f\x81\x81\x81\x81\x01\x00"), Scan::Invalid("tag number too long"));
    }

    #[test]
    fn deep_nesting_is_refused_without_recursion() {
        let mut inner = vec![0x30, 0x00];
        for _ in 0..MAX_DEPTH - 1 {
            let mut next = vec![0x30, u8::try_from(inner.len()).expect("short")];
            next.extend_from_slice(&inner);
            inner = next;
        }
        assert_eq!(scan(&inner), Scan::Complete(inner.len()));
        let mut deeper = vec![0x30, u8::try_from(inner.len()).expect("short")];
        deeper.extend_from_slice(&inner);
        assert_eq!(scan(&deeper), Scan::Invalid("nesting too deep"));
        // 100 000 levels: a few hundred KiB, scanned in constant stack.
        let mut huge = vec![0x30, 0x00];
        for _ in 0..100_000 {
            let len = huge.len();
            let [.., b2, b1, b0] = len.to_be_bytes();
            let mut next = vec![0x30, 0x83, b2, b1, b0];
            next.extend_from_slice(&huge);
            huge = next;
            if huge.len() > MAX_FRAME {
                break;
            }
        }
        assert!(matches!(scan(&huge), Scan::Invalid(_)));
    }
}
