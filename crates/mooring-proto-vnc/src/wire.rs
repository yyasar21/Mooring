//! Incremental parsing helpers: every RFB parser is a pure function over the bytes received
//! so far and answers either "need at least N bytes in total" or "done, consumed M bytes".
//! Nothing here allocates from a server-supplied length before that length is checked.

use crate::error::VncError;

/// Result of a parser over a possibly incomplete buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<T> {
    /// The buffer must hold at least this many bytes (in total, from its start) before the
    /// parser can make progress. Always greater than the current length.
    Need(usize),
    /// A complete item and the number of bytes it occupied.
    Done(T, usize),
}

impl<T> Parsed<T> {
    /// Map the item.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Parsed<U> {
        match self {
            Self::Need(n) => Parsed::Need(n),
            Self::Done(t, used) => Parsed::Done(f(t), used),
        }
    }
}

/// Parser result.
pub type PResult<T> = Result<Parsed<T>, VncError>;

/// Unwrap a [`Rd`] read: on a short buffer return `Ok(Parsed::Need(..))` from the caller.
macro_rules! take {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(need) => return Ok($crate::wire::Parsed::Need(need)),
        }
    };
}
pub(crate) use take;

/// A cursor over a byte slice. Reads past the end return `Err(total_needed)`.
#[derive(Debug, Clone, Copy)]
pub struct Rd<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    /// Start at offset 0.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes left.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Take `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], usize> {
        let end = self.pos.checked_add(n).ok_or(usize::MAX)?;
        if end > self.buf.len() {
            return Err(end);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<(), usize> {
        self.bytes(n).map(|_| ())
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, usize> {
        Ok(self.bytes(1)?[0])
    }

    /// Big-endian u16.
    pub fn u16(&mut self) -> Result<u16, usize> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Big-endian u32.
    pub fn u32(&mut self) -> Result<u32, usize> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Big-endian i32.
    pub fn i32(&mut self) -> Result<i32, usize> {
        let b = self.bytes(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// `usize` from a wire `u32` (lossless on every supported target).
pub fn len_u32(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two(buf: &[u8]) -> PResult<(u8, u16)> {
        let mut r = Rd::new(buf);
        let a = take!(r.u8());
        let b = take!(r.u16());
        Ok(Parsed::Done((a, b), r.pos()))
    }

    #[test]
    fn need_reports_total_length() {
        assert_eq!(two(&[]).expect("p"), Parsed::Need(1));
        assert_eq!(two(&[1, 0]).expect("p"), Parsed::Need(3));
        assert_eq!(two(&[1, 0, 2, 9]).expect("p"), Parsed::Done((1, 2), 3));
        let mut r = Rd::new(&[0; 4]);
        assert_eq!(r.bytes(usize::MAX), Err(usize::MAX));
        assert_eq!(r.i32(), Ok(0));
        assert_eq!(r.remaining(), 0);
    }
}
