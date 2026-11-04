//! A byte transport (TCP or TLS) with a receive buffer driven by the pure parsers.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::VncError;
use crate::wire::{PResult, Parsed};

/// Anything we can speak RFB over.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Default cap on one buffered item during the handshake.
pub const HANDSHAKE_MAX: usize = 64 * 1024;
const READ_CHUNK: usize = 64 * 1024;

/// Receive buffer over a reader.
#[derive(Debug)]
pub struct RecvBuf<R> {
    pub(crate) io: R,
    buf: Vec<u8>,
    /// Largest item that may be buffered.
    pub(crate) max: usize,
}

impl<R: AsyncRead + Unpin> RecvBuf<R> {
    /// Wrap a reader.
    pub fn new(io: R) -> Self {
        Self { io, buf: Vec::new(), max: HANDSHAKE_MAX }
    }

    /// Wrap a reader with bytes already received.
    pub fn with_leftover(io: R, buf: Vec<u8>, max: usize) -> Self {
        Self { io, buf, max }
    }

    /// Bytes buffered but not consumed.
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Give up the reader and the unconsumed bytes.
    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.io, self.buf)
    }

    async fn fill_to(&mut self, n: usize) -> Result<(), VncError> {
        if n > self.max {
            return Err(VncError::protocol("message exceeds the size cap"));
        }
        if self.buf.capacity() < n {
            self.buf.reserve(n - self.buf.len());
        }
        while self.buf.len() < n {
            let start = self.buf.len();
            self.buf.resize(start + READ_CHUNK, 0);
            let got = self.io.read(&mut self.buf[start..]).await;
            match got {
                Ok(0) => {
                    self.buf.truncate(start);
                    return Err(VncError::Network("connection closed by the server".into()));
                }
                Ok(k) => self.buf.truncate(start + k),
                Err(e) => {
                    self.buf.truncate(start);
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    /// Run `parse` until it completes; returns the item and its length, without consuming.
    pub async fn peek<T>(
        &mut self,
        parse: impl Fn(&[u8]) -> PResult<T>,
    ) -> Result<(T, usize), VncError> {
        loop {
            match parse(&self.buf)? {
                Parsed::Done(t, n) => return Ok((t, n)),
                Parsed::Need(n) => self.fill_to(n.max(self.buf.len() + 1)).await?,
            }
        }
    }

    /// Run `parse` until it completes and consume the item.
    pub async fn next<T>(&mut self, parse: impl Fn(&[u8]) -> PResult<T>) -> Result<T, VncError> {
        let (t, n) = self.peek(parse).await?;
        self.consume(n);
        Ok(t)
    }

    /// Drop `n` consumed bytes from the front.
    pub fn consume(&mut self, n: usize) {
        self.buf.drain(..n.min(self.buf.len()));
    }

    /// Read and throw away `n` bytes (oversized cut text) without buffering them.
    pub async fn discard(&mut self, mut n: usize) -> Result<(), VncError> {
        let have = n.min(self.buf.len());
        self.consume(have);
        n -= have;
        let mut scratch = vec![0u8; READ_CHUNK];
        while n > 0 {
            let k = self.io.read(&mut scratch[..n.min(READ_CHUNK)]).await?;
            if k == 0 {
                return Err(VncError::Network("connection closed by the server".into()));
            }
            n -= k;
        }
        Ok(())
    }
}

/// Handshake connection: one buffered stream.
pub type Conn = RecvBuf<Box<dyn Io>>;

/// Write one message and flush (TLS buffers otherwise).
pub async fn send<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, msg: &[u8]) -> Result<(), VncError> {
    w.write_all(msg).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{take, Rd};

    fn four(b: &[u8]) -> PResult<u32> {
        let mut r = Rd::new(b);
        Ok(Parsed::Done(take!(r.u32()), 4))
    }

    #[tokio::test]
    async fn reads_across_chunks_and_caps() {
        let (mut a, b) = tokio::io::duplex(8);
        let mut rb = RecvBuf::new(b);
        tokio::spawn(async move {
            for byte in [0u8, 0, 1, 2, 9, 9, 9, 9, 0, 0, 0, 0] {
                a.write_all(&[byte]).await.expect("w");
            }
            // 20 bytes to discard, then EOF.
            a.write_all(&[7; 20]).await.expect("w");
        });
        assert_eq!(rb.next(four).await.expect("u32"), 0x0102);
        let (v, n) = rb.peek(four).await.expect("peek");
        assert_eq!((v, n), (0x0909_0909, 4));
        rb.consume(n);
        assert_eq!(rb.next(four).await.expect("u32"), 0);
        rb.discard(20).await.expect("discard");
        assert!(matches!(rb.next(four).await, Err(VncError::Network(_))));
        let mut capped = RecvBuf::new(tokio::io::empty());
        capped.max = 2;
        assert!(matches!(capped.next(four).await, Err(VncError::Protocol(_))));
    }
}
