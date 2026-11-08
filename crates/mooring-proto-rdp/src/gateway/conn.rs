//! The byte layers above the gateway's TLS: buffered HTTP reads for the upgrade, then the
//! WebSocket carrying MS-TSGU packets. Every read is bounded by the caps of [`super::http`],
//! [`super::ws`] and [`super::pdu`].

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::http::{self, Head};
use super::pdu::{self, Packet};
use super::ws::{self, Decoder, Frame};

/// Per-step deadline of the upgrade and the tunnel setup.
pub(crate) const STEP: Duration = Duration::from_secs(15);

/// A failure of the gateway byte layers; the caller maps it to a close code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wire {
    /// I/O error, EOF or a deadline.
    Io,
    /// A malformed HTTP head, WebSocket frame or MS-TSGU packet.
    Protocol(&'static str),
}

/// Random bytes from the ring provider of our TLS stack. A failed system RNG ends the open
/// (review 9 N-72) instead of sending constant keys, masks or connection ids.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Wire> {
    random_from(crate::tls::provider().secure_random)
}

pub(crate) fn random_from<const N: usize>(
    rng: &dyn rustls::crypto::SecureRandom,
) -> Result<[u8; N], Wire> {
    let mut b = [0u8; N];
    rng.fill(&mut b).map_err(|_| {
        tracing::warn!("system random source failed");
        Wire::Protocol("system random source failed")
    })?;
    Ok(b)
}

/// The TLS stream with a read-ahead buffer.
pub(crate) struct Conn<S> {
    pub(crate) io: S,
    pub(crate) buf: Vec<u8>,
}

impl<S> std::fmt::Debug for Conn<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").field("buffered", &self.buf.len()).finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub(crate) fn new(io: S) -> Self {
        Self { io, buf: Vec::new() }
    }

    async fn fill(&mut self) -> Result<(), Wire> {
        let mut tmp = vec![0u8; 16 * 1024];
        let n = tokio::time::timeout(STEP, self.io.read(&mut tmp))
            .await
            .map_err(|_| Wire::Io)?
            .map_err(|_| Wire::Io)?;
        if n == 0 {
            return Err(Wire::Io);
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(())
    }

    pub(crate) async fn write(&mut self, bytes: &[u8]) -> Result<(), Wire> {
        let w = async {
            self.io.write_all(bytes).await?;
            self.io.flush().await
        };
        tokio::time::timeout(STEP, w).await.map_err(|_| Wire::Io)?.map_err(|_| Wire::Io)
    }

    /// Read one response head and drain its body (capped), leaving any bytes after it.
    pub(crate) async fn read_response(&mut self) -> Result<Head, Wire> {
        let end = loop {
            match http::head_end(&self.buf) {
                Ok(Some(e)) => break e,
                Ok(None) => self.fill().await?,
                Err(_) => return Err(Wire::Protocol("the RD Gateway response head is too large")),
            }
        };
        let head = http::parse_head(&self.buf[..end])
            .map_err(|_| Wire::Protocol("malformed RD Gateway HTTP response"))?;
        self.buf.drain(..end);
        if head.status != 101 {
            let body = head
                .body_len()
                .map_err(|_| Wire::Protocol("unsupported RD Gateway response body"))?;
            while self.buf.len() < body {
                self.fill().await?;
            }
            self.buf.drain(..body);
        }
        Ok(head)
    }
}

/// The WebSocket over [`Conn`], carrying MS-TSGU packets as a byte stream.
pub(crate) struct WsConn<S> {
    pub(crate) conn: Conn<S>,
    dec: Decoder,
    /// MS-TSGU bytes received, not yet a whole packet.
    rdg: Vec<u8>,
    closed: bool,
}

impl<S> std::fmt::Debug for WsConn<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConn").field("closed", &self.closed).finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsConn<S> {
    pub(crate) fn new(conn: Conn<S>) -> Self {
        Self { conn, dec: Decoder::new(false), rdg: Vec::new(), closed: false }
    }

    /// Send one MS-TSGU packet in one masked binary frame.
    pub(crate) async fn send(&mut self, packet: &[u8]) -> Result<(), Wire> {
        let frame = ws::encode(ws::op::BINARY, packet, Some(random()?));
        self.conn.write(&frame).await
    }

    /// Best-effort close frame.
    pub(crate) async fn close(&mut self) {
        let Ok(mask) = random() else { return };
        let frame = ws::encode(ws::op::CLOSE, &[0x03, 0xE8], Some(mask));
        let _ = self.conn.write(&frame).await;
    }

    /// Process buffered bytes: frames into the MS-TSGU stream, pings answered. Returns the
    /// next whole packet if one is complete.
    pub(crate) async fn poll_packet(&mut self) -> Result<Option<Packet>, Wire> {
        loop {
            match pdu::peek_len(&self.rdg) {
                Err(_) => return Err(Wire::Protocol("RD Gateway packet length out of range")),
                Ok(Some(n)) if self.rdg.len() >= n => {
                    let p = pdu::decode(&self.rdg[..n])
                        .map_err(|_| Wire::Protocol("malformed RD Gateway packet"))?;
                    self.rdg.drain(..n);
                    return Ok(Some(p));
                }
                Ok(_) => {}
            }
            if self.closed {
                return Err(Wire::Io);
            }
            let Some((frame, used)) = self
                .dec
                .decode(&self.conn.buf)
                .map_err(|_| Wire::Protocol("malformed RD Gateway WebSocket frame"))?
            else {
                return Ok(None);
            };
            self.conn.buf.drain(..used);
            match frame {
                Frame::Binary(b) => {
                    if self.rdg.len() + b.len() > pdu::MAX_PACKET * 2 {
                        return Err(Wire::Protocol("RD Gateway packet length out of range"));
                    }
                    self.rdg.extend_from_slice(&b);
                }
                Frame::Ping(p) => {
                    let pong = ws::encode(ws::op::PONG, &p, Some(random()?));
                    self.conn.write(&pong).await?;
                }
                Frame::Pong => {}
                Frame::Close => self.closed = true,
            }
        }
    }

    /// The next packet, reading as needed (bounded by [`STEP`] per read).
    pub(crate) async fn recv(&mut self) -> Result<Packet, Wire> {
        loop {
            if let Some(p) = self.poll_packet().await? {
                return Ok(p);
            }
            self.conn.fill().await?;
        }
    }

    /// Bytes read from the socket outside [`Self::recv`] (the relay's own read).
    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        self.conn.buf.extend_from_slice(bytes);
    }
}
