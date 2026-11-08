//! RFC 6455 framing for the RD Gateway WebSocket (binary messages only, no extensions). The
//! client masks every frame; frames from the gateway must be unmasked, have no RSV bits and
//! stay under [`MAX_FRAME`]; control frames are ≤ 125 bytes and final. Fragmented binary
//! messages are delivered as a byte stream (MS-TSGU packets are parsed across frames), so
//! nothing is ever assembled beyond one frame. Fuzz entry: [`super::fuzz_rdg_pdu`] feeds
//! frames too.

/// Largest frame payload accepted from the gateway.
pub const MAX_FRAME: usize = 128 * 1024;

/// Opcodes.
pub mod op {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Payload of a binary (or continuation of a binary) frame.
    Binary(Vec<u8>),
    /// Ping with its payload (answered with a pong).
    Ping(Vec<u8>),
    /// Pong (ignored).
    Pong,
    /// Close.
    Close,
}

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// RSV bits, an unknown or text opcode, a masked server frame, a bad control frame or a
    /// continuation without a binary start.
    Protocol,
    /// Above [`MAX_FRAME`] (or a 64-bit length with the high bit set).
    TooLarge,
}

/// Stateful decoder (it tracks whether a fragmented binary message is open).
#[derive(Debug, Default)]
pub struct Decoder {
    in_binary: bool,
    /// When set, frames must be masked (the test gateway decodes client frames).
    expect_masked: bool,
}

impl Decoder {
    /// A decoder of gateway frames (`false`) or of client frames (`true`, test gateway).
    #[must_use]
    pub fn new(expect_masked: bool) -> Self {
        Self { in_binary: false, expect_masked }
    }

    /// Decode one frame from the front of `buf`: `Ok(None)` when incomplete, else the frame
    /// and the bytes it used.
    pub fn decode(&mut self, buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let (b0, b1) = (buf[0], buf[1]);
        let fin = b0 & 0x80 != 0;
        if b0 & 0x70 != 0 {
            return Err(FrameError::Protocol);
        }
        let opcode = b0 & 0x0F;
        let masked = b1 & 0x80 != 0;
        if masked != self.expect_masked {
            return Err(FrameError::Protocol);
        }
        let (len, mut at) = match b1 & 0x7F {
            126 => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
            }
            127 => {
                if buf.len() < 10 {
                    return Ok(None);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[2..10]);
                (u64::from_be_bytes(b), 10)
            }
            n => (u64::from(n), 2),
        };
        let len = usize::try_from(len).map_err(|_| FrameError::TooLarge)?;
        if len > MAX_FRAME {
            return Err(FrameError::TooLarge);
        }
        let control = opcode & 0x08 != 0;
        if control && (len > 125 || !fin) {
            return Err(FrameError::Protocol);
        }
        let mask = if masked {
            if buf.len() < at + 4 {
                return Ok(None);
            }
            let m = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
            at += 4;
            Some(m)
        } else {
            None
        };
        if buf.len() < at + len {
            return Ok(None);
        }
        let mut payload = buf[at..at + len].to_vec();
        if let Some(m) = mask {
            payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= m[i % 4]);
        }
        let frame = match opcode {
            op::BINARY if !self.in_binary => {
                self.in_binary = !fin;
                Frame::Binary(payload)
            }
            op::CONTINUATION if self.in_binary => {
                self.in_binary = !fin;
                Frame::Binary(payload)
            }
            op::PING => Frame::Ping(payload),
            op::PONG => Frame::Pong,
            op::CLOSE => Frame::Close,
            _ => return Err(FrameError::Protocol),
        };
        Ok(Some((frame, at + len)))
    }
}

/// Encode one final frame. `mask` = `Some(key)` for client frames.
#[must_use]
pub fn encode(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0F));
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(m | u8::try_from(n).unwrap_or(125)),
        n if u16::try_from(n).is_ok() => {
            out.push(m | 0x7E);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
        }
        n => {
            out.push(m | 0x7F);
            out.extend_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            out.extend_from_slice(&k);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_both_roles_and_lengths() {
        for len in [0usize, 5, 125, 126, 300, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).expect("u8")).collect();
            let client = encode(op::BINARY, &payload, Some([1, 2, 3, 4]));
            let mut srv = Decoder::new(true);
            let (f, used) = srv.decode(&client).expect("ok").expect("whole");
            assert_eq!((f, used), (Frame::Binary(payload.clone()), client.len()));
            let server = encode(op::BINARY, &payload, None);
            assert!(
                Decoder::default().decode(&server[..server.len() - 1]).expect("ok").is_none()
                    || len == 0
            );
            let (f, _) = Decoder::default().decode(&server).expect("ok").expect("whole");
            assert_eq!(f, Frame::Binary(payload));
        }
    }

    #[test]
    fn hostile_frames_are_refused() {
        let mut d = Decoder::default();
        // Masked server frame, RSV bit, text, oversized, long ping, fragmented close.
        assert_eq!(d.decode(&encode(op::BINARY, b"x", Some([0; 4]))), Err(FrameError::Protocol));
        assert_eq!(d.decode(&[0xC2, 0x00]), Err(FrameError::Protocol));
        assert_eq!(d.decode(&encode(op::TEXT, b"x", None)), Err(FrameError::Protocol));
        let mut big = vec![0x82, 127];
        big.extend_from_slice(&(MAX_FRAME as u64 + 1).to_be_bytes());
        assert_eq!(d.decode(&big), Err(FrameError::TooLarge));
        let mut huge = vec![0x82, 127];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(d.decode(&huge), Err(FrameError::TooLarge));
        assert_eq!(d.decode(&encode(op::PING, &[0; 126], None)), Err(FrameError::Protocol));
        assert_eq!(d.decode(&[0x08, 0x00]), Err(FrameError::Protocol));
        // A continuation without a start, then a proper fragmented message.
        assert_eq!(d.decode(&[0x80, 0x00]), Err(FrameError::Protocol));
        let mut d = Decoder::default();
        let (f, _) = d.decode(&[0x02, 0x01, b'a']).expect("ok").expect("first");
        assert_eq!(f, Frame::Binary(b"a".to_vec()));
        assert_eq!(d.decode(&[0x82, 0x00]), Err(FrameError::Protocol), "binary inside a message");
        let mut d = Decoder::default();
        d.decode(&[0x02, 0x01, b'a']).expect("ok");
        let (f, _) = d.decode(&[0x80, 0x01, b'b']).expect("ok").expect("cont");
        assert_eq!(f, Frame::Binary(b"b".to_vec()));
    }
}
