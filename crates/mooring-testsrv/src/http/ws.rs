//! Minimal RFC 6455 server side for the kube exec / port-forward mocks: the opening handshake
//! on top of a hyper upgrade, and a frame codec (client frames must be masked, server frames are
//! not; ping → pong; fragmented messages are reassembled up to a cap). No extensions.

use std::io;

use base64::Engine as _;
use http::header::{HeaderValue, CONNECTION, UPGRADE};
use http::{Response, StatusCode};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{Body, Ctx};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Accept` for a client key (RFC 6455 §4.2.2).
pub fn accept_key(key: &str) -> String {
    // RFC 6455 mandates SHA-1 for the handshake accept key; it is not used for security here.
    let mut h = Sha1::new(); // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes
    h.update(key.as_bytes());
    h.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// The client's offered subprotocols, in its order.
pub fn offered_protocols(ctx: &Ctx) -> Vec<String> {
    ctx.headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Checks the upgrade request and picks the first client-offered protocol in `supported`.
/// Returns `(protocol, accept)` or a reason for a 400.
pub fn negotiate(ctx: &Ctx, supported: &[String]) -> Result<(String, String), String> {
    let has = |name, token: &str| {
        ctx.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    if !has(UPGRADE, "websocket") || !has(CONNECTION, "upgrade") {
        return Err("Upgrade request required".to_owned());
    }
    if ctx.header("sec-websocket-version") != Some("13") {
        return Err("unsupported Sec-WebSocket-Version".to_owned());
    }
    let key = ctx.header("sec-websocket-key").ok_or("missing Sec-WebSocket-Key")?;
    let offered = offered_protocols(ctx);
    let proto = offered.iter().find(|p| supported.contains(p)).ok_or_else(|| {
        format!("no supported subprotocol in {offered:?} (server: {supported:?})")
    })?;
    Ok((proto.clone(), accept_key(key)))
}

/// The `101 Switching Protocols` answer.
pub fn switching(accept: &str, protocol: &str) -> Response<Body> {
    let mut r = super::empty(StatusCode::SWITCHING_PROTOCOLS);
    let h = r.headers_mut();
    h.insert(UPGRADE, HeaderValue::from_static("websocket"));
    h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    if let Ok(v) = HeaderValue::from_str(accept) {
        h.insert("sec-websocket-accept", v);
    }
    if let Ok(v) = HeaderValue::from_str(protocol) {
        h.insert("sec-websocket-protocol", v);
    }
    r
}

/// A received data or close message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Binary(Vec<u8>),
    Text(Vec<u8>),
    Close(Option<u16>),
}

/// Server end of an upgraded connection.
#[derive(Debug)]
pub struct WsStream {
    io: TokioIo<Upgraded>,
    max_message: usize,
}

fn proto_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

impl WsStream {
    pub fn new(up: Upgraded, max_message: usize) -> Self {
        Self { io: TokioIo::new(up), max_message }
    }

    /// Next data / close message; `None` on EOF. Pings are answered here.
    pub async fn recv(&mut self) -> io::Result<Option<Message>> {
        let mut msg: Vec<u8> = Vec::new();
        let mut first_op: Option<u8> = None;
        loop {
            let mut h = [0u8; 2];
            match self.io.read_exact(&mut h).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            let fin = h[0] & 0x80 != 0;
            let op = h[0] & 0x0f;
            if h[0] & 0x70 != 0 {
                return Err(proto_err("reserved bits set"));
            }
            if h[1] & 0x80 == 0 {
                return Err(proto_err("unmasked client frame"));
            }
            let len = match h[1] & 0x7f {
                126 => u64::from(self.io.read_u16().await?),
                127 => self.io.read_u64().await?,
                n => u64::from(n),
            };
            let len = usize::try_from(len).map_err(|_| proto_err("frame too large"))?;
            if len > self.max_message || msg.len() + len > self.max_message {
                return Err(proto_err("message over the cap"));
            }
            let mut mask = [0u8; 4];
            self.io.read_exact(&mut mask).await?;
            let mut payload = vec![0u8; len];
            self.io.read_exact(&mut payload).await?;
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
            match op {
                0x9 => self.write_frame(0xA, &payload).await?,
                0xA => {}
                0x8 => {
                    let code =
                        (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]]));
                    return Ok(Some(Message::Close(code)));
                }
                0x0..=0x2 => {
                    if op != 0 {
                        if first_op.is_some() {
                            return Err(proto_err("new message inside a fragmented one"));
                        }
                        first_op = Some(op);
                    } else if first_op.is_none() {
                        return Err(proto_err("continuation without a message"));
                    }
                    msg.extend_from_slice(&payload);
                    if fin {
                        return Ok(Some(if first_op == Some(1) {
                            Message::Text(msg)
                        } else {
                            Message::Binary(msg)
                        }));
                    }
                }
                _ => return Err(proto_err("unknown opcode")),
            }
        }
    }

    async fn write_frame(&mut self, op: u8, data: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(data.len() + 10);
        out.push(0x80 | op);
        match data.len() {
            n if n < 126 => out.push(u8::try_from(n).unwrap_or(0)),
            n if u16::try_from(n).is_ok() => {
                out.push(126);
                out.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&u64::try_from(n).unwrap_or(0).to_be_bytes());
            }
        }
        out.extend_from_slice(data);
        self.io.write_all(&out).await?;
        self.io.flush().await
    }

    pub async fn send_binary(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_frame(0x2, data).await
    }

    /// Sends a close frame with `code` and stops writing.
    pub async fn close(&mut self, code: u16, reason: &str) -> io::Result<()> {
        let mut p = code.to_be_bytes().to_vec();
        p.extend_from_slice(reason.as_bytes());
        self.write_frame(0x8, &p).await?;
        self.io.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn accept_key_matches_rfc_6455_example() {
        assert_eq!(super::accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
