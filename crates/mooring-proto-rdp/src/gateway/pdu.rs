//! MS-TSGU §2.2.10 HTTP-transport packets (the payload of the `RDG_OUT_DATA` WebSocket):
//! our own encoders and a bounded decoder. Every byte from the gateway is hostile: the header
//! length is checked against [`MAX_PACKET`] before anything is buffered, every inner length
//! against the packet, and decoding never allocates more than the packet holds. Fuzz entry:
//! [`super::fuzz_rdg_pdu`].

/// `HTTP_PACKET_HEADER` size.
pub const HEADER: usize = 8;
/// Largest packet accepted (a full `DATA` packet is 8 + 2 + 65 535 bytes; certificates and
/// consent messages in `TUNNEL_RESPONSE` are u16-length-prefixed as well).
pub const MAX_PACKET: usize = 72 * 1024;
/// Largest `DATA` payload we send in one packet.
pub const MAX_DATA: usize = 32 * 1024;

/// Packet types (MS-TSGU 2.2.5.3.3).
pub mod ty {
    pub const HANDSHAKE_REQUEST: u16 = 0x01;
    pub const HANDSHAKE_RESPONSE: u16 = 0x02;
    pub const EXTENDED_AUTH_MSG: u16 = 0x03;
    pub const TUNNEL_CREATE: u16 = 0x04;
    pub const TUNNEL_RESPONSE: u16 = 0x05;
    pub const TUNNEL_AUTH: u16 = 0x06;
    pub const TUNNEL_AUTH_RESPONSE: u16 = 0x07;
    pub const CHANNEL_CREATE: u16 = 0x08;
    pub const CHANNEL_RESPONSE: u16 = 0x09;
    pub const DATA: u16 = 0x0A;
    pub const SERVICE_MESSAGE: u16 = 0x0B;
    pub const REAUTH_MESSAGE: u16 = 0x0C;
    pub const KEEPALIVE: u16 = 0x0D;
    pub const CLOSE_CHANNEL: u16 = 0x10;
    pub const CLOSE_CHANNEL_RESPONSE: u16 = 0x11;
}

/// `HTTP_CAPABILITY_IDLE_TIMEOUT`: the only capability we announce (no SOH / NAP, no PAA,
/// no UDP side channel, no consent / service messages, no in-band reauth).
pub const CAPS_IDLE_TIMEOUT: u32 = 0x02;
/// `HTTP_TUNNEL_RESPONSE_FIELD_*`.
const TR_TUNNEL_ID: u16 = 0x01;
const TR_CAPS: u16 = 0x02;
const TR_SOH_REQ: u16 = 0x04;
const TR_CONSENT_MSG: u16 = 0x10;
/// `HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID`.
const CR_CHANNEL_ID: u16 = 0x01;
/// `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` and friends are never sent.
const PROTOCOL_TCP: u16 = 3;
/// Longest `client_name` (UTF-16 code units, without the terminator).
pub const MAX_CLIENT_NAME: usize = 32;
/// Longest target host in `CHANNEL_CREATE`.
pub const MAX_RESOURCE: usize = 255;

/// A decoded packet from the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// `HANDSHAKE_RESPONSE`.
    HandshakeResponse { error: u32, major: u8, minor: u8, server_version: u16, extended_auth: u16 },
    /// `TUNNEL_RESPONSE`.
    TunnelResponse { status: u32, tunnel_id: Option<u32>, caps: Option<u32> },
    /// `TUNNEL_AUTH_RESPONSE`.
    TunnelAuthResponse { error: u32, idle_timeout_minutes: Option<u32> },
    /// `CHANNEL_RESPONSE`.
    ChannelResponse { error: u32, channel_id: Option<u32> },
    /// `DATA` (the RDP stream).
    Data(Vec<u8>),
    /// `KEEPALIVE`.
    Keepalive,
    /// `SERVICE_MESSAGE` (text dropped; length only, for the log).
    ServiceMessage { len: usize },
    /// `REAUTH_MESSAGE`: we answer by closing; the session reconnects the whole tunnel.
    Reauth,
    /// `CLOSE_CHANNEL` from the gateway.
    CloseChannel { status: u32 },
    /// `CLOSE_CHANNEL_RESPONSE`.
    CloseChannelResponse { status: u32 },
    /// Any other type (`EXTENDED_AUTH_MSG`, client-only types): the caller refuses it.
    Other { ty: u16 },
}

/// Why bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduError {
    /// Header length below 8 or above [`MAX_PACKET`].
    BadLength,
    /// A field ran past the packet, or trailing bytes after a fixed-size packet.
    Truncated,
}

impl std::fmt::Display for PduError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadLength => "RD Gateway packet length out of range",
            Self::Truncated => "malformed RD Gateway packet",
        })
    }
}

impl std::error::Error for PduError {}

/// Little-endian reader over one packet body.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PduError> {
        if self.0.len() < n {
            return Err(PduError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, PduError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, PduError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, PduError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// A u16-length-prefixed blob, skipped.
    fn skip_blob(&mut self) -> Result<usize, PduError> {
        let n = usize::from(self.u16()?);
        self.take(n).map(<[u8]>::len)
    }
}

/// The length of the next packet in `buf` once its header is complete. `Err` on a hostile
/// length, so the caller never buffers more than [`MAX_PACKET`].
pub fn peek_len(buf: &[u8]) -> Result<Option<usize>, PduError> {
    if buf.len() < HEADER {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let len = usize::try_from(len).map_err(|_| PduError::BadLength)?;
    if !(HEADER..=MAX_PACKET).contains(&len) {
        return Err(PduError::BadLength);
    }
    Ok(Some(len))
}

/// Decode one whole packet (`bytes.len()` == its header length).
pub fn decode(bytes: &[u8]) -> Result<Packet, PduError> {
    if peek_len(bytes)? != Some(bytes.len()) {
        return Err(PduError::BadLength);
    }
    let ty = u16::from_le_bytes([bytes[0], bytes[1]]);
    let mut r = Rd(&bytes[HEADER..]);
    let p = match ty {
        ty::HANDSHAKE_RESPONSE => Packet::HandshakeResponse {
            error: r.u32()?,
            major: r.u8()?,
            minor: r.u8()?,
            server_version: r.u16()?,
            extended_auth: r.u16()?,
        },
        ty::TUNNEL_RESPONSE => {
            let _server_version = r.u16()?;
            let status = r.u32()?;
            let fields = r.u16()?;
            let _reserved = r.u16()?;
            let tunnel_id = if fields & TR_TUNNEL_ID != 0 { Some(r.u32()?) } else { None };
            let caps = if fields & TR_CAPS != 0 { Some(r.u32()?) } else { None };
            if fields & TR_SOH_REQ != 0 {
                r.take(20)?;
                r.skip_blob()?;
            }
            if fields & TR_CONSENT_MSG != 0 {
                r.skip_blob()?;
            }
            Packet::TunnelResponse { status, tunnel_id, caps }
        }
        ty::TUNNEL_AUTH_RESPONSE => {
            let error = r.u32()?;
            let fields = r.u16()?;
            let _reserved = r.u16()?;
            if fields & 0x01 != 0 {
                let _redir = r.u32()?;
            }
            let idle = if fields & 0x02 != 0 { Some(r.u32()?) } else { None };
            if fields & 0x04 != 0 {
                r.skip_blob()?;
            }
            Packet::TunnelAuthResponse { error, idle_timeout_minutes: idle }
        }
        ty::CHANNEL_RESPONSE => {
            let error = r.u32()?;
            let fields = r.u16()?;
            let _reserved = r.u16()?;
            let channel_id = if fields & CR_CHANNEL_ID != 0 { Some(r.u32()?) } else { None };
            // UDP port / authn cookie (side channel, never requested) are ignored.
            r.0 = &[];
            Packet::ChannelResponse { error, channel_id }
        }
        ty::DATA => {
            let n = usize::from(r.u16()?);
            Packet::Data(r.take(n)?.to_vec())
        }
        ty::KEEPALIVE => Packet::Keepalive,
        ty::SERVICE_MESSAGE => Packet::ServiceMessage { len: r.skip_blob()? },
        ty::REAUTH_MESSAGE => {
            r.take(8)?;
            Packet::Reauth
        }
        ty::CLOSE_CHANNEL => Packet::CloseChannel { status: r.u32()? },
        ty::CLOSE_CHANNEL_RESPONSE => Packet::CloseChannelResponse { status: r.u32()? },
        other => {
            r.0 = &[];
            Packet::Other { ty: other }
        }
    };
    if !r.0.is_empty() {
        return Err(PduError::Truncated);
    }
    Ok(p)
}

fn packet(ty: u16, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(HEADER + body.len()).unwrap_or(u32::MAX);
    let mut v = Vec::with_capacity(HEADER + body.len());
    v.extend_from_slice(&ty.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// UTF-16LE with a NUL terminator.
fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

fn len16(b: &[u8]) -> [u8; 2] {
    u16::try_from(b.len()).unwrap_or(u16::MAX).to_le_bytes()
}

/// `HANDSHAKE_REQUEST` 1.0, no extended authentication.
#[must_use]
pub fn handshake_request() -> Vec<u8> {
    packet(ty::HANDSHAKE_REQUEST, &[1, 0, 0, 0, 0, 0])
}

/// `TUNNEL_CREATE` without a PAA cookie.
#[must_use]
pub fn tunnel_create() -> Vec<u8> {
    let mut b = CAPS_IDLE_TIMEOUT.to_le_bytes().to_vec();
    b.extend_from_slice(&[0, 0, 0, 0]);
    packet(ty::TUNNEL_CREATE, &b)
}

/// The client name sent in `TUNNEL_AUTH`: visible ASCII letters, digits, `-` and `_` only,
/// at most [`MAX_CLIENT_NAME`] characters (`MOORING` when nothing is left).
#[must_use]
pub fn sanitise_client_name(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(MAX_CLIENT_NAME)
        .collect();
    if s.is_empty() {
        "MOORING".to_owned()
    } else {
        s
    }
}

/// `TUNNEL_AUTH` with the sanitised client name.
#[must_use]
pub fn tunnel_auth(client_name: &str) -> Vec<u8> {
    let name = utf16z(&sanitise_client_name(client_name));
    let mut b = 0u16.to_le_bytes().to_vec();
    b.extend_from_slice(&len16(&name));
    b.extend_from_slice(&name);
    packet(ty::TUNNEL_AUTH, &b)
}

/// `CHANNEL_CREATE` to `host:port` over TCP. `None` when the host is empty, too long or holds
/// a control character.
#[must_use]
pub fn channel_create(host: &str, port: u16) -> Option<Vec<u8>> {
    if host.is_empty() || host.len() > MAX_RESOURCE || host.chars().any(char::is_control) {
        return None;
    }
    let res = utf16z(host);
    let mut b = vec![1, 0];
    b.extend_from_slice(&port.to_le_bytes());
    b.extend_from_slice(&PROTOCOL_TCP.to_le_bytes());
    b.extend_from_slice(&len16(&res));
    b.extend_from_slice(&res);
    Some(packet(ty::CHANNEL_CREATE, &b))
}

/// `DATA` with `data` (≤ 65 535 bytes; callers chunk at [`MAX_DATA`]).
#[must_use]
pub fn data(data: &[u8]) -> Vec<u8> {
    let n = data.len().min(usize::from(u16::MAX));
    let mut b = len16(&data[..n]).to_vec();
    b.extend_from_slice(&data[..n]);
    packet(ty::DATA, &b)
}

/// `KEEPALIVE`.
#[must_use]
pub fn keepalive() -> Vec<u8> {
    packet(ty::KEEPALIVE, &[])
}

/// `CLOSE_CHANNEL` (status 0) or its response.
#[must_use]
pub fn close_channel(response: bool) -> Vec<u8> {
    let t = if response { ty::CLOSE_CHANNEL_RESPONSE } else { ty::CLOSE_CHANNEL };
    packet(t, &0u32.to_le_bytes())
}

/// A gateway-side encoder of the response packets, for the test gateway and the fuzz seeds.
pub mod server {
    use super::{len16, packet, ty, utf16z};

    /// `HANDSHAKE_RESPONSE`.
    #[must_use]
    pub fn handshake_response(error: u32, major: u8) -> Vec<u8> {
        let mut b = error.to_le_bytes().to_vec();
        b.extend_from_slice(&[major, 0, 0, 0, 0, 0]);
        packet(ty::HANDSHAKE_RESPONSE, &b)
    }

    /// `TUNNEL_RESPONSE` with a tunnel id and caps.
    #[must_use]
    pub fn tunnel_response(status: u32, tunnel_id: u32) -> Vec<u8> {
        let mut b = 0u16.to_le_bytes().to_vec();
        b.extend_from_slice(&status.to_le_bytes());
        b.extend_from_slice(&0x03u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&tunnel_id.to_le_bytes());
        b.extend_from_slice(&super::CAPS_IDLE_TIMEOUT.to_le_bytes());
        packet(ty::TUNNEL_RESPONSE, &b)
    }

    /// `TUNNEL_AUTH_RESPONSE` with an idle timeout.
    #[must_use]
    pub fn tunnel_auth_response(error: u32) -> Vec<u8> {
        let mut b = error.to_le_bytes().to_vec();
        b.extend_from_slice(&0x02u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&30u32.to_le_bytes());
        packet(ty::TUNNEL_AUTH_RESPONSE, &b)
    }

    /// `CHANNEL_RESPONSE` with a channel id.
    #[must_use]
    pub fn channel_response(error: u32, channel_id: u32) -> Vec<u8> {
        let mut b = error.to_le_bytes().to_vec();
        b.extend_from_slice(&0x01u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&channel_id.to_le_bytes());
        packet(ty::CHANNEL_RESPONSE, &b)
    }

    /// `SERVICE_MESSAGE`.
    #[must_use]
    pub fn service_message(text: &str) -> Vec<u8> {
        let t = utf16z(text);
        let mut b = len16(&t).to_vec();
        b.extend_from_slice(&t);
        packet(ty::SERVICE_MESSAGE, &b)
    }

    /// A packet of any type with a raw body (hostile tests).
    #[must_use]
    pub fn raw(t: u16, body: &[u8]) -> Vec<u8> {
        packet(t, body)
    }
}

/// What the test gateway parses from the client: `(type, body)` of one whole packet.
pub fn split(bytes: &[u8]) -> Result<(u16, &[u8]), PduError> {
    if peek_len(bytes)? != Some(bytes.len()) {
        return Err(PduError::BadLength);
    }
    Ok((u16::from_le_bytes([bytes[0], bytes[1]]), &bytes[HEADER..]))
}

/// Target `(host, port)` of a client `CHANNEL_CREATE` body (test gateway).
pub fn parse_channel_create(body: &[u8]) -> Result<(String, u16), PduError> {
    let mut r = Rd(body);
    if r.u8()? != 1 {
        return Err(PduError::Truncated);
    }
    let _alt = r.u8()?;
    let port = r.u16()?;
    if r.u16()? != PROTOCOL_TCP {
        return Err(PduError::Truncated);
    }
    let n = usize::from(r.u16()?);
    let raw = r.take(n)?;
    if !r.0.is_empty() || n % 2 != 0 || n > 2 * (MAX_RESOURCE + 1) {
        return Err(PduError::Truncated);
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let units = units.strip_suffix(&[0]).ok_or(PduError::Truncated)?;
    let host = String::from_utf16(units).map_err(|_| PduError::Truncated)?;
    Ok((host, port))
}
