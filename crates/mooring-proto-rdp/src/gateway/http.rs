//! The HTTP/1.1 side of the RD Gateway WebSocket upgrade: our request, a bounded parser of
//! the gateway's response head and its `WWW-Authenticate` challenges, and RFC 4648 base64
//! (NTLM tokens, Basic, `Sec-WebSocket-Key`). Hostile input: the head is capped at
//! [`MAX_HEAD`] bytes and [`MAX_HEADERS`] lines, bodies we drain at [`MAX_BODY`]. Fuzz entry:
//! [`super::fuzz_rdg_http_response`].

use zeroize::Zeroizing;

/// Largest response head (status line + headers).
pub const MAX_HEAD: usize = 16 * 1024;
/// Most header lines.
pub const MAX_HEADERS: usize = 64;
/// Largest response body drained on a `401` (kept-alive connection for NTLM).
pub const MAX_BODY: usize = 64 * 1024;
/// Largest decoded NTLM challenge.
pub const MAX_TOKEN: usize = 8 * 1024;
/// The MS-TSGU WebSocket endpoint.
pub const PATH: &str = "/remoteDesktopGateway/";

/// Why a response head was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    /// More than [`MAX_HEAD`] bytes or [`MAX_HEADERS`] lines.
    TooLarge,
    /// Not `HTTP/1.x NNN …`, a header without `:`, or non-ASCII control bytes.
    Malformed,
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Status code.
    pub status: u16,
    /// `(lower-case name, trimmed value)` in order.
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// Every value of `name` (lower case).
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers.iter().filter(move |(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// Whether a comma list header (`Connection`, `Upgrade`) holds `token`.
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// `Content-Length` (`Ok(0)` when absent). Chunked bodies and bad lengths are refused.
    pub fn body_len(&self) -> Result<usize, HeadError> {
        if self.get("transfer-encoding").is_some() {
            return Err(HeadError::Malformed);
        }
        match self.get("content-length") {
            None => Ok(0),
            Some(v) => {
                v.parse::<usize>().ok().filter(|n| *n <= MAX_BODY).ok_or(HeadError::TooLarge)
            }
        }
    }
}

/// End of the head (`\r\n\r\n`) in `buf`, if present; `Err` once `buf` is over the cap
/// without one.
pub fn head_end(buf: &[u8]) -> Result<Option<usize>, HeadError> {
    match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) if i + 4 <= MAX_HEAD => Ok(Some(i + 4)),
        Some(_) => Err(HeadError::TooLarge),
        None if buf.len() >= MAX_HEAD => Err(HeadError::TooLarge),
        None => Ok(None),
    }
}

/// Parse a complete head (including the blank line).
pub fn parse_head(bytes: &[u8]) -> Result<Head, HeadError> {
    if bytes.len() > MAX_HEAD {
        return Err(HeadError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| HeadError::Malformed)?;
    let text = text.strip_suffix("\r\n\r\n").ok_or(HeadError::Malformed)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(HeadError::Malformed)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !(version == "HTTP/1.1" || version == "HTTP/1.0") || code.len() != 3 {
        return Err(HeadError::Malformed);
    }
    let status: u16 = code.parse().map_err(|_| HeadError::Malformed)?;
    if !(100..=599).contains(&status) {
        return Err(HeadError::Malformed);
    }
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(HeadError::TooLarge);
        }
        let (name, value) = line.split_once(':').ok_or(HeadError::Malformed)?;
        let bad = |s: &str| s.bytes().any(|b| b.is_ascii_control() && b != b'\t');
        if name.is_empty() || name.bytes().any(|b| !b.is_ascii_graphic()) || bad(value) {
            return Err(HeadError::Malformed);
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(Head { status, headers })
}

/// What a `401` offers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Challenges {
    /// `NTLM` offered (without a token: the start of the exchange).
    pub ntlm: bool,
    /// The NTLM `CHALLENGE_MESSAGE`, decoded.
    pub ntlm_token: Option<Vec<u8>>,
    /// `Negotiate` offered (Kerberos/SPNEGO: not supported, ADR-0011).
    pub negotiate: bool,
    /// `Basic` offered.
    pub basic: bool,
}

/// Parse every `WWW-Authenticate` value. Unknown schemes are ignored; a malformed NTLM token
/// is refused (`None`).
pub fn challenges(head: &Head) -> Option<Challenges> {
    let mut c = Challenges::default();
    for value in head.all("www-authenticate") {
        for piece in split_outside_quotes(value) {
            let piece = piece.trim();
            let (scheme, rest) = piece.split_once(' ').unwrap_or((piece, ""));
            if rest.is_empty() && scheme.contains('=') {
                continue; // an auth-param of the previous challenge
            }
            if scheme.eq_ignore_ascii_case("ntlm") {
                c.ntlm = true;
                let token = rest.trim();
                if !token.is_empty() {
                    let raw = decode_base64(token, MAX_TOKEN)?;
                    c.ntlm_token = Some(raw);
                }
            } else if scheme.eq_ignore_ascii_case("negotiate") {
                c.negotiate = true;
            } else if scheme.eq_ignore_ascii_case("basic") {
                c.basic = true;
            }
        }
    }
    Some(c)
}

fn split_outside_quotes(v: &str) -> Vec<&str> {
    let (mut out, mut start, mut quoted) = (Vec::new(), 0, false);
    for (i, ch) in v.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&v[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&v[start..]);
    out
}

/// The upgrade request. `authorization` is the full header value (`NTLM …` / `Basic …`).
pub fn request(
    host: &str,
    port: u16,
    ws_key: &str,
    connection_id: &str,
    authorization: Option<&str>,
) -> Zeroizing<Vec<u8>> {
    let host_header =
        if port == 443 { host.to_owned() } else { crate::gateway::host_port(host, port) };
    let mut s = Zeroizing::new(format!(
        "GET {PATH} HTTP/1.1\r\nHost: {host_header}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {ws_key}\r\nCache-Control: no-cache\r\n\
         Pragma: no-cache\r\nUser-Agent: MS-RDGateway/1.0\r\nRDG-Connection-Id: {connection_id}\r\n"
    ));
    if let Some(a) = authorization {
        s.push_str("Authorization: ");
        s.push_str(a);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    Zeroizing::new(s.as_bytes().to_vec())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// RFC 4648 base64 with padding.
pub fn encode_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(B64[usize::try_from((n >> shift) & 63).unwrap_or(0)]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Strict RFC 4648 base64 (padding required, no whitespace), at most `max` decoded bytes.
pub fn decode_base64(s: &str, max: usize) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) || b.len() / 4 * 3 > max + 2 {
        return None;
    }
    let val = |c: u8| B64.iter().position(|x| *x == c).and_then(|p| u32::try_from(p).ok());
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let quads = b.len() / 4;
    for (qi, q) in b.chunks_exact(4).enumerate() {
        let pad = q.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && qi + 1 != quads) || q[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in q.iter().enumerate() {
            let v = if i < 4 - pad { val(*c)? } else { 0 };
            n |= v << (18 - 6 * u32::try_from(i).ok()?);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    (out.len() <= max).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(plain.as_bytes()), enc);
            if !enc.is_empty() {
                assert_eq!(decode_base64(enc, 64).expect("dec"), plain.as_bytes());
            }
        }
        for bad in ["Zg=", "Z===", "Zg==Zg==", "Zm9v\r\n", "Zm 9", "@@@@"] {
            assert!(decode_base64(bad, 64).is_none(), "{bad:?}");
        }
        assert!(decode_base64("Zm9vYmFy", 5).is_none(), "cap");
    }

    #[test]
    fn head_parse_and_challenges() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n\
WWW-Authenticate: NTLM Zm9v\r\nWWW-Authenticate: Basic realm=\"a,b\", charset=\"UTF-8\"\r\n\
Content-Length: 3\r\n\r\n";
        assert_eq!(head_end(raw).expect("ok"), Some(raw.len()));
        let h = parse_head(raw).expect("head");
        assert_eq!(h.status, 401);
        assert_eq!(h.body_len().expect("len"), 3);
        let c = challenges(&h).expect("c");
        assert!(c.ntlm && c.negotiate && c.basic);
        assert_eq!(c.ntlm_token.as_deref(), Some(&b"foo"[..]));
        let bad_token =
            parse_head(b"HTTP/1.1 401 x\r\nWWW-Authenticate: NTLM ***\r\n\r\n").expect("h");
        assert!(challenges(&bad_token).is_none());
    }

    #[test]
    #[allow(clippy::format_collect)]
    fn hostile_heads_are_refused() {
        let many: String = (0..=MAX_HEADERS).map(|i| format!("X-{i}: v\r\n")).collect();
        let many = format!("HTTP/1.1 200 OK\r\n{many}\r\n");
        assert_eq!(parse_head(many.as_bytes()), Err(HeadError::TooLarge));
        for bad in [
            &b"HTTP/2 101 x\r\n\r\n"[..],
            b"HTTP/1.1 1011 x\r\n\r\n",
            b"HTTP/1.1 101 x\r\nNoColon\r\n\r\n",
            b"HTTP/1.1 101 x\r\nA: b\x01\r\n\r\n",
            b"HTTP/1.1 101 x\r\n",
        ] {
            assert_eq!(parse_head(bad), Err(HeadError::Malformed), "{bad:?}");
        }
        assert_eq!(head_end(&vec![b'a'; MAX_HEAD]), Err(HeadError::TooLarge));
        let chunked =
            parse_head(b"HTTP/1.1 401 x\r\nTransfer-Encoding: chunked\r\n\r\n").expect("h");
        assert!(chunked.body_len().is_err());
        let huge = parse_head(b"HTTP/1.1 401 x\r\nContent-Length: 99999999\r\n\r\n").expect("h");
        assert_eq!(huge.body_len(), Err(HeadError::TooLarge));
    }

    #[test]
    fn request_carries_the_rdg_headers() {
        let r = request("gw.example.test", 443, "a2V5", "{0}", Some("NTLM Zm9v"));
        let t = std::str::from_utf8(&r).expect("utf8");
        assert!(t.starts_with("GET /remoteDesktopGateway/ HTTP/1.1\r\nHost: gw.example.test\r\n"));
        assert!(t.contains("Upgrade: websocket\r\n") && t.contains("RDG-Connection-Id: {0}\r\n"));
        assert!(t.ends_with("Authorization: NTLM Zm9v\r\n\r\n"));
        let r = request("gw.example.test", 8443, "a2V5", "{0}", None);
        assert!(std::str::from_utf8(&r).expect("utf8").contains("Host: gw.example.test:8443\r\n"));
    }
}
