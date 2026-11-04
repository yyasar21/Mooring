//! Channel framing of the Kubernetes WebSocket sub-protocols (hostile input).
//!
//! `v4.channel.k8s.io` / `v5.channel.k8s.io` (exec): every binary message starts with a
//! channel byte — 0 stdin, 1 stdout, 2 stderr, 3 error (a JSON `metav1.Status`), 4 resize
//! (JSON `{"Width","Height"}`); v5 adds 255 = close (`[255, channel]`).
//!
//! Port-forward (`v4.channel.k8s.io`, one port per WebSocket): channel `0` data, `1` error.
//! The first message the server sends on each channel is the port number (2 bytes, little
//! endian); everything after that is payload.

use serde::Deserialize;

use crate::browse::clean;

/// Exec channel numbers.
pub mod channel {
    /// stdin (client → server).
    pub const STDIN: u8 = 0;
    /// stdout.
    pub const STDOUT: u8 = 1;
    /// stderr.
    pub const STDERR: u8 = 2;
    /// Status / error (JSON).
    pub const ERROR: u8 = 3;
    /// Terminal resize (client → server).
    pub const RESIZE: u8 = 4;
    /// v5 stream close.
    pub const CLOSE: u8 = 255;
}

/// Longest status JSON parsed (the WebSocket cap is 1 MiB; a real status is < 1 KiB).
pub const MAX_STATUS: usize = 64 * 1024;

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Empty message (no channel byte).
    #[error("empty frame")]
    Empty,
    /// A channel the server may not send on.
    #[error("unexpected channel")]
    Channel,
    /// Malformed status / close / port header.
    #[error("malformed frame")]
    Malformed,
}

/// How an exec process ended (channel 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecStatus {
    /// `status: Success`.
    Success,
    /// `NonZeroExitCode` with the exit code.
    Exit(i32),
    /// Any other failure; the reason is sanitised and capped.
    Failure(String),
}

/// One decoded server → client exec message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecFrame<'a> {
    /// stdout bytes (may be empty).
    Stdout(&'a [u8]),
    /// stderr bytes (may be empty).
    Stderr(&'a [u8]),
    /// The process status.
    Status(ExecStatus),
    /// v5: the server closed one of its streams.
    Close(u8),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Cause {
    reason: String,
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Details {
    causes: Vec<Cause>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(clippy::struct_field_names)] // mirrors metav1.Status
struct Status {
    status: String,
    reason: String,
    message: String,
    details: Details,
}

/// Parse a channel-3 status document.
pub fn parse_status(json: &[u8]) -> Result<ExecStatus, FrameError> {
    if json.len() > MAX_STATUS {
        return Err(FrameError::Malformed);
    }
    let s: Status = serde_json::from_slice(json).map_err(|_| FrameError::Malformed)?;
    if s.status == "Success" {
        return Ok(ExecStatus::Success);
    }
    if s.reason == "NonZeroExitCode" {
        let code = s
            .details
            .causes
            .iter()
            .find(|c| c.reason == "ExitCode")
            .and_then(|c| c.message.trim().parse::<i32>().ok());
        if let Some(code) = code {
            return Ok(ExecStatus::Exit(code));
        }
    }
    let text = if s.message.is_empty() { &s.reason } else { &s.message };
    Ok(ExecStatus::Failure(clean(text, 256)))
}

/// Decode one server → client exec message.
pub fn decode_exec(msg: &[u8]) -> Result<ExecFrame<'_>, FrameError> {
    let (&ch, rest) = msg.split_first().ok_or(FrameError::Empty)?;
    match ch {
        channel::STDOUT => Ok(ExecFrame::Stdout(rest)),
        channel::STDERR => Ok(ExecFrame::Stderr(rest)),
        channel::ERROR => parse_status(rest).map(ExecFrame::Status),
        channel::CLOSE => match rest {
            [c] => Ok(ExecFrame::Close(*c)),
            _ => Err(FrameError::Malformed),
        },
        _ => Err(FrameError::Channel),
    }
}

/// A channel-prefixed client → server message.
pub fn encode(ch: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 1);
    v.push(ch);
    v.extend_from_slice(data);
    v
}

/// The resize message for `cols` × `rows`.
pub fn encode_resize(cols: u16, rows: u16) -> Vec<u8> {
    encode(channel::RESIZE, format!("{{\"Width\":{cols},\"Height\":{rows}}}").as_bytes())
}

/// One decoded port-forward message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfEvent<'a> {
    /// A port header (consumed).
    Header,
    /// Payload for the local connection.
    Data(&'a [u8]),
    /// The kubelet reported an error (sanitised, capped).
    Error(String),
}

/// Stateful decoder for one port-forward WebSocket.
#[derive(Debug, Clone)]
pub struct PfDecoder {
    port: u16,
    data_header: bool,
    error_header: bool,
}

impl PfDecoder {
    /// A decoder expecting headers for `port`.
    pub fn new(port: u16) -> Self {
        Self { port, data_header: false, error_header: false }
    }

    /// Feed one binary message.
    pub fn feed<'a>(&mut self, msg: &'a [u8]) -> Result<PfEvent<'a>, FrameError> {
        let (&ch, rest) = msg.split_first().ok_or(FrameError::Empty)?;
        let seen = match ch {
            0 => &mut self.data_header,
            1 => &mut self.error_header,
            _ => return Err(FrameError::Channel),
        };
        if !*seen {
            let [lo, hi, tail @ ..] = rest else { return Err(FrameError::Malformed) };
            if u16::from_le_bytes([*lo, *hi]) != self.port {
                return Err(FrameError::Malformed);
            }
            *seen = true;
            // Some servers coalesce the header with the first payload.
            if tail.is_empty() {
                return Ok(PfEvent::Header);
            }
            return Ok(if ch == 0 {
                PfEvent::Data(tail)
            } else {
                PfEvent::Error(clean(&String::from_utf8_lossy(tail), 256))
            });
        }
        Ok(if ch == 0 {
            PfEvent::Data(rest)
        } else {
            PfEvent::Error(clean(&String::from_utf8_lossy(rest), 256))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_frames() {
        assert_eq!(decode_exec(b"\x01hi"), Ok(ExecFrame::Stdout(b"hi")));
        assert_eq!(decode_exec(b"\x02"), Ok(ExecFrame::Stderr(b"")));
        assert_eq!(decode_exec(b"\xff\x01"), Ok(ExecFrame::Close(1)));
        assert_eq!(decode_exec(b"\xff"), Err(FrameError::Malformed));
        assert_eq!(decode_exec(b""), Err(FrameError::Empty));
        assert_eq!(decode_exec(b"\x00x"), Err(FrameError::Channel));
        assert_eq!(decode_exec(b"\x04{}"), Err(FrameError::Channel));
        assert_eq!(
            decode_exec(br#"{"status":"Success"}"#.as_slice()).ok(),
            None,
            "'{{' is not a channel"
        );
    }

    #[test]
    fn statuses() {
        assert_eq!(parse_status(br#"{"metadata":{},"status":"Success"}"#), Ok(ExecStatus::Success));
        let exit = br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"42"}]}}"#;
        assert_eq!(parse_status(exit), Ok(ExecStatus::Exit(42)));
        let other = "{\"status\":\"Failure\",\"message\":\"boom\\u001b[31m\\u202e\"}";
        assert_eq!(parse_status(other.as_bytes()), Ok(ExecStatus::Failure("boom[31m".into())));
        assert_eq!(parse_status(b"not json"), Err(FrameError::Malformed));
        assert_eq!(parse_status(&vec![b' '; MAX_STATUS + 1]), Err(FrameError::Malformed));
    }

    #[test]
    fn resize_json() {
        assert_eq!(encode_resize(80, 24), b"\x04{\"Width\":80,\"Height\":24}".to_vec());
    }

    #[test]
    fn portforward_headers_then_data() {
        let mut d = PfDecoder::new(8080);
        let hdr = 8080u16.to_le_bytes();
        assert_eq!(d.feed(&[0, hdr[0], hdr[1]]), Ok(PfEvent::Header));
        assert_eq!(d.feed(&[1, hdr[0], hdr[1]]), Ok(PfEvent::Header));
        assert_eq!(d.feed(b"\x00abc"), Ok(PfEvent::Data(b"abc")));
        assert_eq!(d.feed(b"\x01refused\x07"), Ok(PfEvent::Error("refused".into())));
        assert_eq!(d.feed(b"\x02"), Err(FrameError::Channel));
        let mut d = PfDecoder::new(80);
        assert_eq!(d.feed(&[0, 81, 0]), Err(FrameError::Malformed), "wrong port");
        assert_eq!(d.feed(&[0, 80]), Err(FrameError::Malformed), "short header");
        assert_eq!(d.feed(&[0, 80, 0, b'x']), Ok(PfEvent::Data(b"x")), "coalesced");
    }
}
