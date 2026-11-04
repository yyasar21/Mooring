//! Pod logs (ADR-0014 §5): not a terminal. The request carries `limitBytes = maxLogBytes`
//! and `tailLines ≤ 10 000`; the reader stops at the byte cap itself as well and ends with
//! `truncated: true` (`kube.stream_limit`). Every line is sanitised before it leaves Rust:
//! ESC sequences (CSI, OSC, DCS/SOS/PM/APC strings), C0/C1 controls except `\t` `\n`, DEL
//! and bidi controls are removed; invalid UTF-8 becomes U+FFFD. At most 8 streams per cluster.

use std::fmt::Write as _;

use http::Request;
use http_body_util::BodyExt as _;
use kube::client::Body;
use tokio::sync::OwnedSemaphorePermit;

use crate::audit::KubeAudit;
use crate::browse::{check_container, check_ns, check_pod, is_bidi};
use crate::client::KubeClient;
use crate::error::KubeError;
use crate::guard::MAX_TAIL_LINES;
use crate::query::MAX_SECONDS;

/// Largest chunk handed to the UI.
pub const LOG_CHUNK: usize = 64 * 1024;
/// A line longer than this is flushed in pieces.
pub const MAX_LINE: usize = 16 * 1024;
/// `LogChunk.end.reason` when the byte cap stopped the stream.
pub const STREAM_LIMIT: &str = "kube.stream_limit";

/// What to stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogParams {
    /// Container (`None` = the pod's only / default container).
    pub container: Option<String>,
    /// Keep the stream open.
    pub follow: bool,
    /// `tailLines` (`None` = the connection's `logTailLines`); clamped to 10 000.
    pub tail_lines: Option<u32>,
    /// `sinceSeconds` (1 s ..= 1 year).
    pub since_seconds: Option<u64>,
    /// Prefix RFC 3339 timestamps.
    pub timestamps: bool,
}

/// One piece of a log stream (IPC `LogChunk`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogChunk {
    /// Sanitised UTF-8 text (complete lines, except a final partial line or an over-long one).
    Data(Vec<u8>),
    /// The stream ended. `truncated` = the byte cap stopped it (`reason = kube.stream_limit`).
    End {
        /// Stopped at the cap.
        truncated: bool,
        /// Machine reason, if any.
        reason: Option<&'static str>,
    },
}

/// Streaming line sanitiser.
#[derive(Debug, Default)]
pub struct Sanitizer {
    line: Vec<u8>,
}

impl Sanitizer {
    /// Feed raw bytes; returns sanitised output for every completed (or over-long) line.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in data {
            self.line.push(b);
            if b == b'\n' || self.line.len() >= MAX_LINE {
                out.extend_from_slice(sanitize_line(&self.line).as_bytes());
                self.line.clear();
            }
        }
        out
    }

    /// Flush the last partial line.
    pub fn finish(&mut self) -> Vec<u8> {
        let out = sanitize_line(&self.line).into_bytes();
        self.line.clear();
        out
    }
}

/// Sanitise one line (or any text): see the module docs.
pub fn sanitize_line(raw: &[u8]) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum St {
        Text,
        Esc,
        Csi,
        /// OSC / DCS / SOS / PM / APC string: until BEL or ST.
        Str,
        StrEsc,
    }
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len());
    let mut st = St::Text;
    for c in text.chars() {
        st = match st {
            St::Text => match c {
                '\u{1b}' => St::Esc,
                '\u{9b}' => St::Csi,
                '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => St::Str,
                '\n' | '\t' => {
                    out.push(c);
                    St::Text
                }
                c if c.is_control() || is_bidi(c) => St::Text,
                c => {
                    out.push(c);
                    St::Text
                }
            },
            St::Esc => match c {
                '[' => St::Csi,
                ']' | 'P' | 'X' | '^' | '_' => St::Str,
                '\n' => {
                    out.push('\n');
                    St::Text
                }
                _ => St::Text,
            },
            St::Csi => match c {
                '\u{40}'..='\u{7e}' => St::Text,
                '\n' => {
                    out.push('\n');
                    St::Text
                }
                _ => St::Csi,
            },
            St::Str => match c {
                '\u{07}' | '\u{9c}' => St::Text,
                '\u{1b}' => St::StrEsc,
                '\n' => {
                    out.push('\n');
                    St::Text
                }
                _ => St::Str,
            },
            St::StrEsc => match c {
                '\\' => St::Text,
                '\n' => {
                    out.push('\n');
                    St::Text
                }
                _ => St::Str,
            },
        };
    }
    out
}

/// A bounded, sanitised log stream. Dropping it closes the connection and frees the slot.
#[derive(Debug)]
pub struct LogStream {
    body: Body,
    sanitizer: Sanitizer,
    remaining: u64,
    pending: Vec<u8>,
    end: Option<LogChunk>,
    finished: bool,
    _slot: OwnedSemaphorePermit,
}

impl LogStream {
    /// The next chunk; `End` once, then `None`.
    pub async fn next(&mut self) -> Result<Option<LogChunk>, KubeError> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(LOG_CHUNK);
                return Ok(Some(LogChunk::Data(self.pending.drain(..n).collect())));
            }
            if self.finished {
                return Ok(self.end.take());
            }
            match self.body.frame().await {
                None => self.finish(false),
                Some(Err(e)) => {
                    // The transport cap (CappedBody) also means "stopped at the limit".
                    match KubeError::from_kube(e) {
                        KubeError::Http(mooring_http::HttpError::BodyTooLarge { .. }) => {
                            self.finish(true);
                        }
                        other => return Err(other),
                    }
                }
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else { continue };
                    let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    if len > self.remaining {
                        let keep = usize::try_from(self.remaining).unwrap_or(0);
                        let out = self.sanitizer.push(&data[..keep]);
                        self.pending.extend_from_slice(&out);
                        self.finish(true);
                    } else {
                        self.remaining -= len;
                        let out = self.sanitizer.push(&data);
                        self.pending.extend_from_slice(&out);
                    }
                }
            }
        }
    }

    fn finish(&mut self, truncated: bool) {
        let tail = self.sanitizer.finish();
        self.pending.extend_from_slice(&tail);
        self.finished = true;
        self.end = Some(LogChunk::End { truncated, reason: truncated.then_some(STREAM_LIMIT) });
    }
}

/// The request path for `params` (validated, clamped).
pub(crate) fn log_path(
    ns: &str,
    pod: &str,
    params: &LogParams,
    default_tail: u32,
    max_bytes: u64,
) -> Result<String, KubeError> {
    check_ns(ns)?;
    check_pod(pod)?;
    check_container(params.container.as_deref())?;
    let tail = u64::from(params.tail_lines.unwrap_or(default_tail)).min(MAX_TAIL_LINES);
    let mut p =
        format!("/api/v1/namespaces/{ns}/pods/{pod}/log?limitBytes={max_bytes}&tailLines={tail}");
    if let Some(c) = &params.container {
        p.push_str("&container=");
        p.push_str(c);
    }
    if params.follow {
        p.push_str("&follow=true");
    }
    if params.timestamps {
        p.push_str("&timestamps=true");
    }
    if let Some(s) = params.since_seconds {
        if !(1..=MAX_SECONDS).contains(&s) {
            return Err(KubeError::Invalid("sinceSeconds out of range"));
        }
        let _ = write!(p, "&sinceSeconds={s}");
    }
    Ok(p)
}

impl KubeClient {
    /// Open a log stream (at most 8 per cluster: `kube.stream_limit`).
    pub async fn logs(
        &self,
        ns: &str,
        pod: &str,
        params: LogParams,
    ) -> Result<LogStream, KubeError> {
        let max = self.limits.max_log_bytes;
        let path = log_path(ns, pod, &params, self.limits.log_tail_lines, max)?;
        let slot =
            self.log_slots.clone().try_acquire_owned().map_err(|_| KubeError::StreamLimit)?;
        let req = Request::get(path.as_str())
            .body(Vec::new())
            .map_err(|_| KubeError::Invalid("request path"))?;
        let resp = self.send(req, true).await?;
        self.audit.push(KubeAudit::LogsOpened {
            namespace: ns.to_owned(),
            pod: pod.to_owned(),
            container: params.container.clone(),
            follow: params.follow,
        });
        Ok(LogStream {
            body: resp.into_body(),
            sanitizer: Sanitizer::default(),
            remaining: max,
            pending: Vec::new(),
            end: None,
            finished: false,
            _slot: slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sequences_and_controls() {
        let cases: &[(&[u8], &str)] = &[
            (b"plain\ttext\n", "plain\ttext\n"),
            (b"\x1b[31mred\x1b[0m\n", "red\n"),
            (b"\x1b]0;title\x07after", "after"),
            (b"\x1b]8;;http://x.example.test\x1b\\link\x1b]8;;\x1b\\", "link"),
            (b"a\x00b\x08c\rd\x7f", "abcd"),
            ("x\u{202e}y\u{2066}z".as_bytes(), "xyz"),
            ("c1\u{9b}31mcsi".as_bytes(), "c1csi"),
            (b"\xff\xfe ok", "\u{fffd}\u{fffd} ok"),
            (b"\x1bPdcs\x1b\\end", "end"),
            (b"\x1b[12;3\nnext", "\nnext"),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitize_line(raw), *want, "{raw:?}");
        }
    }

    #[test]
    fn sanitizer_handles_split_input_and_long_lines() {
        let mut s = Sanitizer::default();
        let mut out = s.push(b"\x1b[3");
        out.extend(s.push(b"1mhi\n\xe2\x82"));
        out.extend(s.push(b"\xac\n"));
        out.extend(s.finish());
        assert_eq!(String::from_utf8(out).expect("utf8"), "hi\n\u{20ac}\n");
        let long = vec![b'a'; MAX_LINE * 2 + 5];
        let mut out = s.push(&long);
        out.extend(s.finish());
        assert_eq!(out.len(), long.len());
    }

    #[test]
    fn log_path_clamps_and_validates() {
        let p = LogParams { tail_lines: Some(100_000), follow: true, ..LogParams::default() };
        let path = log_path("ns", "pod-1", &p, 500, 1024).expect("path");
        assert_eq!(
            path,
            "/api/v1/namespaces/ns/pods/pod-1/log?limitBytes=1024&tailLines=10000&follow=true"
        );
        let bad = LogParams { container: Some("Bad".into()), ..LogParams::default() };
        assert!(log_path("ns", "p", &bad, 1, 1).is_err());
        assert!(log_path("NS", "p", &LogParams::default(), 1, 1).is_err());
        assert!(log_path("ns", "p/../x", &LogParams::default(), 1, 1).is_err());
        let since = LogParams { since_seconds: Some(0), ..LogParams::default() };
        assert!(log_path("ns", "p", &since, 1, 1).is_err());
    }
}
