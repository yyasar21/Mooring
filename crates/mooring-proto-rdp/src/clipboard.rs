//! Text-only clipboard over cliprdr (ADR-0011 §Clipboard).
//!
//! Only `CF_UNICODETEXT` (13) and `CF_TEXT` (1) are ever requested or offered, at most
//! [`MAX_CLIPBOARD_TEXT`] bytes after UTF-8 conversion; file lists, HTML and images are
//! refused (we advertise no file-clip capability and never request those formats). The
//! `IronRDP` backend callbacks run synchronously inside `ActiveStage::process`, so the backend
//! only queues [`ClipEvent`]s; the active loop drains them, applies the [`ClipboardPolicy`],
//! touches the OS clipboard through `LocalClipboard` and audits through [`ClipAudit`].
//! The text never crosses IPC.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use mooring_core::audit::{ClipboardDirection, SessionAudit};
use mooring_core::options::ClipboardPolicy;

/// Largest clipboard text, in UTF-8 bytes (ADR-0011: 1 MiB).
pub const MAX_CLIPBOARD_TEXT: usize = 1024 * 1024;
/// Largest raw format-data payload we decode (UTF-16 of 1 MiB of UTF-8 text plus NUL).
pub const MAX_CLIPBOARD_WIRE: usize = 4 * MAX_CLIPBOARD_TEXT + 2;
/// `CF_TEXT`.
pub const CF_TEXT: u32 = 1;
/// `CF_UNICODETEXT`.
pub const CF_UNICODETEXT: u32 = 13;
/// Audit coalescing window per direction.
pub const AUDIT_WINDOW: Duration = Duration::from_secs(1);

/// What the cliprdr backend saw, for the active loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClipEvent {
    /// The server wants our format list (initialization).
    RequestFormatList,
    /// The remote copied something; the text format we would fetch, if any.
    RemoteCopy(Option<u32>),
    /// The remote asks for our data in this format.
    DataRequest(u32),
    /// Answer to our paste request (`None` = error response).
    DataResponse(Option<Vec<u8>>),
}

/// The text format we fetch from a remote format list: Unicode first, then ANSI.
pub fn pick_text_format(formats: &[u32]) -> Option<u32> {
    if formats.contains(&CF_UNICODETEXT) {
        Some(CF_UNICODETEXT)
    } else if formats.contains(&CF_TEXT) {
        Some(CF_TEXT)
    } else {
        None
    }
}

/// Decode a format-data payload into text. `None` for other formats, oversized payloads or
/// text over 1 MiB after conversion. Stops at the first NUL; invalid UTF-16 is replaced,
/// `CF_TEXT` is read as UTF-8 when valid and as Latin-1 otherwise. Hostile input: fuzzed via
/// [`crate::fuzz::cliprdr_text`].
pub fn decode_text(format: u32, data: &[u8]) -> Option<String> {
    if data.len() > MAX_CLIPBOARD_WIRE {
        return None;
    }
    let text = match format {
        CF_UNICODETEXT => {
            let units = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0);
            char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect::<String>()
        }
        CF_TEXT => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            let bytes = &data[..end];
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_owned(),
                Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
            }
        }
        _ => return None,
    };
    (text.len() <= MAX_CLIPBOARD_TEXT).then_some(text)
}

/// Encode local text for a format request; `None` when the format is not text or the text is
/// over the cap.
pub(crate) fn encode_text(format: u32, text: &str) -> Option<FormatDataResponse<'static>> {
    if text.len() > MAX_CLIPBOARD_TEXT {
        return None;
    }
    match format {
        CF_UNICODETEXT => Some(FormatDataResponse::new_unicode_string(text)),
        CF_TEXT => Some(FormatDataResponse::new_string(text)),
        _ => None,
    }
}

/// The formats we announce for local text.
pub(crate) fn text_formats() -> Vec<ClipboardFormat> {
    vec![
        ClipboardFormat::new(ClipboardFormatId::new(CF_UNICODETEXT)),
        ClipboardFormat::new(ClipboardFormatId::new(CF_TEXT)),
    ]
}

/// Whether the policy lets text go `direction`.
pub fn allowed(policy: ClipboardPolicy, direction: ClipboardDirection) -> bool {
    match direction {
        ClipboardDirection::ToRemote => policy.allows_to_remote(),
        ClipboardDirection::FromRemote => policy.allows_from_remote(),
    }
}

/// Queue shared between the backend (inside `IronRDP`) and the active loop.
pub(crate) type ClipQueue = Arc<Mutex<VecDeque<ClipEvent>>>;

/// Drain the queue.
pub(crate) fn drain(queue: &ClipQueue) -> Vec<ClipEvent> {
    queue.lock().unwrap_or_else(PoisonError::into_inner).drain(..).collect()
}

/// The cliprdr backend: records events, holds no clipboard data.
#[derive(Debug)]
pub(crate) struct QueueBackend {
    queue: ClipQueue,
}

impl QueueBackend {
    pub(crate) fn new(queue: ClipQueue) -> Self {
        Self { queue }
    }

    fn push(&self, event: ClipEvent) {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        // A remote flooding format lists cannot grow memory: keep the newest 64 events.
        if q.len() >= 64 {
            q.pop_front();
        }
        q.push_back(event);
    }
}

impl ironrdp_core::AsAny for QueueBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl CliprdrBackend for QueueBackend {
    fn temporary_directory(&self) -> &'static str {
        // Sent to the server only as a hint for file transfers, which we never offer.
        ".mooring-cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {
        self.push(ClipEvent::RequestFormatList);
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        let ids: Vec<u32> = available_formats.iter().map(|f| f.id().value()).collect();
        self.push(ClipEvent::RemoteCopy(pick_text_format(&ids)));
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.push(ClipEvent::DataRequest(request.format.value()));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let data = (!response.is_error() && response.data().len() <= MAX_CLIPBOARD_WIRE)
            .then(|| response.data().to_vec());
        self.push(ClipEvent::DataResponse(data));
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

/// `session.clipboard` coalescing: at most one entry per second per direction, carrying the
/// bytes since the previous entry; [`ClipAudit::flush_due`] emits the remainder.
#[derive(Debug, Default)]
pub(crate) struct ClipAudit {
    to_remote: Pending,
    from_remote: Pending,
}

#[derive(Debug, Default)]
struct Pending {
    bytes: u64,
    last: Option<Instant>,
}

impl ClipAudit {
    fn slot(&mut self, d: ClipboardDirection) -> &mut Pending {
        match d {
            ClipboardDirection::ToRemote => &mut self.to_remote,
            ClipboardDirection::FromRemote => &mut self.from_remote,
        }
    }

    /// Record a transfer at `now`; returns the entry to audit, if the window allows one.
    pub(crate) fn record(
        &mut self,
        d: ClipboardDirection,
        bytes: usize,
        now: Instant,
    ) -> Option<SessionAudit> {
        let p = self.slot(d);
        p.bytes = p.bytes.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        let due = p.last.is_none_or(|t| now.duration_since(t) >= AUDIT_WINDOW);
        if !due {
            return None;
        }
        p.last = Some(now);
        Some(SessionAudit::Clipboard { direction: d, bytes: std::mem::take(&mut p.bytes) })
    }

    /// Entries still owed: those whose window has elapsed, or all of them (`all`, on close).
    pub(crate) fn flush_due(&mut self, now: Instant, all: bool) -> Vec<SessionAudit> {
        let mut out = Vec::new();
        for d in [ClipboardDirection::ToRemote, ClipboardDirection::FromRemote] {
            let p = self.slot(d);
            let due = all || p.last.is_none_or(|t| now.duration_since(t) >= AUDIT_WINDOW);
            if p.bytes > 0 && due {
                p.last = Some(now);
                out.push(SessionAudit::Clipboard {
                    direction: d,
                    bytes: std::mem::take(&mut p.bytes),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).chain([0, 0]).collect()
    }

    #[test]
    fn decodes_both_text_formats() {
        assert_eq!(
            decode_text(CF_UNICODETEXT, &utf16("Merhaba şğ")).as_deref(),
            Some("Merhaba şğ")
        );
        assert_eq!(decode_text(CF_TEXT, b"abc\0junk").as_deref(), Some("abc"));
        assert_eq!(decode_text(CF_TEXT, &[0xE9, 0]).as_deref(), Some("é"), "Latin-1 fallback");
        assert_eq!(decode_text(CF_UNICODETEXT, &[0x00, 0xD8, 0, 0]).as_deref(), Some("\u{FFFD}"));
        assert_eq!(decode_text(8, b"BM...."), None, "CF_DIB refused");
        assert_eq!(decode_text(49_000, b"x"), None, "registered formats refused");
    }

    #[test]
    fn size_cap_is_exact() {
        let at = "a".repeat(MAX_CLIPBOARD_TEXT);
        let over = "a".repeat(MAX_CLIPBOARD_TEXT + 1);
        assert!(decode_text(CF_TEXT, at.as_bytes()).is_some());
        assert!(decode_text(CF_TEXT, over.as_bytes()).is_none());
        assert!(decode_text(CF_UNICODETEXT, &utf16(&at)).is_some());
        assert!(decode_text(CF_UNICODETEXT, &utf16(&over)).is_none());
        assert!(decode_text(CF_UNICODETEXT, &vec![b'a'; MAX_CLIPBOARD_WIRE + 1]).is_none());
        assert!(encode_text(CF_UNICODETEXT, &at).is_some());
        assert!(encode_text(CF_UNICODETEXT, &over).is_none());
        assert!(encode_text(2, "x").is_none());
    }

    #[test]
    fn format_choice_and_policy() {
        use ClipboardDirection::{FromRemote, ToRemote};
        assert_eq!(pick_text_format(&[1, 13, 49_158]), Some(CF_UNICODETEXT));
        assert_eq!(pick_text_format(&[7, 1]), Some(CF_TEXT));
        assert_eq!(pick_text_format(&[8, 49_158]), None);
        assert!(
            allowed(ClipboardPolicy::Both, ToRemote) && allowed(ClipboardPolicy::Both, FromRemote)
        );
        assert!(
            allowed(ClipboardPolicy::ToRemote, ToRemote)
                && !allowed(ClipboardPolicy::ToRemote, FromRemote)
        );
        assert!(
            !allowed(ClipboardPolicy::FromRemote, ToRemote)
                && allowed(ClipboardPolicy::FromRemote, FromRemote)
        );
        assert!(
            !allowed(ClipboardPolicy::Off, ToRemote) && !allowed(ClipboardPolicy::Off, FromRemote)
        );
    }

    #[test]
    fn audit_coalesces_per_direction() {
        let mut a = ClipAudit::default();
        let t0 = Instant::now();
        let d = ClipboardDirection::FromRemote;
        assert_eq!(a.record(d, 10, t0), Some(SessionAudit::Clipboard { direction: d, bytes: 10 }));
        assert_eq!(a.record(d, 5, t0 + Duration::from_millis(200)), None);
        assert!(a.record(ClipboardDirection::ToRemote, 1, t0).is_some(), "independent window");
        assert_eq!(
            a.record(d, 7, t0 + Duration::from_millis(1100)),
            Some(SessionAudit::Clipboard { direction: d, bytes: 12 })
        );
        assert_eq!(a.record(d, 3, t0 + Duration::from_millis(1200)), None);
        assert!(a.flush_due(t0 + Duration::from_millis(1500), false).is_empty(), "window open");
        assert_eq!(
            a.flush_due(t0 + Duration::from_millis(2200), false),
            vec![SessionAudit::Clipboard { direction: d, bytes: 3 }]
        );
        assert_eq!(a.record(d, 4, t0 + Duration::from_millis(2300)), None);
        assert_eq!(a.flush_due(t0 + Duration::from_millis(2301), true).len(), 1, "close flushes");
        assert!(a.flush_due(t0 + Duration::from_millis(9999), true).is_empty());
    }

    #[test]
    fn backend_queue_is_bounded() {
        let q = ClipQueue::default();
        let mut b = QueueBackend::new(Arc::clone(&q));
        for _ in 0..100 {
            b.on_request_format_list();
        }
        b.on_remote_copy(&text_formats());
        let events = drain(&q);
        assert_eq!(events.len(), 64);
        assert_eq!(events.last(), Some(&ClipEvent::RemoteCopy(Some(CF_UNICODETEXT))));
    }
}
