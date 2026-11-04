//! Clipboard side of the active stage: turns the cliprdr backend's queued events into
//! channel messages, applying the `ClipboardPolicy` and the text caps (ADR-0011 §Clipboard).
//! The OS clipboard is touched only through `LocalClipboard`, on a blocking thread.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use ironrdp_cliprdr::pdu::{ClipboardFormatId, FormatDataResponse};
use ironrdp_cliprdr::{CliprdrClient, CliprdrSvcMessages};
use ironrdp_core::IntoOwned as _;
use ironrdp_session::ActiveStage;
use mooring_core::audit::ClipboardDirection;
use mooring_core::options::ClipboardPolicy;
use zeroize::Zeroizing;

use crate::clipboard::{
    allowed, decode_text, drain, encode_text, text_formats, ClipAudit, ClipEvent, ClipQueue,
    MAX_CLIPBOARD_TEXT,
};
use crate::options::{AuditSink, LocalClipboard};

/// Most paste requests we keep track of (the cliprdr crate caps its own queue too).
const MAX_PENDING_PASTES: usize = 8;

/// Per-session clipboard state.
pub(crate) struct ClipState {
    queue: Option<ClipQueue>,
    local: Option<Arc<dyn LocalClipboard>>,
    policy: ClipboardPolicy,
    /// Text we announced to the remote (served on its format-data request).
    offered: Option<Zeroizing<String>>,
    pending_pastes: VecDeque<u32>,
    audit: ClipAudit,
}

impl std::fmt::Debug for ClipState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipState")
            .field("enabled", &self.queue.is_some())
            .field("policy", &self.policy)
            .field("offered", &self.offered.as_ref().map(|t| t.len()))
            .finish_non_exhaustive()
    }
}

fn messages(
    stage: &ActiveStage,
    msgs: ironrdp_pdu::PduResult<CliprdrSvcMessages<ironrdp_cliprdr::Client>>,
) -> Vec<Vec<u8>> {
    match msgs
        .map_err(|e| e.to_string())
        .and_then(|m| stage.process_svc_processor_messages(m).map_err(|e| e.to_string()))
    {
        Ok(frame) if !frame.is_empty() => vec![frame],
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::debug!(error = %e, "cliprdr message not sent");
            Vec::new()
        }
    }
}

impl ClipState {
    /// `queue` is `Some` when the cliprdr channel was attached.
    pub(crate) fn new(
        queue: Option<ClipQueue>,
        local: Option<Arc<dyn LocalClipboard>>,
        policy: ClipboardPolicy,
    ) -> Self {
        Self {
            queue,
            local,
            policy,
            offered: None,
            pending_pastes: VecDeque::new(),
            audit: ClipAudit::default(),
        }
    }

    /// Whether cliprdr should be attached at all.
    pub(crate) fn enabled(
        local: Option<&Arc<dyn LocalClipboard>>,
        policy: ClipboardPolicy,
    ) -> bool {
        local.is_some() && policy != ClipboardPolicy::Off
    }

    fn record(&mut self, direction: ClipboardDirection, bytes: usize, audit: &AuditSink) {
        if let Some(event) = self.audit.record(direction, bytes, Instant::now()) {
            audit.push(event);
        }
    }

    /// Emit coalesced entries that are due (`all`: everything, on close).
    pub(crate) fn flush_audit(&mut self, audit: &AuditSink, all: bool) {
        for event in self.audit.flush_due(Instant::now(), all) {
            audit.push(event);
        }
    }

    /// Process what the backend queued during the last `ActiveStage::process`.
    pub(crate) async fn on_events(
        &mut self,
        stage: &mut ActiveStage,
        audit: &AuditSink,
    ) -> Vec<Vec<u8>> {
        let Some(queue) = &self.queue else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for event in drain(queue) {
            out.extend(self.on_event(event, stage, audit).await);
        }
        out
    }

    async fn on_event(
        &mut self,
        event: ClipEvent,
        stage: &mut ActiveStage,
        audit: &AuditSink,
    ) -> Vec<Vec<u8>> {
        match event {
            ClipEvent::RequestFormatList => {
                // Initialization: announce our text only if one is already offered.
                let formats = if self.offered.is_some() { text_formats() } else { Vec::new() };
                let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                    return Vec::new();
                };
                let msgs = c.initiate_copy(&formats);
                messages(stage, msgs)
            }
            ClipEvent::RemoteCopy(Some(format))
                if allowed(self.policy, ClipboardDirection::FromRemote) =>
            {
                if self.pending_pastes.len() >= MAX_PENDING_PASTES {
                    return Vec::new();
                }
                let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                    return Vec::new();
                };
                if !c.is_ready() {
                    return Vec::new();
                }
                let msgs = c.initiate_paste(ClipboardFormatId::new(format));
                self.pending_pastes.push_back(format);
                messages(stage, msgs)
            }
            ClipEvent::RemoteCopy(_) => Vec::new(),
            ClipEvent::DataResponse(data) => {
                let format = self.pending_pastes.pop_front();
                let text = format.zip(data).and_then(|(f, d)| decode_text(f, &d));
                if let (Some(text), Some(local)) = (text, &self.local) {
                    if allowed(self.policy, ClipboardDirection::FromRemote) && !text.is_empty() {
                        let bytes = text.len();
                        let local = Arc::clone(local);
                        let text = Zeroizing::new(text);
                        let _ = tokio::task::spawn_blocking(move || {
                            local.write_text(&text);
                        })
                        .await;
                        self.record(ClipboardDirection::FromRemote, bytes, audit);
                    }
                }
                Vec::new()
            }
            ClipEvent::DataRequest(format) => {
                let served = self
                    .offered
                    .as_ref()
                    .filter(|_| allowed(self.policy, ClipboardDirection::ToRemote))
                    .and_then(|t| encode_text(format, t).map(|r| (r, t.len())));
                let (response, bytes) = match served {
                    Some((r, n)) => (r, n),
                    None => (FormatDataResponse::new_error(), 0),
                };
                let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                    return Vec::new();
                };
                let msgs = c.submit_format_data(response.into_owned());
                let out = messages(stage, msgs);
                if bytes > 0 && !out.is_empty() {
                    self.record(ClipboardDirection::ToRemote, bytes, audit);
                }
                out
            }
        }
    }

    /// `SessionInput::ClipboardOffer`: read the OS clipboard here in Rust and announce it.
    pub(crate) async fn offer(&mut self, stage: &mut ActiveStage) -> Vec<Vec<u8>> {
        if self.queue.is_none() || !allowed(self.policy, ClipboardDirection::ToRemote) {
            return Vec::new();
        }
        let Some(local) = self.local.as_ref().map(Arc::clone) else {
            return Vec::new();
        };
        let text = tokio::task::spawn_blocking(move || local.read_text()).await.ok().flatten();
        let Some(text) = text.filter(|t| !t.is_empty() && t.len() <= MAX_CLIPBOARD_TEXT) else {
            return Vec::new();
        };
        if self.offered.as_deref().is_some_and(|o| o == &text) {
            return Vec::new();
        }
        self.offered = Some(Zeroizing::new(text));
        let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else { return Vec::new() };
        let msgs = c.initiate_copy(&text_formats());
        messages(stage, msgs)
    }
}
