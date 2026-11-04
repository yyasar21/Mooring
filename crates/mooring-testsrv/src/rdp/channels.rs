//! Static / dynamic channels: `cliprdr` (text only) and `drdynvc` + Display Control.

use std::sync::{Arc, Mutex};

use ironrdp_acceptor::Acceptor;
use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_cliprdr::CliprdrServer;
use ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout;
use ironrdp_displaycontrol::server::{DisplayControlHandler, DisplayControlServer};
use ironrdp_dvc::DrdynvcServer;

use super::{lock, Shared};

/// Work the clipboard backend asks the active loop to do (the backend cannot send itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClipAction {
    /// The client announced CF_UNICODETEXT: fetch it.
    Paste,
    /// The client asked for our text.
    Serve,
}

#[derive(Debug)]
pub(crate) struct ClipBackend {
    shared: Arc<Shared>,
    pub(crate) actions: Arc<Mutex<Vec<ClipAction>>>,
}

impl ironrdp_core::AsAny for ClipBackend {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &'static str {
        ".cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {}

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if available_formats.iter().any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT) {
            lock(&self.actions).push(ClipAction::Paste);
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        if request.format == ClipboardFormatId::CF_UNICODETEXT {
            lock(&self.actions).push(ClipAction::Serve);
        }
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if let Ok(text) = response.to_unicode_string() {
            lock(&self.shared.stats).clipboard_from_client.push(text);
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

struct LayoutRecorder(Arc<Shared>);

impl DisplayControlHandler for LayoutRecorder {
    fn monitor_layout(&self, layout: DisplayControlMonitorLayout) {
        let primary =
            layout.monitors().iter().find(|m| m.is_primary()).or_else(|| layout.monitors().first());
        if let Some(m) = primary {
            lock(&self.0.stats).layouts.push(m.dimensions());
        }
    }
}

/// Attaches the configured channels; returns the clipboard action queue when cliprdr is on.
pub(crate) fn attach(
    shared: &Arc<Shared>,
    acceptor: &mut Acceptor,
) -> Option<Arc<Mutex<Vec<ClipAction>>>> {
    let mut queue = None;
    if shared.config.clipboard {
        let actions = Arc::new(Mutex::new(Vec::new()));
        queue = Some(Arc::clone(&actions));
        let backend = ClipBackend { shared: Arc::clone(shared), actions };
        acceptor.attach_static_channel(CliprdrServer::new(Box::new(backend)));
    }
    if shared.config.display_control {
        let dvc = DrdynvcServer::new().with_dynamic_channel(DisplayControlServer::new(Box::new(
            LayoutRecorder(Arc::clone(shared)),
        )));
        acceptor.attach_static_channel(dvc);
    }
    queue
}

/// The single text format the server announces.
pub(crate) fn text_formats() -> [ClipboardFormat; 1] {
    [ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
}
