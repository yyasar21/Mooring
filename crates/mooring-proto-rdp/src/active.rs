//! The active stage (ADR-0011 §Session behaviour): server PDUs → `ActiveStage::process` →
//! `FrameSink` (bitmaps, cursor), user input → fast-path input, debounced Display Control
//! resize, Deactivation-Reactivation (server-side size changes), cliprdr text, graceful close.

use std::sync::Arc;
use std::time::Duration;

use ironrdp_cliprdr::CliprdrClient;
use ironrdp_connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationState,
};
use ironrdp_connector::{ClientConnector, DesktopSize, Sequence as _};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{
    ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason,
};
use ironrdp_tokio::{single_sequence_step_read, split_tokio_framed, FramedWrite, TokioFramed};
use mooring_core::frame::{Cursor, PixelOrder, Rect, MAX_CURSOR, MAX_DIM};
use mooring_core::session::{CloseCode, SessionEvent, SessionInput};
use mooring_core::FrameSink;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::active_clip::ClipState;
use crate::clipboard::{ClipQueue, QueueBackend};
use crate::connect::{clamp_desktop, Established, RdpStream};
use crate::errors::{self, end, End};
use crate::input::InputMapper;
use crate::reassembly::Reassembly;
use crate::shared::{sanitize, Shared};

/// ADR-0011: a UI resize is debounced for 300 ms.
pub const RESIZE_DEBOUNCE: Duration = Duration::from_millis(300);
/// How long a graceful close waits for the server's disconnect.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

type Reader = TokioFramed<ReadHalf<RdpStream>>;
type Writer = TokioFramed<WriteHalf<RdpStream>>;

/// Front → driver.
#[derive(Debug)]
pub(crate) enum Command {
    Input(SessionInput),
    Close,
}

/// Channels attached to every connector: drdynvc (Display Control) and, when enabled,
/// cliprdr.
#[derive(Debug, Clone, Default)]
pub(crate) struct Channels {
    pub(crate) cliprdr: Option<ClipQueue>,
}

impl Channels {
    pub(crate) fn attach(&self, connector: ClientConnector) -> ClientConnector {
        let dvc = DrdynvcClient::new()
            .with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
        let connector = connector.with_static_channel(dvc);
        match &self.cliprdr {
            Some(q) => connector.with_static_channel(CliprdrClient::new(Box::new(
                QueueBackend::new(Arc::clone(q)),
            ))),
            None => connector,
        }
    }
}

/// Inclusive RDP rectangle → our `Rect`, clipped to `w × h`. `None` when empty or outside.
pub fn to_rect(r: &InclusiveRectangle, w: u16, h: u16) -> Option<Rect> {
    if r.left >= w || r.top >= h || r.right < r.left || r.bottom < r.top {
        return None;
    }
    let right = r.right.min(w - 1);
    let bottom = r.bottom.min(h - 1);
    Some(Rect::new(r.left, r.top, right - r.left + 1, bottom - r.top + 1))
}

/// B-5: the desktop size comes from the server's Demand Active and is unbounded in
/// `IronRDP`. Check it before anything allocates `w × h × 4` bytes for it.
pub(crate) fn check_desktop(size: DesktopSize) -> Result<(), End> {
    let (w, h) = (size.width, size.height);
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
        return Err(end(CloseCode::ProtocolError, "the server desktop size is not supported"));
    }
    Ok(())
}

/// Copy a damaged region of the decoded image into the sink (RGBA, alpha forced opaque).
pub(crate) fn blit(sink: &FrameSink, image: &DecodedImage, r: &InclusiveRectangle) {
    let Some(rect) = to_rect(r, image.width(), image.height()) else {
        return;
    };
    let stride = image.stride();
    let start = usize::from(rect.y) * stride + usize::from(rect.x) * 4;
    if let Some(src) = image.data().get(start..) {
        if let Err(e) = sink.blit(rect, src, stride, PixelOrder::Rgbx) {
            tracing::debug!(error = %e, "rdp blit refused");
        }
    }
}

/// Server pointer bitmap → cursor sprite (`Default` when it cannot be shown).
pub(crate) fn cursor(p: &ironrdp_graphics::pointer::DecodedPointer) -> Cursor {
    let size_ok = p.width > 0 && p.height > 0 && p.width <= MAX_CURSOR && p.height <= MAX_CURSOR;
    if !size_ok || p.bitmap_data.len() != usize::from(p.width) * usize::from(p.height) * 4 {
        return Cursor::Default;
    }
    Cursor::Sprite {
        hot_x: p.hotspot_x.min(p.width - 1),
        hot_y: p.hotspot_y.min(p.height - 1),
        w: p.width,
        h: p.height,
        rgba: p.bitmap_data.clone(),
    }
}

pub(crate) struct Active<'a> {
    pub(crate) shared: &'a Shared,
    pub(crate) sink: FrameSink,
    pub(crate) commands: &'a mut mpsc::Receiver<Command>,
    pub(crate) clip: ClipState,
    stage: ActiveStage,
    image: DecodedImage,
    size: DesktopSize,
    factory: ConnectionActivationFactory,
    refresh_rect: bool,
    suppress_output: bool,
    input: InputMapper,
    pending_resize: Option<(DesktopSize, Instant)>,
    reassembly: Reassembly,
}

impl<'a> Active<'a> {
    pub(crate) fn new(
        est: Established,
        shared: &'a Shared,
        sink: FrameSink,
        commands: &'a mut mpsc::Receiver<Command>,
        clip: ClipState,
    ) -> Result<(Self, TokioFramed<RdpStream>), End> {
        let Established { framed, result, .. } = est;
        let size = result.desktop_size;
        check_desktop(size)?;
        sink.resize(size.width, size.height).map_err(|_| {
            end(CloseCode::ProtocolError, "the server desktop size is not supported")
        })?;
        let factory = result.activation_factory;
        let drdynvc = result.static_channels.get_channel_id_by_type::<DrdynvcClient>();
        let reassembly = Reassembly::new(result.io_channel_id, result.message_channel_id, drdynvc);
        let stage = ActiveStageBuilder {
            static_channels: result.static_channels,
            user_channel_id: result.user_channel_id,
            io_channel_id: result.io_channel_id,
            message_channel_id: result.message_channel_id,
            share_id: result.share_id,
            compression_type: result.compression_type,
            enable_server_pointer: result.enable_server_pointer,
            pointer_software_rendering: result.pointer_software_rendering,
        }
        .build();
        let me = Self {
            shared,
            sink,
            commands,
            clip,
            stage,
            image: DecodedImage::new(PixelFormat::RgbA32, size.width, size.height),
            size,
            factory,
            refresh_rect: result.refresh_rect_support,
            suppress_output: result.suppress_output_support,
            input: InputMapper::new(),
            pending_resize: None,
            reassembly,
        };
        Ok((me, framed))
    }

    async fn resized(&mut self, size: DesktopSize) -> Result<(), End> {
        check_desktop(size)?;
        self.sink.resize(size.width, size.height).map_err(|_| {
            end(CloseCode::ProtocolError, "the server desktop size is not supported")
        })?;
        self.size = size;
        if (self.image.width(), self.image.height()) != (size.width, size.height) {
            self.image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
        }
        let event = SessionEvent::DesktopResized {
            width: u32::from(size.width),
            height: u32::from(size.height),
        };
        self.shared.events.send(event).await.map_err(|_| end(CloseCode::User, "closed by user"))
    }

    /// Drive the session until it ends.
    pub(crate) async fn run(mut self, framed: TokioFramed<RdpStream>) -> End {
        let (mut reader, mut writer) = split_tokio_framed(framed);
        if let Err(e) = self.resized(self.size).await {
            return e;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let ended = loop {
            let deadline = self.pending_resize.map(|(_, at)| at);
            let resize_due = async move {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            let step = tokio::select! {
                biased;
                () = self.shared.closed() => Err(self.shutdown(&mut reader, &mut writer).await),
                pdu = reader.read_pdu() => match pdu {
                    Ok((action, frame)) => {
                        let at = reader.last_read_at();
                        self.on_pdu(action, &frame, at, &mut reader, &mut writer).await
                    }
                    Err(e) => Err(errors::io(&e)),
                },
                cmd = self.commands.recv() => match cmd {
                    Some(Command::Input(input)) => self.on_input(input, &mut writer).await,
                    Some(Command::Close) | None => Err(self.shutdown(&mut reader, &mut writer).await),
                },
                () = resize_due => self.send_resize(&mut writer).await,
                _ = tick.tick() => {
                    self.clip.flush_audit(&self.shared.audit, false);
                    Ok(())
                }
            };
            if let Err(e) = step {
                break e;
            }
        };
        self.clip.flush_audit(&self.shared.audit, true);
        ended
    }

    async fn write(writer: &mut Writer, frame: &[u8]) -> Result<(), End> {
        if frame.is_empty() {
            return Ok(());
        }
        writer.write_all(frame).await.map_err(|e| errors::io(&e))
    }

    async fn outputs(
        &mut self,
        outputs: Vec<ActiveStageOutput>,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> Result<(), End> {
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(f) => Self::write(writer, &f).await?,
                ActiveStageOutput::GraphicsUpdate(r) => blit(&self.sink, &self.image, &r),
                ActiveStageOutput::PointerDefault => self.sink.cursor(Cursor::Default),
                ActiveStageOutput::PointerHidden => self.sink.cursor(Cursor::Hidden),
                ActiveStageOutput::PointerBitmap(p) => self.sink.cursor(cursor(&p)),
                ActiveStageOutput::Terminate(reason) => return Err(self.terminated(&reason)),
                ActiveStageOutput::DeactivateAll => self.reactivate(reader, writer).await?,
                ActiveStageOutput::ServerRedirection(_) => {
                    return Err(end(
                        CloseCode::ProtocolError,
                        "server redirection is not supported",
                    ));
                }
                other => {
                    tracing::trace!(output = ?std::mem::discriminant(&other), "rdp output ignored");
                }
            }
        }
        Ok(())
    }

    fn terminated(&self, reason: &GracefulDisconnectReason) -> End {
        if self.shared.is_closing() {
            return end(CloseCode::User, "closed by user");
        }
        match reason {
            GracefulDisconnectReason::UserInitiated => {
                end(CloseCode::ServerEnded, "the remote session was ended")
            }
            GracefulDisconnectReason::ServerInitiated => {
                end(CloseCode::ServerEnded, "the server ended the session")
            }
            GracefulDisconnectReason::Other(text) => (CloseCode::ServerEnded, sanitize(text)),
        }
    }

    async fn on_pdu(
        &mut self,
        action: ironrdp_pdu::Action,
        frame: &[u8],
        at: Option<ironrdp_connector::MonotonicInstant>,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> Result<(), End> {
        // M-14: IronRDP reassembles channel and fast-path fragments without a cap.
        self.reassembly.check(action, frame)?;
        let outputs = self
            .stage
            .process(&mut self.image, action, frame, at)
            .map_err(|e| errors::session(&e))?;
        self.outputs(outputs, reader, writer).await?;
        if self.stage.take_bitmap_recovery_request() {
            let (w, h) = (self.size.width, self.size.height);
            let frames = self
                .stage
                .request_full_redraw(w, h, self.refresh_rect, self.suppress_output)
                .map_err(|e| errors::session(&e))?;
            for f in frames {
                Self::write(writer, &f).await?;
            }
        }
        let frames = self.clip.on_events(&mut self.stage, &self.shared.audit).await;
        for f in frames {
            Self::write(writer, &f).await?;
        }
        Ok(())
    }

    async fn fastpath(
        &mut self,
        events: &[FastPathInputEvent],
        writer: &mut Writer,
    ) -> Result<(), End> {
        let outputs = self
            .stage
            .process_fastpath_input(&mut self.image, events)
            .map_err(|e| errors::session(&e))?;
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(f) => Self::write(writer, &f).await?,
                ActiveStageOutput::GraphicsUpdate(r) => blit(&self.sink, &self.image, &r),
                _ => {}
            }
        }
        Ok(())
    }

    async fn on_input(&mut self, input: SessionInput, writer: &mut Writer) -> Result<(), End> {
        let (w, h) = (self.size.width, self.size.height);
        let events = match input {
            SessionInput::Pointer { x, y, buttons } => self.input.pointer(x, y, buttons, w, h),
            SessionInput::Key { code, pressed, .. } => self.input.key(&code, pressed),
            SessionInput::Wheel { dx, dy } => self.input.wheel(dx, dy),
            SessionInput::Unicode { text } => self.input.unicode(&text),
            SessionInput::ReleaseAll => self.input.release_all(),
            SessionInput::Resize { size } => {
                let target = clamp_desktop(size.width, size.height);
                self.pending_resize = Some((target, Instant::now() + RESIZE_DEBOUNCE));
                Vec::new()
            }
            SessionInput::ClipboardOffer => {
                for f in self.clip.offer(&mut self.stage).await {
                    Self::write(writer, &f).await?;
                }
                Vec::new()
            }
            SessionInput::Bytes { .. }
            | SessionInput::Answer { .. }
            | SessionInput::CredentialAnswer { .. } => Vec::new(),
        };
        self.fastpath(&events, writer).await
    }

    async fn send_resize(&mut self, writer: &mut Writer) -> Result<(), End> {
        let Some((size, _)) = self.pending_resize.take() else {
            return Ok(());
        };
        if size == self.size {
            return Ok(());
        }
        match self.stage.encode_resize(u32::from(size.width), u32::from(size.height), None, None) {
            Some(Ok(frame)) => Self::write(writer, &frame).await,
            Some(Err(e)) => {
                tracing::debug!(error = %e, "display control resize not encoded");
                Ok(())
            }
            // No Display Control channel: the session keeps its size and the UI scales.
            None => Ok(()),
        }
    }

    /// Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3): a fresh capability exchange,
    /// typically with a new desktop size after a Display Control resize.
    async fn reactivate(&mut self, reader: &mut Reader, writer: &mut Writer) -> Result<(), End> {
        let mut seq = self.factory.create();
        let mut buf = WriteBuf::new();
        while !seq.state().is_terminal() {
            let written = single_sequence_step_read(reader, &mut seq, &mut buf)
                .await
                .map_err(|e| errors::connector(&e))?;
            if let Some(n) = written.size() {
                Self::write(writer, &buf.filled()[..n]).await?;
            }
        }
        let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            static_channel_chunk_size,
            enable_server_pointer,
            pointer_software_rendering,
            refresh_rect_support,
            suppress_output_support,
            ..
        } = seq.connection_activation_state()
        else {
            return Err(end(CloseCode::ProtocolError, "reactivation did not finish"));
        };
        let (io, user) = (self.factory.io_channel_id(), self.factory.user_channel_id());
        if !self.stage.reactivate(
            io,
            user,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            static_channel_chunk_size,
        ) {
            return Err(end(
                CloseCode::ProtocolError,
                "invalid channel chunk size on reactivation",
            ));
        }
        self.refresh_rect = refresh_rect_support;
        self.suppress_output = suppress_output_support;
        self.resized(desktop_size).await
    }

    /// Send the shutdown request and wait briefly for the server's disconnect.
    async fn shutdown(&mut self, reader: &mut Reader, writer: &mut Writer) -> End {
        let bye = end(CloseCode::User, "closed by user");
        let Ok(frames) = self.stage.graceful_shutdown() else {
            return bye;
        };
        for out in frames {
            if let ActiveStageOutput::ResponseFrame(f) = out {
                if Self::write(writer, &f).await.is_err() {
                    return bye;
                }
            }
        }
        let _ = tokio::time::timeout(SHUTDOWN_GRACE, async {
            while let Ok((action, frame)) = reader.read_pdu().await {
                let Ok(outputs) = self.stage.process(&mut self.image, action, &frame, None) else {
                    break;
                };
                if outputs.iter().any(|o| matches!(o, ActiveStageOutput::Terminate(_))) {
                    break;
                }
            }
        })
        .await;
        bye
    }
}

#[cfg(test)]
#[path = "active_tests.rs"]
mod tests;
