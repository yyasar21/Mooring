//! Active stage of the test server: bitmap updates out; input, channel data and shutdown in.

use std::sync::{Arc, Mutex};

use ironrdp_acceptor::AcceptorResult;
use ironrdp_async::FramedWrite;
use ironrdp_cliprdr::pdu::{ClipboardFormatId, FormatDataResponse};
use ironrdp_cliprdr::CliprdrServer;
use ironrdp_core::decode;
use ironrdp_pdu::input::fast_path::{
    FastPathInput, FastPathInputEvent, KeyboardFlags as FpKeyFlags,
};
use ironrdp_pdu::input::scan_code::KeyboardFlags as ScanFlags;
use ironrdp_pdu::input::unicode::KeyboardFlags as UniFlags;
use ironrdp_pdu::input::{InputEvent, MousePdu};
use ironrdp_pdu::mcs::{DisconnectReason, McsMessage};
use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu, ShareDataPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::Action;
use ironrdp_svc::{server_encode_svc_messages, StaticChannelSet, SvcMessage};
use ironrdp_tokio::TokioFramed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use super::channels::{text_formats, ClipAction};
use super::{bitmap, lock, Event, InputRecord, Rect, Shared};

struct Active<'a> {
    shared: &'a Shared,
    channels: StaticChannelSet,
    user_channel_id: u16,
    io_channel_id: u16,
    clip: Option<Arc<Mutex<Vec<ClipAction>>>>,
}

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub(crate) async fn run<S>(
    shared: &Arc<Shared>,
    mut framed: TokioFramed<S>,
    result: AcceptorResult,
    clip: Option<Arc<Mutex<Vec<ClipAction>>>>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    let mut events = shared.events.subscribe();
    let mut st = Active {
        shared,
        channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        clip,
    };
    let mut out = Vec::new();
    for (_, channel, id) in st.channels.iter_mut() {
        if let Some(id) = id {
            let msgs = channel.start().map_err(s)?;
            out.extend(server_encode_svc_messages(msgs, id, result.user_channel_id).map_err(s)?);
        }
    }
    framed.write_all(&out).await.map_err(s)?;
    for frame in result.input_events {
        let action =
            Action::from_fp_output_header(frame[0]).map_err(|_| "bad backlog frame".to_owned())?;
        let reply = st.dispatch(action, &frame)?;
        framed.write_all(&reply.bytes).await.map_err(s)?;
    }
    let full = lock(&shared.fb).bounds();
    st.send_bitmap(&mut framed, full).await?;

    loop {
        tokio::select! {
            pdu = framed.read_pdu() => {
                let (action, bytes) = match pdu {
                    Ok(p) => p,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(e) => return Err(format!("read: {e}")),
                };
                let reply = st.dispatch(action, &bytes)?;
                if !reply.bytes.is_empty() {
                    framed.write_all(&reply.bytes).await.map_err(s)?;
                }
                if reply.disconnect {
                    return Ok(());
                }
            }
            ev = events.recv() => match ev {
                Ok(Event::Dirty(r)) => st.send_bitmap(&mut framed, r).await?,
                Ok(Event::ClipboardOffer) => {
                    let bytes = st.with_cliprdr(|c| c.initiate_copy(&text_formats()).map(Into::into))?;
                    framed.write_all(&bytes).await.map_err(s)?;
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let full = lock(&shared.fb).bounds();
                    st.send_bitmap(&mut framed, full).await?;
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        }
        let bytes = st.drain_clipboard()?;
        if !bytes.is_empty() {
            framed.write_all(&bytes).await.map_err(s)?;
        }
    }
}

#[derive(Default)]
struct Reply {
    bytes: Vec<u8>,
    disconnect: bool,
}

impl Active<'_> {
    async fn send_bitmap<W: FramedWrite>(&self, w: &mut W, r: Rect) -> Result<(), String> {
        let cfg = &self.shared.config;
        let (pdus, planar) = {
            let fb = lock(&self.shared.fb);
            bitmap::updates(&fb, r, cfg.bitmap, cfg.knobs.out_of_bounds_bitmap)?
        };
        for pdu in pdus {
            w.write_all(&pdu).await.map_err(s)?;
        }
        let mut stats = lock(&self.shared.stats);
        stats.bitmap_updates += 1;
        stats.planar_tiles += planar;
        Ok(())
    }

    fn record(&self, rec: InputRecord) {
        lock(&self.shared.stats).inputs.push(rec);
    }

    fn mouse(&self, m: MousePdu) {
        self.record(InputRecord::Mouse {
            flags: m.flags.bits(),
            x: m.x_position,
            y: m.y_position,
            wheel: m.number_of_wheel_rotation_units,
        });
    }

    fn dispatch(&mut self, action: Action, frame: &[u8]) -> Result<Reply, String> {
        match action {
            Action::FastPath => {
                let input: FastPathInput = decode(frame).map_err(s)?;
                for ev in input.input_events() {
                    match ev {
                        FastPathInputEvent::KeyboardEvent(f, code) => {
                            self.record(InputRecord::Key {
                                code: *code,
                                extended: f.contains(FpKeyFlags::EXTENDED),
                                release: f.contains(FpKeyFlags::RELEASE),
                            });
                        }
                        FastPathInputEvent::UnicodeKeyboardEvent(f, code) => {
                            self.record(InputRecord::Unicode {
                                code: *code,
                                release: f.contains(FpKeyFlags::RELEASE),
                            });
                        }
                        FastPathInputEvent::MouseEvent(m) => self.mouse(*m),
                        FastPathInputEvent::SyncEvent(f) => {
                            self.record(InputRecord::Sync(u32::from(f.bits())));
                        }
                        _ => {}
                    }
                }
                Ok(Reply::default())
            }
            Action::X224 => self.x224(frame),
        }
    }

    fn x224(&mut self, frame: &[u8]) -> Result<Reply, String> {
        let message = decode::<X224<McsMessage<'_>>>(frame).map_err(s)?;
        match message.0 {
            McsMessage::SendDataRequest(data) if data.channel_id == self.io_channel_id => {
                let control: ShareControlHeader = decode(data.user_data.as_ref()).map_err(s)?;
                if let ShareControlPdu::Data(header) = control.share_control_pdu {
                    match header.share_data_pdu {
                        ShareDataPdu::Input(pdu) => self.slow_input(pdu.0),
                        ShareDataPdu::ShutdownRequest => {
                            lock(&self.shared.stats).shutdown_requests += 1;
                            return Ok(Reply { bytes: Vec::new(), disconnect: true });
                        }
                        _ => {}
                    }
                }
                Ok(Reply::default())
            }
            McsMessage::SendDataRequest(data) => {
                let Some(svc) = self.channels.get_by_channel_id_mut(data.channel_id) else {
                    return Ok(Reply::default());
                };
                let msgs = svc.process(&data.user_data).map_err(s)?;
                let bytes = server_encode_svc_messages(msgs, data.channel_id, self.user_channel_id)
                    .map_err(s)?;
                Ok(Reply { bytes, disconnect: false })
            }
            McsMessage::DisconnectProviderUltimatum(d) => Ok(Reply {
                bytes: Vec::new(),
                disconnect: d.reason == DisconnectReason::UserRequested,
            }),
            _ => Ok(Reply::default()),
        }
    }

    fn slow_input(&self, events: Vec<InputEvent>) {
        for ev in events {
            match ev {
                InputEvent::ScanCode(k) => self.record(InputRecord::Key {
                    code: k.key_code.to_le_bytes()[0],
                    extended: k.flags.contains(ScanFlags::EXTENDED),
                    release: k.flags.contains(ScanFlags::RELEASE),
                }),
                InputEvent::Unicode(u) => self.record(InputRecord::Unicode {
                    code: u.unicode_code,
                    release: u.flags.contains(UniFlags::RELEASE),
                }),
                InputEvent::Mouse(m) => self.mouse(m),
                InputEvent::Sync(sy) => self.record(InputRecord::Sync(sy.flags.bits())),
                _ => {}
            }
        }
    }

    /// Runs `f` on the cliprdr processor and encodes its messages for the wire.
    fn with_cliprdr<F>(&mut self, f: F) -> Result<Vec<u8>, String>
    where
        F: FnOnce(&mut CliprdrServer) -> ironrdp_pdu::PduResult<Vec<SvcMessage>>,
    {
        let Some(id) = self.channels.get_channel_id_by_type::<CliprdrServer>() else {
            return Ok(Vec::new());
        };
        let Some(c) = self
            .channels
            .get_by_type_mut::<CliprdrServer>()
            .and_then(|svc| svc.channel_processor_downcast_mut::<CliprdrServer>())
        else {
            return Ok(Vec::new());
        };
        let msgs = f(c).map_err(s)?;
        server_encode_svc_messages(msgs, id, self.user_channel_id).map_err(s)
    }

    fn drain_clipboard(&mut self) -> Result<Vec<u8>, String> {
        let actions = match &self.clip {
            Some(q) => std::mem::take(&mut *lock(q)),
            None => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for a in actions {
            let bytes = match a {
                ClipAction::Paste => self.with_cliprdr(|c| {
                    c.initiate_paste(ClipboardFormatId::CF_UNICODETEXT).map(Into::into)
                })?,
                ClipAction::Serve => {
                    let text = lock(&self.shared.clipboard).clone().unwrap_or_default();
                    lock(&self.shared.stats).clipboard_served += 1;
                    let resp = FormatDataResponse::new_unicode_string(&text);
                    self.with_cliprdr(|c| c.submit_format_data(resp).map(Into::into))?
                }
            };
            out.extend(bytes);
        }
        Ok(out)
    }
}
