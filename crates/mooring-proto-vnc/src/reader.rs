//! The receive side of a running session: parses server messages, decodes rectangles into
//! the `FrameSink` and reports what the control loop must know. Runs as its own task so a
//! long write never stalls reading (and the other way round).

use mooring_core::frame::{FrameSink, PixelOrder};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;

use crate::conn::RecvBuf;
use crate::decode::{Decoders, RectOp, MAX_INFLATE};
use crate::error::VncError;
use crate::messages::{parse_rect, parse_server_message, ServerMessage, MAX_ZRLE_COMPRESSED};

/// What the reader tells the control loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReaderEvent {
    /// A `FramebufferUpdate` was fully applied.
    UpdateDone,
    /// The framebuffer was resized (the sink is already resized).
    Resized { w: u16, h: u16 },
    /// The server supports `ExtendedDesktopSize`: first screen (id, flags).
    ExtDesktop((u32, u32)),
    /// QEMU Extended Key Event confirmed.
    QemuExtKey,
    /// Remote cut text (Latin-1 converted), within the cap.
    CutText(String),
    /// Bell.
    Bell,
    /// The reader stopped.
    Failed(VncError),
}

fn sink_err(e: &mooring_core::MooringError) -> VncError {
    VncError::protocol(format!("frame: {e}"))
}

/// Largest item buffered for a `w × h` framebuffer: a Raw rectangle of the whole screen, or
/// the largest compressed ZRLE payload.
fn max_item(w: u16, h: u16) -> usize {
    (usize::from(w) * usize::from(h) * 4).max(MAX_ZRLE_COMPRESSED.max(MAX_INFLATE)) + 64 * 1024
}

pub(crate) async fn run<R: AsyncRead + Unpin>(
    mut rb: RecvBuf<R>,
    sink: FrameSink,
    tx: mpsc::Sender<ReaderEvent>,
) {
    let mut dec = Decoders::default();
    let end = loop {
        match step(&mut rb, &sink, &mut dec, &tx).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => break e,
        }
    };
    let _ = tx.send(ReaderEvent::Failed(end)).await;
}

/// One server message. `Ok(false)`: the control loop is gone.
async fn step<R: AsyncRead + Unpin>(
    rb: &mut RecvBuf<R>,
    sink: &FrameSink,
    dec: &mut Decoders,
    tx: &mpsc::Sender<ReaderEvent>,
) -> Result<bool, VncError> {
    let (w, h) = sink.size();
    rb.max = max_item(w, h);
    let event = match rb.next(parse_server_message).await? {
        ServerMessage::FramebufferUpdate { rects } => {
            update(rb, sink, dec, tx, rects).await?;
            ReaderEvent::UpdateDone
        }
        ServerMessage::SetColourMapEntries => {
            return Err(VncError::protocol("colour map requested for a true-colour format"));
        }
        ServerMessage::Bell => ReaderEvent::Bell,
        ServerMessage::CutText(text) => ReaderEvent::CutText(text),
        ServerMessage::CutTextTooLong { len } => {
            tracing::debug!(len, "vnc: oversized server cut text discarded");
            rb.discard(len).await?;
            return Ok(true);
        }
    };
    Ok(tx.send(event).await.is_ok())
}

async fn update<R: AsyncRead + Unpin>(
    rb: &mut RecvBuf<R>,
    sink: &FrameSink,
    dec: &mut Decoders,
    tx: &mpsc::Sender<ReaderEvent>,
    rects: u16,
) -> Result<(), VncError> {
    for _ in 0..rects {
        let (fw, fh) = sink.size();
        rb.max = max_item(fw, fh);
        let (frame, used) = rb.peek(|b| parse_rect(b, fw, fh)).await?;
        let op = dec.decode(&frame, rb.buffered());
        rb.consume(used);
        match op? {
            RectOp::Blit { rect, rgbx } => {
                sink.blit(rect, &rgbx, usize::from(rect.w) * 4, PixelOrder::Rgbx)
                    .map_err(|e| sink_err(&e))?;
            }
            RectOp::Fill { rect, rgba } => sink.fill(rect, rgba).map_err(|e| sink_err(&e))?,
            RectOp::Copy { rect, src_x, src_y } => {
                sink.copy(rect, src_x, src_y).map_err(|e| sink_err(&e))?;
            }
            RectOp::Resize { w, h, screen } => {
                if let Some(s) = screen {
                    let _ = tx.send(ReaderEvent::ExtDesktop(s)).await;
                }
                // The initial ExtendedDesktopSize reply repeats the current size: resizing
                // would clear the framebuffer for nothing.
                if (w, h) != sink.size() {
                    sink.resize(w, h).map_err(|e| sink_err(&e))?;
                    let _ = tx.send(ReaderEvent::Resized { w, h }).await;
                }
            }
            RectOp::ExtDesktopRefused { screen } => {
                if let Some(s) = screen {
                    let _ = tx.send(ReaderEvent::ExtDesktop(s)).await;
                }
            }
            RectOp::Cursor(c) => sink.cursor(c),
            RectOp::QemuExtKey => {
                let _ = tx.send(ReaderEvent::QemuExtKey).await;
            }
            RectOp::LastRect => break,
            RectOp::Nothing => {}
        }
    }
    Ok(())
}
