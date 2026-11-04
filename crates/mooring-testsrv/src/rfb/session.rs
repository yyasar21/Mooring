//! Post-ServerInit message loop: client messages in, framebuffer updates and cut text out.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf};
use tokio::sync::{broadcast, mpsc};

use super::conn::{BoxIo, HsError};
use super::encode::{Encoded, Encoders};
use super::framebuffer::{Framebuffer, Rect};
use super::pixel::PixelFormat;
use super::{encoding, lock, Event, KeyRecord, RfbConfig, Shared};

/// Cap on ClientCutText (ADR-0012 uses the same 1 MiB for ServerCutText).
const MAX_CUT_TEXT: u32 = 1 << 20;

enum ClientMsg {
    PixelFormat(PixelFormat),
    Encodings(Vec<i32>),
    Request { incremental: bool, rect: Rect },
    SetDesktopSize(u16, u16),
}

/// What the writer still owes the client.
#[derive(Default)]
struct Pending {
    request: Option<(bool, Rect)>,
    dirty: Rect,
    copies: Vec<(Rect, u16, u16)>,
    /// `Some(reason)` = a size change to announce (0 = server, 1 = client request), with status.
    resize: Option<(u16, u16)>,
    first_update: bool,
}

pub(crate) async fn run(shared: Arc<Shared>, cfg: &RfbConfig, io: BoxIo) -> Result<(), HsError> {
    let (rd, mut wr) = tokio::io::split(io);
    let (tx, mut rx) = mpsc::channel(256);
    let mut events = shared.events.subscribe();
    let reader = tokio::spawn(read_loop(Arc::clone(&shared), rd, tx));
    let mut enc = Encoders::new(cfg.zrle_mode, cfg.tight_mode);
    let mut pf = PixelFormat::SERVER_DEFAULT;
    let mut encodings: Vec<i32> = Vec::new();
    let mut p = Pending { first_update: true, ..Pending::default() };
    let result = loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                None => break Ok(()),
                Some(ClientMsg::PixelFormat(f)) => pf = f,
                Some(ClientMsg::Encodings(e)) => encodings = e,
                Some(ClientMsg::Request { incremental, rect }) => p.request = Some((incremental, rect)),
                Some(ClientMsg::SetDesktopSize(w, h)) => {
                    let allow = lock(&shared.config).allow_client_resize;
                    if allow && w > 0 && h > 0 {
                        *lock(&shared.fb) = Framebuffer::synthetic(w, h);
                        p.resize = Some((1, 0));
                    } else {
                        p.resize = Some((1, 1));
                    }
                }
            },
            ev = events.recv() => match ev {
                Ok(Event::Dirty(r)) => p.dirty = p.dirty.union(&r),
                Ok(Event::Copy { dst, src_x, src_y }) => p.copies.push((dst, src_x, src_y)),
                Ok(Event::Resized) => p.resize = Some((0, 0)),
                Ok(Event::CutText(text)) => {
                    let lie = lock(&shared.config).knobs.lie_cut_text_length;
                    let len = lie.unwrap_or_else(|| u32::try_from(text.len()).unwrap_or(u32::MAX));
                    let mut msg = vec![3, 0, 0, 0];
                    msg.extend_from_slice(&len.to_be_bytes());
                    msg.extend_from_slice(&text);
                    if let Err(e) = wr.write_all(&msg).await {
                        break Err(e.into());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => p.dirty = lock(&shared.fb).bounds(),
                Err(broadcast::error::RecvError::Closed) => break Ok(()),
            },
        }
        if let Some(update) = build_update(&shared, &mut enc, &pf, &encodings, &mut p) {
            if let Err(e) = wr.write_all(&update).await {
                break Err(e.into());
            }
            lock(&shared.stats).updates_sent += 1;
        }
    };
    reader.abort();
    result
}

fn pick_encoding(client: &[i32], force: Option<i32>) -> i32 {
    force.unwrap_or_else(|| {
        client
            .iter()
            .copied()
            .find(|e| matches!(*e, encoding::RAW | encoding::ZRLE | encoding::TIGHT))
            .unwrap_or(encoding::RAW)
    })
}

fn push_rect(out: &mut Vec<u8>, r: Rect, enc: i32, data: &[u8]) {
    for v in [r.x, r.y, r.w, r.h] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&enc.to_be_bytes());
    out.extend_from_slice(data);
}

fn eds_payload(w: u16, h: u16) -> Vec<u8> {
    let mut d = vec![1, 0, 0, 0];
    d.extend_from_slice(&0u32.to_be_bytes());
    for v in [0u16, 0, w, h] {
        d.extend_from_slice(&v.to_be_bytes());
    }
    d.extend_from_slice(&0u32.to_be_bytes());
    d
}

/// Assembles one FramebufferUpdate when a request is pending and there is something to send.
fn build_update(
    shared: &Shared,
    enc: &mut Encoders,
    pf: &PixelFormat,
    client: &[i32],
    p: &mut Pending,
) -> Option<Vec<u8>> {
    let (incremental, req) = p.request?;
    let knobs = lock(&shared.config).knobs.clone();
    enc.lie_zlib_length = knobs.lie_zlib_length;
    enc.tight_jpeg = knobs.tight_jpeg;
    let fb = lock(&shared.fb);
    let has = |e: i32| client.contains(&e);
    let mut rects: Vec<(Rect, i32, Vec<u8>)> = Vec::new();

    if p.first_update && has(encoding::QEMU_EXTENDED_KEY) {
        rects.push((Rect::default(), encoding::QEMU_EXTENDED_KEY, Vec::new()));
    }
    if let Some((reason, status)) = p.resize.take() {
        if has(encoding::EXTENDED_DESKTOP_SIZE) {
            let r = Rect::new(reason, status, fb.width, fb.height);
            rects.push((r, encoding::EXTENDED_DESKTOP_SIZE, eds_payload(fb.width, fb.height)));
        } else if has(encoding::DESKTOP_SIZE) && status == 0 {
            rects.push((Rect::new(0, 0, fb.width, fb.height), encoding::DESKTOP_SIZE, Vec::new()));
        }
        // After a size change the client must ask for the new screen; drop stale state.
        p.dirty = Rect::default();
        p.copies.clear();
    } else {
        if p.first_update && has(encoding::EXTENDED_DESKTOP_SIZE) {
            let r = Rect::new(0, 0, fb.width, fb.height);
            rects.push((r, encoding::EXTENDED_DESKTOP_SIZE, eds_payload(fb.width, fb.height)));
        }
        let mut region = if incremental { Rect::default() } else { req };
        if has(encoding::COPY_RECT) {
            for (dst, sx, sy) in p.copies.drain(..) {
                let mut d = sx.to_be_bytes().to_vec();
                d.extend_from_slice(&sy.to_be_bytes());
                rects.push((dst, encoding::COPY_RECT, d));
            }
        } else {
            for (dst, _, _) in p.copies.drain(..) {
                p.dirty = p.dirty.union(&dst);
            }
        }
        region = region.union(&p.dirty.intersect(&req)).intersect(&fb.bounds());
        if !region.is_empty() {
            let e = pick_encoding(client, knobs.force_encoding);
            for Encoded { rect, encoding, data } in enc.encode(&fb, region, e, pf) {
                rects.push((rect, encoding, data));
            }
            if region == p.dirty.intersect(&fb.bounds()) {
                p.dirty = Rect::default();
            }
        }
        if let Some(extra) = knobs.oversized_rect.filter(|_| !rects.is_empty()) {
            let w = 1 + extra;
            let r = Rect::new(fb.width.saturating_sub(1), 0, w, 1);
            rects.push((r, encoding::RAW, vec![0; usize::from(w) * pf.bytes_per_pixel()]));
        }
    }
    if rects.is_empty() {
        return None;
    }
    p.request = None;
    p.first_update = false;
    let announced = if knobs.use_last_rect {
        u16::MAX
    } else {
        u16::try_from(rects.len())
            .unwrap_or(u16::MAX)
            .saturating_add(knobs.missing_rects.unwrap_or(0))
    };
    let mut out = vec![0, 0];
    out.extend_from_slice(&announced.to_be_bytes());
    for (r, e, d) in &rects {
        push_rect(&mut out, *r, *e, d);
    }
    if knobs.use_last_rect {
        push_rect(&mut out, Rect::default(), encoding::LAST_RECT, &[]);
    }
    Some(out)
}

async fn read_loop(shared: Arc<Shared>, mut rd: ReadHalf<BoxIo>, tx: mpsc::Sender<ClientMsg>) {
    if let Err(e) = read_messages(&shared, &mut rd, &tx).await {
        if !matches!(&e, HsError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof) {
            lock(&shared.stats).errors.push(e.to_string());
        }
    }
}

async fn read_messages(
    shared: &Shared,
    rd: &mut ReadHalf<BoxIo>,
    tx: &mpsc::Sender<ClientMsg>,
) -> Result<(), HsError> {
    loop {
        let kind = rd.read_u8().await?;
        let msg = match kind {
            0 => {
                let mut b = [0u8; 19];
                rd.read_exact(&mut b).await?;
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&b[3..]);
                let pf = PixelFormat::from_bytes(&raw);
                lock(&shared.stats).pixel_formats.push(pf);
                if !pf.is_supported() {
                    return Err(HsError::Protocol(format!("unsupported pixel format {pf:?}")));
                }
                ClientMsg::PixelFormat(pf)
            }
            2 => {
                let _pad = rd.read_u8().await?;
                let n = rd.read_u16().await?;
                if n > 1024 {
                    return Err(HsError::Protocol(format!("SetEncodings with {n} entries")));
                }
                let mut list = Vec::with_capacity(usize::from(n));
                for _ in 0..n {
                    list.push(rd.read_i32().await?);
                }
                lock(&shared.stats).encodings.clone_from(&list);
                ClientMsg::Encodings(list)
            }
            3 => {
                let incremental = rd.read_u8().await? != 0;
                let rect = Rect::new(
                    rd.read_u16().await?,
                    rd.read_u16().await?,
                    rd.read_u16().await?,
                    rd.read_u16().await?,
                );
                lock(&shared.stats).update_requests += 1;
                ClientMsg::Request { incremental, rect }
            }
            4 => {
                let down = rd.read_u8().await? != 0;
                let _pad = rd.read_u16().await?;
                let keysym = rd.read_u32().await?;
                lock(&shared.stats).key_events.push(KeyRecord { down, keysym, qemu_keycode: None });
                continue;
            }
            5 => {
                let mask = rd.read_u8().await?;
                let (x, y) = (rd.read_u16().await?, rd.read_u16().await?);
                let mut stats = lock(&shared.stats);
                stats.pointer_events += 1;
                stats.last_pointer = Some((mask, x, y));
                continue;
            }
            6 => {
                let mut pad = [0u8; 3];
                rd.read_exact(&mut pad).await?;
                let len = rd.read_u32().await?;
                if len > MAX_CUT_TEXT {
                    return Err(HsError::Protocol(format!("ClientCutText of {len} bytes")));
                }
                let mut text = vec![0u8; len as usize];
                rd.read_exact(&mut text).await?;
                lock(&shared.stats).client_cut_text.push(text);
                continue;
            }
            251 => {
                let _pad = rd.read_u8().await?;
                let (w, h) = (rd.read_u16().await?, rd.read_u16().await?);
                let screens = rd.read_u8().await?;
                let _pad = rd.read_u8().await?;
                let mut skip = vec![0u8; usize::from(screens) * 16];
                rd.read_exact(&mut skip).await?;
                lock(&shared.stats).desktop_size_requests.push((w, h));
                ClientMsg::SetDesktopSize(w, h)
            }
            255 => {
                let sub = rd.read_u8().await?;
                if sub != 0 {
                    return Err(HsError::Protocol(format!("QEMU client message subtype {sub}")));
                }
                let down = rd.read_u16().await? != 0;
                let keysym = rd.read_u32().await?;
                let keycode = rd.read_u32().await?;
                let rec = KeyRecord { down, keysym, qemu_keycode: Some(keycode) };
                lock(&shared.stats).key_events.push(rec);
                continue;
            }
            other => return Err(HsError::Protocol(format!("unknown client message {other}"))),
        };
        if tx.send(msg).await.is_err() {
            return Ok(());
        }
    }
}
