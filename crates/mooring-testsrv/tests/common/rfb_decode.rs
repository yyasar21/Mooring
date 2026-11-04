//! Reference ZRLE / Tight decoders for RGBX (CPIXEL = TPIXEL = R, G, B). Test-only: they
//! check the server's encoders, they are not the product decoders.

use flate2::{Decompress, FlushDecompress};
use mooring_testsrv::rfb::Rect;
use tokio::io::AsyncReadExt;

use super::rfb_client::{err, Io, Res};

pub struct Inflaters {
    zrle: Decompress,
    tight: [Decompress; 4],
    /// ZRLE tile sub-encodings and Tight (control byte, filter) seen, for coverage asserts.
    pub zrle_subs: Vec<u8>,
    pub tight_kinds: Vec<(u8, u8)>,
}

impl Inflaters {
    pub fn new() -> Self {
        let d = || Decompress::new(true);
        Self {
            zrle: d(),
            tight: [d(), d(), d(), d()],
            zrle_subs: Vec::new(),
            tight_kinds: Vec::new(),
        }
    }
}

fn inflate(d: &mut Decompress, input: &[u8], limit: usize) -> Res<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 4 + 1024);
    let start = d.total_in();
    loop {
        let used = usize::try_from(d.total_in() - start).map_err(err)?;
        if out.capacity() - out.len() < 1024 {
            out.reserve(out.capacity());
        }
        let before = out.len();
        d.decompress_vec(&input[used..], &mut out, FlushDecompress::Sync).map_err(err)?;
        if out.len() > limit {
            return Err("inflate limit".to_owned());
        }
        let used = usize::try_from(d.total_in() - start).map_err(err)?;
        if used == input.len() && out.len() - before < out.capacity() - before {
            return Ok(out);
        }
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Res<&[u8]> {
        let s = self.b.get(self.pos..self.pos + n).ok_or("truncated tile data")?;
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }

    fn px(&mut self) -> Res<[u8; 4]> {
        let p = self.take(3)?;
        Ok([p[0], p[1], p[2], 255])
    }

    fn run(&mut self) -> Res<usize> {
        let mut n = 1;
        loop {
            let b = self.u8()?;
            n += usize::from(b);
            if b != 255 {
                return Ok(n);
            }
        }
    }
}

fn put_tile(out: &mut [u8], rw: u16, t: Rect, origin: Rect, px: &[[u8; 4]]) {
    for (i, p) in px.iter().enumerate() {
        let x = usize::from(t.x - origin.x) + i % usize::from(t.w);
        let y = usize::from(t.y - origin.y) + i / usize::from(t.w);
        let o = (y * usize::from(rw) + x) * 4;
        out[o..o + 4].copy_from_slice(p);
    }
}

fn unpack(c: &mut Cursor<'_>, w: u16, h: u16, bits: u8, pal: &[[u8; 4]]) -> Res<Vec<[u8; 4]>> {
    let mut v = Vec::new();
    let row_bytes = (usize::from(w) * usize::from(bits)).div_ceil(8);
    for _ in 0..h {
        let row = c.take(row_bytes)?;
        for x in 0..usize::from(w) {
            let bit = x * usize::from(bits);
            let idx = (row[bit / 8] >> (8 - usize::from(bits) - bit % 8)) & ((1 << bits) - 1);
            v.push(*pal.get(usize::from(idx)).ok_or("palette index")?);
        }
    }
    Ok(v)
}

pub async fn read_zrle(io: &mut Box<dyn Io>, inf: &mut Inflaters, r: Rect) -> Res<Vec<u8>> {
    let len = io.read_u32().await.map_err(err)?;
    if len > 64 << 20 {
        return Err(format!("ZRLE length {len}"));
    }
    let mut z = vec![0u8; len as usize];
    io.read_exact(&mut z).await.map_err(err)?;
    let data = inflate(&mut inf.zrle, &z, 64 << 20)?;
    let mut c = Cursor { b: &data, pos: 0 };
    let mut out = vec![0u8; usize::from(r.w) * usize::from(r.h) * 4];
    let mut ty = r.y;
    while ty < r.y + r.h {
        let th = 64.min(r.y + r.h - ty);
        let mut tx = r.x;
        while tx < r.x + r.w {
            let tw = 64.min(r.x + r.w - tx);
            let t = Rect::new(tx, ty, tw, th);
            let n = usize::from(tw) * usize::from(th);
            let sub = c.u8()?;
            inf.zrle_subs.push(sub);
            let px: Vec<[u8; 4]> = match sub {
                0 => (0..n).map(|_| c.px()).collect::<Res<_>>()?,
                1 => vec![c.px()?; n],
                2..=16 => {
                    let pal: Vec<_> = (0..sub).map(|_| c.px()).collect::<Res<_>>()?;
                    let bits = match sub {
                        2 => 1,
                        3 | 4 => 2,
                        _ => 4,
                    };
                    unpack(&mut c, tw, th, bits, &pal)?
                }
                128 => {
                    let mut v = Vec::with_capacity(n);
                    while v.len() < n {
                        let p = c.px()?;
                        let k = c.run()?;
                        v.extend(std::iter::repeat_n(p, k));
                    }
                    v
                }
                130..=255 => {
                    let pal: Vec<_> = (0..sub - 128).map(|_| c.px()).collect::<Res<_>>()?;
                    let mut v = Vec::with_capacity(n);
                    while v.len() < n {
                        let i = c.u8()?;
                        let p = *pal.get(usize::from(i & 0x7F)).ok_or("palette index")?;
                        let k = if i & 0x80 != 0 { c.run()? } else { 1 };
                        v.extend(std::iter::repeat_n(p, k));
                    }
                    v
                }
                s => return Err(format!("ZRLE subencoding {s}")),
            };
            if px.len() != n {
                return Err("ZRLE run overflow".to_owned());
            }
            put_tile(&mut out, r.w, t, r, &px);
            tx += tw;
        }
        ty += th;
    }
    Ok(out)
}

async fn compact_len(io: &mut Box<dyn Io>) -> Res<usize> {
    let mut len = 0usize;
    for shift in [0, 7, 14] {
        let b = io.read_u8().await.map_err(err)?;
        if shift == 14 {
            return Ok(len | (usize::from(b) << 14));
        }
        len |= usize::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(len)
}

pub async fn read_tight(io: &mut Box<dyn Io>, inf: &mut Inflaters, r: Rect) -> Res<Vec<u8>> {
    let n = usize::from(r.w) * usize::from(r.h);
    let ctl = io.read_u8().await.map_err(err)?;
    for s in 0..4 {
        if ctl & (1 << s) != 0 {
            inf.tight[s] = Decompress::new(true);
        }
    }
    let kind = ctl >> 4;
    if kind == 8 {
        inf.tight_kinds.push((ctl, 0));
        let mut p = [0u8; 3];
        io.read_exact(&mut p).await.map_err(err)?;
        return Ok([p[0], p[1], p[2], 255].repeat(n));
    }
    if kind > 7 {
        return Err(format!("Tight compression control {ctl:#04x}"));
    }
    let stream = usize::from(kind & 3);
    let filter = if kind & 4 != 0 { io.read_u8().await.map_err(err)? } else { 0 };
    inf.tight_kinds.push((ctl, filter));
    let mut pal = Vec::new();
    let size = match filter {
        0 | 2 => n * 3,
        1 => {
            let count = usize::from(io.read_u8().await.map_err(err)?) + 1;
            for _ in 0..count {
                let mut p = [0u8; 3];
                io.read_exact(&mut p).await.map_err(err)?;
                pal.push([p[0], p[1], p[2], 255]);
            }
            if count == 2 {
                usize::from(r.h) * usize::from(r.w).div_ceil(8)
            } else {
                n
            }
        }
        f => return Err(format!("Tight filter {f}")),
    };
    let data = if size < 12 {
        let mut d = vec![0u8; size];
        io.read_exact(&mut d).await.map_err(err)?;
        d
    } else {
        let len = compact_len(io).await?;
        let mut z = vec![0u8; len];
        io.read_exact(&mut z).await.map_err(err)?;
        inflate(&mut inf.tight[stream], &z, 64 << 20)?
    };
    if data.len() != size {
        return Err(format!("Tight data {} != {size}", data.len()));
    }
    let mut c = Cursor { b: &data, pos: 0 };
    let px: Vec<[u8; 4]> = match filter {
        0 => (0..n).map(|_| c.px()).collect::<Res<_>>()?,
        1 if pal.len() == 2 => unpack(&mut c, r.w, r.h, 1, &pal)?,
        1 => data
            .iter()
            .map(|i| pal.get(usize::from(*i)).copied().ok_or("index"))
            .collect::<Result<_, _>>()?,
        _ => {
            let w = usize::from(r.w);
            let mut v: Vec<[u8; 4]> = Vec::with_capacity(n);
            for i in 0..n {
                let (x, y) = (i % w, i / w);
                let mut p = [0u8, 0, 0, 255];
                for ch in 0..3 {
                    let left = if x > 0 { i32::from(v[i - 1][ch]) } else { 0 };
                    let up = if y > 0 { i32::from(v[i - w][ch]) } else { 0 };
                    let ul = if x > 0 && y > 0 { i32::from(v[i - w - 1][ch]) } else { 0 };
                    let pred = (left + up - ul).clamp(0, 255);
                    p[ch] = ((pred + i32::from(data[i * 3 + ch])) & 0xFF).to_le_bytes()[0];
                }
                v.push(p);
            }
            v
        }
    };
    Ok(px.concat())
}
