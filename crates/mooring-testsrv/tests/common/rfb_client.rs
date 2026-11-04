//! Minimal RFB 3.8 verification client for the test server's self-tests. NOT the product
//! client (that is `mooring-proto-vnc`, ADR-0012): it trusts any certificate, has no caps
//! beyond what the tests need, and always asks for RGBX (32 bpp, shifts 0/8/16).

use std::net::SocketAddr;

use mooring_testsrv::rfb::{vnc_auth_response, PixelFormat, Rect};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::rfb_decode::{read_tight, read_zrle, Inflaters};
use super::tls::client_config;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type Res<T> = Result<T, String>;

pub fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// How the client authenticates.
#[derive(Debug, Clone)]
pub enum Auth {
    None,
    Vnc(String),
    /// VeNCrypt subtype code plus the credential its inner auth needs.
    VeNCrypt {
        sub: u32,
        password: Option<String>,
        plain: Option<(String, String)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMsg {
    Update(Vec<(Rect, i32)>),
    CutText(Vec<u8>),
}

pub struct Client {
    io: Box<dyn Io>,
    pub width: u16,
    pub height: u16,
    pub name_len: usize,
    pub fb: Vec<u8>,
    pub security_types: Vec<u8>,
    /// Leaf certificate DER when VeNCrypt TLS ran.
    pub peer_cert: Option<Vec<u8>>,
    pub inflaters: Inflaters,
}

async fn read_reason(io: &mut Box<dyn Io>) -> Res<String> {
    let len = io.read_u32().await.map_err(err)?;
    if len > 1 << 20 {
        return Err(format!("reason of {len} bytes"));
    }
    let mut b = vec![0u8; len as usize];
    io.read_exact(&mut b).await.map_err(err)?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

impl Client {
    pub async fn connect(addr: SocketAddr, auth: Auth) -> Res<Self> {
        let tcp = TcpStream::connect(addr).await.map_err(err)?;
        let mut io: Box<dyn Io> = Box::new(tcp);
        let mut version = [0u8; 12];
        io.read_exact(&mut version).await.map_err(err)?;
        if &version != b"RFB 003.008\n" {
            return Err(format!("server version {:?}", String::from_utf8_lossy(&version)));
        }
        io.write_all(b"RFB 003.008\n").await.map_err(err)?;
        let n = io.read_u8().await.map_err(err)?;
        if n == 0 {
            return Err(format!("no security types: {}", read_reason(&mut io).await?));
        }
        let mut types = vec![0u8; usize::from(n)];
        io.read_exact(&mut types).await.map_err(err)?;
        let wanted = match &auth {
            Auth::None => 1,
            Auth::Vnc(_) => 2,
            Auth::VeNCrypt { .. } => 19,
        };
        if !types.contains(&wanted) {
            return Err(format!("type {wanted} not offered: {types:?}"));
        }
        io.write_all(&[wanted]).await.map_err(err)?;
        let mut peer_cert = None;
        match &auth {
            Auth::None => {}
            Auth::Vnc(pw) => vnc_answer(&mut io, pw).await?,
            Auth::VeNCrypt { sub, password, plain } => {
                let (tls_io, cert) =
                    vencrypt(io, *sub, password.as_deref(), plain.as_ref()).await?;
                io = tls_io;
                peer_cert = cert;
            }
        }
        if io.read_u32().await.map_err(err)? != 0 {
            return Err(format!("security failure: {}", read_reason(&mut io).await?));
        }
        io.write_all(&[1]).await.map_err(err)?; // shared
        let width = io.read_u16().await.map_err(err)?;
        let height = io.read_u16().await.map_err(err)?;
        let mut pf = [0u8; 16];
        io.read_exact(&mut pf).await.map_err(err)?;
        let name = read_reason(&mut io).await?;
        let mut c = Self {
            io,
            width,
            height,
            name_len: name.len(),
            fb: vec![0; usize::from(width) * usize::from(height) * 4],
            security_types: types,
            peer_cert,
            inflaters: Inflaters::new(),
        };
        let mut msg = vec![0, 0, 0, 0];
        msg.extend_from_slice(&PixelFormat::RGBX.to_bytes());
        c.io.write_all(&msg).await.map_err(err)?;
        Ok(c)
    }

    pub async fn set_encodings(&mut self, list: &[i32]) -> Res<()> {
        let mut msg = vec![2, 0];
        msg.extend_from_slice(&u16::try_from(list.len()).map_err(err)?.to_be_bytes());
        for e in list {
            msg.extend_from_slice(&e.to_be_bytes());
        }
        self.io.write_all(&msg).await.map_err(err)
    }

    pub async fn request(&mut self, incremental: bool) -> Res<()> {
        let mut msg = vec![3, u8::from(incremental)];
        for v in [0, 0, self.width, self.height] {
            msg.extend_from_slice(&v.to_be_bytes());
        }
        self.io.write_all(&msg).await.map_err(err)
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) -> Res<()> {
        self.io.write_all(bytes).await.map_err(err)
    }

    /// Reads `n` raw bytes (for knob tests that inspect the wire).
    pub async fn read_bytes(&mut self, n: usize) -> Res<Vec<u8>> {
        let mut b = vec![0u8; n];
        self.io.read_exact(&mut b).await.map_err(err)?;
        Ok(b)
    }

    pub async fn key(&mut self, down: bool, keysym: u32) -> Res<()> {
        let mut m = vec![4, u8::from(down), 0, 0];
        m.extend_from_slice(&keysym.to_be_bytes());
        self.send_raw(&m).await
    }

    pub async fn pointer(&mut self, mask: u8, x: u16, y: u16) -> Res<()> {
        let mut m = vec![5, mask];
        m.extend_from_slice(&x.to_be_bytes());
        m.extend_from_slice(&y.to_be_bytes());
        self.send_raw(&m).await
    }

    pub async fn cut_text(&mut self, latin1: &[u8]) -> Res<()> {
        let mut m = vec![6, 0, 0, 0];
        m.extend_from_slice(&u32::try_from(latin1.len()).map_err(err)?.to_be_bytes());
        m.extend_from_slice(latin1);
        self.send_raw(&m).await
    }

    pub async fn set_desktop_size(&mut self, w: u16, h: u16) -> Res<()> {
        let mut m = vec![251, 0];
        m.extend_from_slice(&w.to_be_bytes());
        m.extend_from_slice(&h.to_be_bytes());
        m.extend_from_slice(&[1, 0]);
        m.extend_from_slice(&[0; 4]); // id
        for v in [0u16, 0, w, h] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&[0; 4]); // flags
        self.send_raw(&m).await
    }

    /// Reads one server message, decoding update rects into `fb`.
    pub async fn read(&mut self) -> Res<ServerMsg> {
        match self.io.read_u8().await.map_err(err)? {
            0 => {
                let _pad = self.io.read_u8().await.map_err(err)?;
                let n = self.io.read_u16().await.map_err(err)?;
                let mut rects = Vec::new();
                for _ in 0..n {
                    let r = Rect::new(
                        self.io.read_u16().await.map_err(err)?,
                        self.io.read_u16().await.map_err(err)?,
                        self.io.read_u16().await.map_err(err)?,
                        self.io.read_u16().await.map_err(err)?,
                    );
                    let enc = self.io.read_i32().await.map_err(err)?;
                    rects.push((r, enc));
                    if enc == -224 {
                        break;
                    }
                    self.rect(r, enc).await?;
                }
                Ok(ServerMsg::Update(rects))
            }
            3 => {
                let mut pad = [0u8; 3];
                self.io.read_exact(&mut pad).await.map_err(err)?;
                let len = self.io.read_u32().await.map_err(err)?;
                if len > 1 << 20 {
                    return Err(format!("ServerCutText of {len} bytes"));
                }
                let mut t = vec![0u8; len as usize];
                self.io.read_exact(&mut t).await.map_err(err)?;
                Ok(ServerMsg::CutText(t))
            }
            t => Err(format!("unexpected server message {t}")),
        }
    }

    /// Reads messages until an update arrives (cut text is skipped).
    pub async fn read_update(&mut self) -> Res<Vec<(Rect, i32)>> {
        loop {
            if let ServerMsg::Update(r) = self.read().await? {
                return Ok(r);
            }
        }
    }

    fn check(&self, r: Rect) -> Res<()> {
        if u32::from(r.x) + u32::from(r.w) > u32::from(self.width)
            || u32::from(r.y) + u32::from(r.h) > u32::from(self.height)
        {
            return Err(format!("rect {r:?} outside {}x{}", self.width, self.height));
        }
        Ok(())
    }

    fn put(&mut self, r: Rect, rgba: &[u8]) {
        let row = usize::from(r.w) * 4;
        for (i, y) in (r.y..r.y + r.h).enumerate() {
            let o = (usize::from(y) * usize::from(self.width) + usize::from(r.x)) * 4;
            self.fb[o..o + row].copy_from_slice(&rgba[i * row..(i + 1) * row]);
        }
    }

    async fn rect(&mut self, r: Rect, enc: i32) -> Res<()> {
        match enc {
            -223 | -308 => {
                if enc == -308 {
                    let n = self.io.read_u8().await.map_err(err)?;
                    let mut skip = vec![0u8; 3 + usize::from(n) * 16];
                    self.io.read_exact(&mut skip).await.map_err(err)?;
                }
                if enc == -223 || r.y == 0 {
                    self.width = r.w;
                    self.height = r.h;
                    self.fb = vec![0; usize::from(r.w) * usize::from(r.h) * 4];
                }
                return Ok(());
            }
            -258 => return Ok(()),
            _ => {}
        }
        self.check(r)?;
        let n = usize::from(r.w) * usize::from(r.h);
        let rgba = match enc {
            0 => {
                let mut raw = vec![0u8; n * 4];
                self.io.read_exact(&mut raw).await.map_err(err)?;
                raw.chunks_exact_mut(4).for_each(|p| p[3] = 255);
                raw
            }
            1 => {
                let (sx, sy) = (
                    self.io.read_u16().await.map_err(err)?,
                    self.io.read_u16().await.map_err(err)?,
                );
                let src = Rect::new(sx, sy, r.w, r.h);
                self.check(src)?;
                let mut block = Vec::with_capacity(n * 4);
                for y in sy..sy + r.h {
                    let o = (usize::from(y) * usize::from(self.width) + usize::from(sx)) * 4;
                    block.extend_from_slice(&self.fb[o..o + usize::from(r.w) * 4]);
                }
                block
            }
            16 => read_zrle(&mut self.io, &mut self.inflaters, r).await?,
            7 => read_tight(&mut self.io, &mut self.inflaters, r).await?,
            e => return Err(format!("unsupported encoding {e}")),
        };
        self.put(r, &rgba);
        Ok(())
    }
}

async fn vnc_answer(io: &mut Box<dyn Io>, pw: &str) -> Res<()> {
    let mut challenge = [0u8; 16];
    io.read_exact(&mut challenge).await.map_err(err)?;
    io.write_all(&vnc_auth_response(pw.as_bytes(), &challenge)).await.map_err(err)
}

async fn vencrypt(
    mut io: Box<dyn Io>,
    sub: u32,
    password: Option<&str>,
    plain: Option<&(String, String)>,
) -> Res<(Box<dyn Io>, Option<Vec<u8>>)> {
    let mut v = [0u8; 2];
    io.read_exact(&mut v).await.map_err(err)?;
    io.write_all(&[0, 2]).await.map_err(err)?;
    if io.read_u8().await.map_err(err)? != 0 {
        return Err("VeNCrypt version refused".to_owned());
    }
    let n = io.read_u8().await.map_err(err)?;
    let mut subs = Vec::new();
    for _ in 0..n {
        subs.push(io.read_u32().await.map_err(err)?);
    }
    if !subs.contains(&sub) {
        return Err(format!("subtype {sub} not offered: {subs:?}"));
    }
    io.write_all(&sub.to_be_bytes()).await.map_err(err)?;
    if io.read_u8().await.map_err(err)? != 1 {
        return Err("subtype not accepted".to_owned());
    }
    let mut cert = None;
    if sub != 256 {
        let (config, verifier) = client_config();
        let name = rustls::pki_types::ServerName::try_from("example.test").map_err(err)?;
        let tls = tokio_rustls::TlsConnector::from(config).connect(name, io).await.map_err(err)?;
        cert.clone_from(&verifier.leaf.lock().expect("leaf"));
        io = Box::new(tls);
    }
    match sub {
        258 | 261 => vnc_answer(&mut io, password.unwrap_or("")).await?,
        256 | 259 | 262 => {
            let (u, p) = plain.cloned().unwrap_or_default();
            let mut m = u32::try_from(u.len()).map_err(err)?.to_be_bytes().to_vec();
            m.extend_from_slice(&u32::try_from(p.len()).map_err(err)?.to_be_bytes());
            m.extend_from_slice(u.as_bytes());
            m.extend_from_slice(p.as_bytes());
            io.write_all(&m).await.map_err(err)?;
        }
        _ => {}
    }
    Ok((io, cert))
}
