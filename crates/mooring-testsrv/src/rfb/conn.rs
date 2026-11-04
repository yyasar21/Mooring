//! Per-connection RFB 3.8 handshake: version, security, SecurityResult, ClientInit, ServerInit.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::pixel::PixelFormat;
use super::{lock, session, vencrypt, RfbConfig, SecurityOffer, Shared};

/// Any byte stream the server talks over (TCP or TLS over TCP).
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type BoxIo = Box<dyn Io>;

#[derive(Debug)]
pub(crate) enum HsError {
    Io(std::io::Error),
    Protocol(String),
}

impl From<std::io::Error> for HsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for HsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

pub(crate) const VERSION_38: &[u8; 12] = b"RFB 003.008\n";

/// Writes `bytes`, one byte per `slow` delay when the slow-loris knob is on.
async fn send(io: &mut BoxIo, bytes: &[u8], slow: Option<Duration>) -> std::io::Result<()> {
    match slow {
        Some(d) => {
            for b in bytes {
                tokio::time::sleep(d).await;
                io.write_all(&[*b]).await?;
                io.flush().await?;
            }
            Ok(())
        }
        None => io.write_all(bytes).await,
    }
}

fn reason_bytes(reason: &str) -> Vec<u8> {
    let mut v = u32::try_from(reason.len()).unwrap_or(u32::MAX).to_be_bytes().to_vec();
    v.extend_from_slice(reason.as_bytes());
    v
}

/// Entry point for one accepted TCP connection.
pub(crate) async fn serve(shared: Arc<Shared>, tcp: TcpStream, index: u32) {
    let _ = tcp.set_nodelay(true);
    let cfg = lock(&shared.config).clone();
    let io: BoxIo = Box::new(tcp);
    let result = match handshake(&shared, &cfg, io, index).await {
        Ok(io) => session::run(Arc::clone(&shared), &cfg, io).await,
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        if !matches!(&e, HsError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof) {
            lock(&shared.stats).errors.push(e.to_string());
        }
    }
}

async fn handshake(
    shared: &Shared,
    cfg: &RfbConfig,
    mut io: BoxIo,
    index: u32,
) -> Result<BoxIo, HsError> {
    let slow = cfg.knobs.slow_loris;
    send(&mut io, cfg.knobs.version.as_ref().unwrap_or(VERSION_38), slow).await?;
    let mut client_version = [0u8; 12];
    io.read_exact(&mut client_version).await?;
    lock(&shared.stats).client_versions.push(String::from_utf8_lossy(&client_version).into_owned());
    if &client_version != VERSION_38 {
        return Err(HsError::Protocol("client did not answer RFB 003.008".to_owned()));
    }

    let strip = cfg.knobs.strip_tls_after.is_some_and(|n| index >= n);
    let offers: Vec<&SecurityOffer> = cfg
        .security
        .iter()
        .filter(|o| !(strip && matches!(o, SecurityOffer::VeNCrypt(_))))
        .collect();
    let types: Vec<u8> = offers.iter().map(|o| type_code(o)).collect();
    if types.is_empty() {
        let mut msg = vec![0];
        msg.extend_from_slice(&reason_bytes("no security types configured"));
        send(&mut io, &msg, slow).await?;
        return Err(HsError::Protocol("empty security list".to_owned()));
    }
    let mut list = vec![u8::try_from(types.len()).unwrap_or(u8::MAX)];
    list.extend_from_slice(&types);
    send(&mut io, &list, slow).await?;
    let chosen = io.read_u8().await?;
    let Some(offer) = offers.iter().find(|o| type_code(o) == chosen) else {
        lock(&shared.stats).chosen_security.push((chosen, None));
        return Err(HsError::Protocol(format!("client chose type {chosen}, not offered")));
    };

    let (mut io, sub, ok) = match offer {
        SecurityOffer::None => (io, None, true),
        SecurityOffer::VncAuth => {
            let ok = vencrypt::vnc_auth(&mut io, cfg).await?;
            (io, None, ok)
        }
        SecurityOffer::VeNCrypt(subs) => {
            let (io, sub, ok) = vencrypt::negotiate(io, cfg, subs, shared.tls.as_ref()).await?;
            (io, Some(sub), ok)
        }
        SecurityOffer::Other(t) => {
            return Err(HsError::Protocol(format!("type {t} has no handler")))
        }
    };
    lock(&shared.stats).chosen_security.push((chosen, sub));

    let failure = if ok {
        cfg.knobs.fail_auth_reason.clone()
    } else {
        Some("authentication failed".to_owned())
    };
    if let Some(reason) = failure {
        lock(&shared.stats).auth_failed += 1;
        let mut msg = 1u32.to_be_bytes().to_vec();
        msg.extend_from_slice(&reason_bytes(&reason));
        io.write_all(&msg).await?;
        io.flush().await?;
        return Err(HsError::Protocol(format!("auth failed: {reason}")));
    }
    lock(&shared.stats).auth_ok += 1;
    send(&mut io, &0u32.to_be_bytes(), slow).await?;

    let shared_flag = io.read_u8().await? != 0;
    lock(&shared.stats).shared_flags.push(shared_flag);

    let (w, h) = {
        let fb = lock(&shared.fb);
        (fb.width, fb.height)
    };
    let mut init = Vec::with_capacity(64);
    init.extend_from_slice(&w.to_be_bytes());
    init.extend_from_slice(&h.to_be_bytes());
    init.extend_from_slice(&PixelFormat::SERVER_DEFAULT.to_bytes());
    let name = match cfg.knobs.huge_name {
        Some(n) => "N".repeat(n as usize),
        None => cfg.name.clone(),
    };
    init.extend_from_slice(&reason_bytes(&name));
    send(&mut io, &init, slow).await?;
    io.flush().await?;
    Ok(io)
}

fn type_code(o: &SecurityOffer) -> u8 {
    match o {
        SecurityOffer::None => 1,
        SecurityOffer::VncAuth => 2,
        SecurityOffer::VeNCrypt(_) => 19,
        SecurityOffer::Other(t) => *t,
    }
}
