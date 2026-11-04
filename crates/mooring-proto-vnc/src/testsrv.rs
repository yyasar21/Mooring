//! A minimal in-process RFB 3.8 server for loopback tests (None, VNC auth, `VeNCrypt` X509
//! with an rcgen certificate). It answers every connection with the same script and forwards
//! what the client sends after its set-up messages.
//!
//! TODO(merge): replace with `crates/mooring-testsrv` (QA, in progress) once it lands.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::conn::Io;
use crate::handshake::PixelFormat;
use crate::security::vnc_auth_response;

/// What the stub server does.
#[derive(Clone, Default)]
pub(crate) struct SrvConfig {
    /// Security types offered.
    pub(crate) security: Vec<u8>,
    /// `VeNCrypt` subtypes offered.
    pub(crate) subtypes: Vec<u32>,
    /// Certificate (DER) and PKCS#8 key (DER) for `VeNCrypt`.
    pub(crate) tls: Option<(Vec<u8>, Vec<u8>)>,
    /// VNC password the server expects (`None` = accept any response).
    pub(crate) password: Option<Vec<u8>>,
    /// Framebuffer size.
    pub(crate) fb: (u16, u16),
    /// Messages sent after the client's set-up.
    pub(crate) script: Vec<Vec<u8>>,
}

pub(crate) struct Srv {
    pub(crate) addr: SocketAddr,
    /// Client bytes after set-up, per chunk.
    pub(crate) rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Number of TCP connections accepted.
    pub(crate) conns: Arc<std::sync::atomic::AtomicUsize>,
}

impl Srv {
    /// Collect client bytes until `pred` holds or 3 s pass.
    pub(crate) async fn until(&mut self, got: &mut Vec<u8>, pred: impl Fn(&[u8]) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while !pred(got) {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(chunk)) => got.extend_from_slice(&chunk),
                _ => return false,
            }
        }
        true
    }
}

pub(crate) async fn start(cfg: SrvConfig) -> Srv {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::unbounded_channel();
    let conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = Arc::clone(&conns);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (cfg, tx) = (cfg.clone(), tx.clone());
            tokio::spawn(async move {
                let _ = serve(sock, cfg, tx).await;
            });
        }
    });
    Srv { addr, rx, conns }
}

async fn read_n<S: AsyncRead + Unpin>(s: &mut S, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}

async fn vnc_auth<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    cfg: &SrvConfig,
) -> std::io::Result<bool> {
    let challenge: [u8; 16] = std::array::from_fn(|i| u8::try_from(i * 7 + 3).unwrap_or(0));
    s.write_all(&challenge).await?;
    let resp = read_n(s, 16).await?;
    Ok(cfg.password.as_ref().is_none_or(|p| resp == vnc_auth_response(p, &challenge)))
}

fn tls_acceptor(cert: &[u8], key: &[u8]) -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .expect("server cert");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

async fn serve(
    mut tcp: tokio::net::TcpStream,
    cfg: SrvConfig,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) -> std::io::Result<()> {
    tcp.write_all(b"RFB 003.008\n").await?;
    read_n(&mut tcp, 12).await?;
    let mut list = vec![u8::try_from(cfg.security.len()).unwrap_or(0)];
    list.extend_from_slice(&cfg.security);
    tcp.write_all(&list).await?;
    let choice = read_n(&mut tcp, 1).await?[0];
    let mut s: Box<dyn Io> = Box::new(tcp);
    let ok = match choice {
        1 => true,
        2 => vnc_auth(&mut s, &cfg).await?,
        19 => {
            s.write_all(&[0, 2]).await?;
            read_n(&mut s, 2).await?;
            s.write_all(&[0, u8::try_from(cfg.subtypes.len()).unwrap_or(0)]).await?;
            for t in &cfg.subtypes {
                s.write_all(&t.to_be_bytes()).await?;
            }
            let sub = u32::from_be_bytes(read_n(&mut s, 4).await?.try_into().unwrap_or([0; 4]));
            s.write_all(&[1]).await?;
            let (cert, key) = cfg.tls.clone().expect("tls config for VeNCrypt");
            let tls = tls_acceptor(&cert, &key).accept(s).await?;
            s = Box::new(tls);
            match sub {
                261 => vnc_auth(&mut s, &cfg).await?,
                262 => {
                    let lens = read_n(&mut s, 8).await?;
                    let u = u32::from_be_bytes([lens[0], lens[1], lens[2], lens[3]]);
                    let p = u32::from_be_bytes([lens[4], lens[5], lens[6], lens[7]]);
                    read_n(&mut s, usize::try_from(u + p).unwrap_or(0)).await?;
                    true
                }
                _ => true,
            }
        }
        _ => return Ok(()),
    };
    if !ok {
        let mut fail = vec![0, 0, 0, 1, 0, 0, 0, 12];
        fail.extend_from_slice(b"bad password");
        s.write_all(&fail).await?;
        return s.flush().await;
    }
    s.write_all(&[0, 0, 0, 0]).await?;
    read_n(&mut s, 1).await?; // ClientInit
    let mut init = Vec::new();
    init.extend_from_slice(&cfg.fb.0.to_be_bytes());
    init.extend_from_slice(&cfg.fb.1.to_be_bytes());
    init.extend_from_slice(&PixelFormat::RGBX.encode());
    init.extend_from_slice(&[0, 0, 0, 4]);
    init.extend_from_slice(b"test");
    s.write_all(&init).await?;
    s.flush().await?;
    // Client set-up: SetPixelFormat, SetEncodings, the first FramebufferUpdateRequest.
    let spf = read_n(&mut s, 20).await?;
    assert_eq!(spf[0], 0, "SetPixelFormat first");
    let head = read_n(&mut s, 4).await?;
    assert_eq!(head[0], 2, "SetEncodings second");
    read_n(&mut s, usize::from(u16::from_be_bytes([head[2], head[3]])) * 4).await?;
    let fbur = read_n(&mut s, 10).await?;
    assert_eq!(&fbur[..2], &[3, 0], "first request is non-incremental");
    for m in &cfg.script {
        s.write_all(m).await?;
    }
    s.flush().await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = s.read(&mut buf).await?;
        if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
            return Ok(());
        }
    }
}

/// `FramebufferUpdate` header.
pub(crate) fn update(rects: u16) -> Vec<u8> {
    let mut m = vec![0, 0];
    m.extend_from_slice(&rects.to_be_bytes());
    m
}

/// One rectangle.
#[allow(clippy::many_single_char_names)]
pub(crate) fn rect(x: u16, y: u16, w: u16, h: u16, enc: i32, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    for v in [x, y, w, h] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m.extend_from_slice(&enc.to_be_bytes());
    m.extend_from_slice(payload);
    m
}

/// A self-signed certificate and PKCS#8 key for `name`.
pub(crate) fn cert(name: &str) -> (Vec<u8>, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("rcgen");
    (ck.cert.der().to_vec(), ck.signing_key.serialize_der())
}
