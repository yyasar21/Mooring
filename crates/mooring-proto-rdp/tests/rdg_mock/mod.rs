//! A mock RD Gateway (ADR-0027 test plan): TLS + the HTTP upgrade with NTLM (`sspi` server
//! side) or Basic + RFC 6455 framing + MS-TSGU handshake / tunnel / authorize / channel,
//! then a relay to the in-process `IronRDP` test server. Hostile modes misbehave on purpose.

#![allow(clippy::many_single_char_names)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ironrdp_connector::sspi::{
    AuthIdentity, BufferType, CredentialUse, DataRepresentation, Ntlm, SecurityBuffer,
    SecurityStatus, ServerRequestFlags, Sspi, SspiImpl, Username,
};
use mooring_proto_rdp::gateway::http::{accept_key, decode_base64, encode_base64};
use mooring_proto_rdp::gateway::pdu::{self, server, ty};
use mooring_proto_rdp::gateway::ws::{self, Decoder, Frame};
use mooring_testsrv::tls::TestCert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How the mock behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// NTLM, then the full tunnel and relay.
    Ntlm,
    /// Offers Basic only (401 to the NTLM negotiate).
    BasicOnly,
    /// `404` on the WebSocket path (an RPC-over-HTTP-only gateway).
    NotFound,
    /// `CHANNEL_RESPONSE` with an error.
    ChannelRefused,
    /// A packet header announcing more than the cap after the handshake request.
    Oversized,
    /// `DATA` instead of `HANDSHAKE_RESPONSE`.
    OutOfOrder,
    /// `101` with a wrong `Sec-WebSocket-Accept`.
    BadAccept,
    /// `101` without `Sec-WebSocket-Accept`.
    NoAccept,
    /// NTLM with Extended Protection expecting another certificate's channel binding (a
    /// relay through a different TLS session): the `AUTHENTICATE` must be refused.
    WrongBinding,
}

pub const GW_USER: &str = "alice";
pub const GW_PASS: &str = "gateway pass";

/// What the gateway saw (for "the target was never contacted" checks).
#[derive(Debug, Default)]
pub struct Log {
    pub requests: usize,
    pub channels: Vec<(String, u16)>,
    pub auth_ok: bool,
}

pub struct Gateway {
    pub addr: SocketAddr,
    pub cert: TestCert,
    pub log: Arc<Mutex<Log>>,
}

pub async fn start(mode: Mode, rdp: SocketAddr) -> Gateway {
    let cert = TestCert::generate(&["127.0.0.1"]).expect("cert");
    let acceptor = tokio_rustls::TlsAcceptor::from(cert.server_config().expect("cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let log = Arc::new(Mutex::new(Log::default()));
    let l2 = Arc::clone(&log);
    let leaf: Arc<[u8]> = cert.cert_der().to_vec().into();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, log, leaf) = (acceptor.clone(), Arc::clone(&l2), Arc::clone(&leaf));
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = Box::pin(serve(tls, mode, rdp, log, &leaf)).await;
                }
            });
        }
    });
    Gateway { addr, cert, log }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(buf[..i + 4].to_vec()).ok()?;
            buf.drain(..i + 4);
            return Some(head);
        }
        let mut tmp = [0u8; 4096];
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn authorization(head: &str) -> Option<(String, String)> {
    head.split("\r\n").find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case("authorization").then(|| {
            let (s, t) = v.trim().split_once(' ').unwrap_or((v.trim(), ""));
            (s.to_owned(), t.to_owned())
        })
    })
}

fn key(head: &str) -> String {
    head.split("\r\n")
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap_or_default()
        .to_owned()
}

struct NtlmServer {
    ntlm: Ntlm,
    handle: Option<ironrdp_connector::sspi::AuthIdentityBuffers>,
}

/// RFC 5929 `tls-server-end-point` for a SHA-256-signed leaf (the rcgen default, P-256).
fn binding(der: &[u8]) -> Vec<u8> {
    let mut b = b"tls-server-end-point:".to_vec();
    b.extend_from_slice(&mooring_core::known_certs::fingerprint(der));
    b
}

impl NtlmServer {
    /// Extended Protection on: the server checks `MsvAvChannelBindings` against `cbt`.
    fn new(cbt: &[u8]) -> Self {
        let mut ntlm = Ntlm::new();
        ntlm.set_channel_bindings(cbt);
        let identity = AuthIdentity {
            username: Username::new(GW_USER, None).expect("user"),
            password: GW_PASS.to_owned().into(),
        };
        let acq = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Inbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .expect("acquire");
        Self { ntlm, handle: acq.credentials_handle }
    }

    /// `Ok(Some(token))` to send back, `Ok(None)` when done, `Err` on a refused login.
    fn step(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        let mut input = vec![SecurityBuffer::new(token.to_vec(), BufferType::Token)];
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = self
            .ntlm
            .accept_security_context()
            .with_credentials_handle(&mut self.handle)
            .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let r = self.ntlm.accept_security_context_impl(builder).map_err(|_| ())?;
        let r = { r }.resolve_to_result().map_err(|_| ())?;
        if matches!(r.status, SecurityStatus::CompleteAndContinue | SecurityStatus::CompleteNeeded)
        {
            self.ntlm.complete_auth_token(&mut output).map_err(|_| ())?;
        }
        if r.status == SecurityStatus::ContinueNeeded {
            return Ok(output.pop().map(|b| b.buffer));
        }
        Ok(None)
    }
}

const UNAUTH: &str = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\n";

async fn upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    mode: Mode,
    log: &Mutex<Log>,
    leaf: &[u8],
) -> Option<()> {
    let cbt = if mode == Mode::WrongBinding {
        binding(TestCert::generate(&["127.0.0.1"]).expect("cert").cert_der())
    } else {
        binding(leaf)
    };
    let mut ntlm = NtlmServer::new(&cbt);
    loop {
        let head = read_head(s, buf).await?;
        log.lock().expect("log").requests += 1;
        if mode == Mode::NotFound {
            s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await.ok()?;
            continue;
        }
        let ok = match (authorization(&head), mode) {
            (Some((scheme, t)), Mode::BasicOnly) if scheme == "Basic" => {
                decode_base64(&t, 256).as_deref() == Some(format!("{GW_USER}:{GW_PASS}").as_bytes())
            }
            (Some((scheme, t)), m) if scheme == "NTLM" && m != Mode::BasicOnly => {
                let token = decode_base64(&t, 8192)?;
                match ntlm.step(&token) {
                    Ok(Some(challenge)) => {
                        let h = format!(
                            "{UNAUTH}WWW-Authenticate: NTLM {}\r\n\r\nnope",
                            encode_base64(&challenge)
                        );
                        s.write_all(h.as_bytes()).await.ok()?;
                        continue;
                    }
                    Ok(None) => true,
                    Err(()) => false,
                }
            }
            _ => false,
        };
        if !ok {
            let offer = if mode == Mode::BasicOnly { "Basic realm=\"gw\"" } else { "NTLM" };
            let h = format!("{UNAUTH}WWW-Authenticate: {offer}\r\n\r\nnope");
            s.write_all(h.as_bytes()).await.ok()?;
            continue;
        }
        log.lock().expect("log").auth_ok = true;
        let accept = match mode {
            Mode::BadAccept => format!("Sec-WebSocket-Accept: {}\r\n", accept_key("other")),
            Mode::NoAccept => String::new(),
            _ => format!("Sec-WebSocket-Accept: {}\r\n", accept_key(&key(&head))),
        };
        let h = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n{accept}\r\n"
        );
        s.write_all(h.as_bytes()).await.ok()?;
        return Some(());
    }
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, packet: &[u8]) -> Option<()> {
    s.write_all(&ws::encode(ws::op::BINARY, packet, None)).await.ok()
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    mode: Mode,
    rdp: SocketAddr,
    log: Arc<Mutex<Log>>,
    leaf: &[u8],
) -> Option<()> {
    let mut buf = Vec::new();
    upgrade(&mut s, &mut buf, mode, &log, leaf).await?;
    let mut dec = Decoder::new(true);
    let mut rdg = Vec::new();
    loop {
        // One client packet.
        let (t, body) = loop {
            if let Ok(Some(n)) = pdu::peek_len(&rdg) {
                if rdg.len() >= n {
                    let p: Vec<u8> = rdg.drain(..n).collect();
                    let (t, b) = pdu::split(&p).ok()?;
                    break (t, b.to_vec());
                }
            }
            match dec.decode(&buf).ok()? {
                Some((Frame::Binary(b), used)) => {
                    buf.drain(..used);
                    rdg.extend_from_slice(&b);
                }
                Some((_, used)) => {
                    buf.drain(..used);
                }
                None => {
                    let mut tmp = [0u8; 16384];
                    let n = s.read(&mut tmp).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
        };
        match (t, mode) {
            (ty::HANDSHAKE_REQUEST, Mode::Oversized) => {
                let mut h = server::raw(ty::DATA, &[]);
                h[4..8].copy_from_slice(&u32::try_from(pdu::MAX_PACKET + 1).ok()?.to_le_bytes());
                send(&mut s, &h).await?;
            }
            (ty::HANDSHAKE_REQUEST, Mode::OutOfOrder) => send(&mut s, &pdu::data(b"early")).await?,
            (ty::HANDSHAKE_REQUEST, _) => send(&mut s, &server::handshake_response(0, 1)).await?,
            (ty::TUNNEL_CREATE, _) => {
                send(&mut s, &pdu::keepalive()).await?;
                send(&mut s, &server::tunnel_response(0, 7)).await?;
            }
            (ty::TUNNEL_AUTH, _) => send(&mut s, &server::tunnel_auth_response(0)).await?,
            (ty::CHANNEL_CREATE, m) => {
                let target = pdu::parse_channel_create(&body).ok()?;
                log.lock().expect("log").channels.push(target);
                if m == Mode::ChannelRefused {
                    send(&mut s, &server::channel_response(0x8007_59DD, 0)).await?;
                    continue;
                }
                let tcp = TcpStream::connect(rdp).await.ok()?;
                send(&mut s, &server::channel_response(0, 1)).await?;
                return relay(s, tcp, dec, buf, rdg).await;
            }
            _ => return None,
        }
    }
}

async fn relay<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    mut tcp: TcpStream,
    mut dec: Decoder,
    mut buf: Vec<u8>,
    mut rdg: Vec<u8>,
) -> Option<()> {
    let mut a = vec![0u8; 16384];
    let mut b = vec![0u8; 16384];
    loop {
        while let Ok(Some(n)) = pdu::peek_len(&rdg) {
            if rdg.len() < n {
                break;
            }
            let p: Vec<u8> = rdg.drain(..n).collect();
            match pdu::decode(&p).ok()? {
                pdu::Packet::Data(d) => tcp.write_all(&d).await.ok()?,
                pdu::Packet::Keepalive => {}
                _ => return None,
            }
        }
        while let Some((f, used)) = dec.decode(&buf).ok()? {
            buf.drain(..used);
            match f {
                Frame::Binary(x) => rdg.extend_from_slice(&x),
                Frame::Close => return None,
                _ => {}
            }
        }
        if pdu::peek_len(&rdg).ok()?.is_some_and(|n| rdg.len() >= n) {
            continue;
        }
        tokio::select! {
            n = s.read(&mut a) => {
                let n = n.ok()?;
                if n == 0 { return None; }
                buf.extend_from_slice(&a[..n]);
            }
            n = tcp.read(&mut b) => {
                let n = n.ok()?;
                if n == 0 { return None; }
                send(&mut s, &pdu::data(&b[..n])).await?;
            }
        }
    }
}
