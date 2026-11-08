//! One gateway open: TLS (TOFU over `known_rdg_certs`) → HTTP upgrade with NTLM / Basic →
//! MS-TSGU tunnel and channel → the relay task. Emits `GatewayStatus` and audits
//! `session.rdp.gateway` with the outcome.

use std::sync::Arc;
use std::time::Duration;

use mooring_core::known_certs::{display_fingerprint, peer_identity, CertVerdict, KnownCerts};
use mooring_core::options::{GatewayUsage, RdGatewayOptions};
use mooring_core::session::{CloseCode, HopState, SessionEvent};
use mooring_core::transport::{Dialed, Erased};
use mooring_core::SessionAudit;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use super::conn::{random, Conn, Wire, WsConn};
use super::http::{self, encode_base64};
use super::ntlm::NtlmClient;
use super::pdu::{self, Packet};
use super::{relay, GatewayAccount, GatewayCredential};
use crate::connect::Target;
use crate::creds::Creds;
use crate::errors::{end, End};
use crate::options::AuditSink;
use crate::tls::{self, take_decision, Decision, DecisionSlot, TofuVerifier};

/// `usage: if_unreachable`: how long the direct path is tried first.
pub(crate) const PROBE: Duration = Duration::from_secs(3);
/// Most HTTP requests of one upgrade (NTLM is two; a Basic fallback one more).
const MAX_ROUNDS: usize = 3;
/// Keepalives / service messages skipped while waiting for a setup response.
const MAX_SKIPS: usize = 8;

/// The gateway part of a [`Target`].
#[derive(Debug, Clone)]
pub(crate) struct GatewayTarget {
    pub(crate) opts: RdGatewayOptions,
    pub(crate) known_certs: std::path::PathBuf,
    pub(crate) credential: Arc<GatewayCredential>,
    /// Gateway leaf accepted for this session (`trusted_once` or a `yes`).
    pub(crate) session_pin: Option<[u8; 32]>,
}

/// The result of [`open`].
pub(crate) enum Opened {
    /// The byte stream to the target; `true` when it runs through the gateway.
    Stream(Dialed, bool),
    /// The gateway certificate needs the user (`gateway_certificate_trust`).
    NeedsTrust(Decision),
}

type GwStream = TlsStream<Erased>;

fn wire(e: Wire) -> End {
    match e {
        Wire::Io => end(CloseCode::Network, "the RD Gateway connection failed"),
        Wire::Protocol(m) => end(CloseCode::ProtocolError, m),
    }
}

fn auth_failed(reason: &str) -> End {
    end(CloseCode::GatewayAuth, reason)
}

async fn status(
    events: &mpsc::Sender<SessionEvent>,
    host: &str,
    state: HopState,
    id: Option<String>,
) {
    let e = SessionEvent::GatewayStatus { host: host.to_owned(), state, peer_identity: id };
    let _ = events.send(e).await;
}

fn outcome(code: CloseCode) -> &'static str {
    match code {
        CloseCode::GatewayAuth => "auth_failed",
        CloseCode::GatewayRefused => "refused",
        CloseCode::GatewayUnsupported => "unsupported",
        CloseCode::TrustMismatch | CloseCode::TrustConflict | CloseCode::TrustRejected => "trust",
        CloseCode::ProtocolError => "protocol",
        _ => "network",
    }
}

/// Open the gateway (or, with `if_unreachable`, the direct path when it answers in 3 s).
pub(crate) async fn open(
    target: &Target,
    gw: &GatewayTarget,
    creds: &Creds,
    audit: &AuditSink,
    events: &mpsc::Sender<SessionEvent>,
) -> Result<Opened, End> {
    let label = gw.opts.label();
    if gw.opts.usage == GatewayUsage::IfUnreachable {
        let dial = Arc::clone(&target.dialer).dial(&target.host, target.port);
        if let Ok(Ok(d)) = tokio::time::timeout(PROBE, dial).await {
            let row = SessionAudit::Gateway {
                host: label,
                auth: "none",
                outcome: "direct",
                tunnel_id: 0,
            };
            audit.push(row);
            return Ok(Opened::Stream(d, false));
        }
    }
    status(events, &label, HopState::Connecting, None).await;
    let mut auth = "ntlm";
    let mut tunnel_id = 0;
    let r = Box::pin(run(target, gw, creds, audit, events, &mut auth, &mut tunnel_id)).await;
    let result = match &r {
        Ok(Opened::NeedsTrust(_)) => return r,
        Ok(_) => "ok",
        Err((code, _)) => {
            status(events, &label, HopState::Failed, None).await;
            outcome(*code)
        }
    };
    audit.push(SessionAudit::Gateway { host: label, auth, outcome: result, tunnel_id });
    r
}

async fn run(
    target: &Target,
    gw: &GatewayTarget,
    creds: &Creds,
    audit: &AuditSink,
    events: &mpsc::Sender<SessionEvent>,
    auth: &mut &'static str,
    tunnel_id: &mut u32,
) -> Result<Opened, End> {
    let same;
    let account = match &*gw.credential {
        GatewayCredential::Account(a) => a,
        GatewayCredential::SameAsSignIn => {
            same = GatewayAccount {
                username: creds.username.clone(),
                domain: creds.domain.clone(),
                password: SecretString::from(creds.password.expose_secret().to_owned()),
            };
            &same
        }
    };
    let mut basic: Option<Zeroizing<String>> = None;
    let mut reopened = false;
    let conn = loop {
        let (conn, d) = match tls_connect(target, gw, audit).await? {
            Tls::Done(s, d) => (Conn::new(*s), d),
            Tls::NeedsTrust(d) => return Ok(Opened::NeedsTrust(d)),
        };
        if !reopened {
            let id = Some(peer_identity(&d.fingerprint));
            status(events, &gw.opts.label(), HopState::Authenticating, id).await;
        }
        match Box::pin(upgrade(conn, gw, account, basic.take(), audit, auth)).await? {
            Upgrade::Done(c) => break *c,
            Upgrade::Reopen(h) if !reopened => {
                (basic, reopened) = (Some(h), true);
            }
            Upgrade::Reopen(_) => {
                return Err(auth_failed(
                    "the RD Gateway closed the connection during authentication",
                ))
            }
        }
    };
    let mut ws = WsConn::new(conn);
    *tunnel_id = Box::pin(tunnel(&mut ws, target)).await?;
    let (ours, theirs) = tokio::io::duplex(relay::DUPLEX);
    tokio::spawn(relay::run(ws, theirs));
    status(events, &gw.opts.label(), HopState::Up, None).await;
    Ok(Opened::Stream(Dialed { stream: Box::new(ours), local_addr: None }, true))
}

enum Tls {
    Done(Box<GwStream>, Decision),
    NeedsTrust(Decision),
}

async fn tls_connect(target: &Target, gw: &GatewayTarget, audit: &AuditSink) -> Result<Tls, End> {
    let (host, port) = (gw.opts.host.clone(), gw.opts.port);
    let (path, ca, pin) = (gw.known_certs.clone(), gw.opts.ca_pem.clone(), gw.session_pin);
    let h = host.clone();
    let (known, roots) = tokio::task::spawn_blocking(move || {
        let mut known = KnownCerts::load(&path)?;
        if let Some(pin) = pin {
            if !known.has_pin(&h, port) {
                known.add(&h, port, &pin, time::OffsetDateTime::now_utc());
            }
        }
        Ok::<_, mooring_core::known_certs::KnownCertsError>((
            known,
            tls::root_store(tls::system_roots(), ca.as_deref()),
        ))
    })
    .await
    .map_err(|_| end(CloseCode::ProtocolError, "trust store task failed"))?
    .map_err(|_| end(CloseCode::ProtocolError, "the RD Gateway trust store could not be read"))?;
    let dial = Arc::clone(&target.dialer).dial(&host, port);
    let Dialed { stream, .. } = tokio::time::timeout(target.connect_timeout, dial)
        .await
        .map_err(|_| end(CloseCode::Network, "the RD Gateway did not answer in time"))?
        .map_err(|_| end(CloseCode::Network, "the RD Gateway could not be reached"))?;
    let name = tls::server_name(&host)
        .ok_or_else(|| end(CloseCode::ProtocolError, "the gateway host is not a valid TLS name"))?;
    let slot = DecisionSlot::default();
    let verifier = Arc::new(TofuVerifier::new(&host, port, known, roots, Arc::clone(&slot)));
    let cfg = tls::client_config(verifier)
        .map_err(|_| end(CloseCode::ProtocolError, "TLS setup failed"))?;
    let hs = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, Erased::new(stream));
    let hs = tokio::time::timeout(target.connect_timeout, hs)
        .await
        .map_err(|_| end(CloseCode::Network, "the RD Gateway TLS handshake timed out"))?;
    let label = gw.opts.label();
    match (hs, take_decision(&slot)) {
        (Ok(s), Some(d)) => {
            if d.verdict == CertVerdict::AcceptCa {
                let fingerprint = display_fingerprint(&d.fingerprint);
                audit.push(SessionAudit::CertCaValid { host: host.clone(), port, fingerprint });
            }
            Ok(Tls::Done(Box::new(s), d))
        }
        (Err(_), Some(d)) => match d.verdict {
            CertVerdict::Prompt => Ok(Tls::NeedsTrust(d)),
            CertVerdict::Mismatch { expected } => {
                let (old, new) = (display_fingerprint(&expected), display_fingerprint(&d.fingerprint));
                let row = SessionAudit::CertMismatch { host, port, expected: old.clone(), presented: new.clone() };
                audit.push(row);
                let reason = format!("RD GATEWAY CERTIFICATE CHANGED for {label}: expected {old}, got {new}");
                Err((CloseCode::TrustMismatch, reason))
            }
            CertVerdict::Conflict => Err((
                CloseCode::TrustConflict,
                format!("CONFLICTING PINS for RD Gateway {label}: remove them in the known certificates manager"),
            )),
            _ => Err(end(CloseCode::Network, "the RD Gateway TLS handshake failed")),
        },
        (Err(_), None) => Err(end(CloseCode::Network, "the RD Gateway TLS handshake failed")),
        (Ok(_), None) => Err(end(CloseCode::ProtocolError, "TLS handshake without a certificate")),
    }
}

enum Upgrade {
    Done(Box<Conn<GwStream>>),
    /// The gateway closed after offering Basic: reconnect and send this header.
    Reopen(Zeroizing<String>),
}

fn basic_header(a: &GatewayAccount) -> Zeroizing<String> {
    let user = match a.domain.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => format!("{d}\\{}", a.username),
        None => a.username.clone(),
    };
    let plain = Zeroizing::new(format!("{user}:{}", a.password.expose_secret()));
    Zeroizing::new(format!("Basic {}", encode_base64(plain.as_bytes())))
}

fn guid() -> Result<String, End> {
    let b: [u8; 16] = random().map_err(wire)?;
    let h = b.iter().fold(String::with_capacity(32), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02X}");
        s
    });
    Ok(format!("{{{}-{}-{}-{}-{}}}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

async fn upgrade(
    mut conn: Conn<GwStream>,
    gw: &GatewayTarget,
    account: &GatewayAccount,
    basic: Option<Zeroizing<String>>,
    audit: &AuditSink,
    auth: &mut &'static str,
) -> Result<Upgrade, End> {
    let (host, port) = (gw.opts.host.as_str(), gw.opts.port);
    let key = encode_base64(&random::<16>().map_err(wire)?);
    let id = guid()?;
    let spn = format!("HTTP/{host}");
    let mut ntlm = None;
    let mut header = if let Some(h) = basic {
        h
    } else {
        let leaf = conn
            .io
            .get_ref()
            .1
            .peer_certificates()
            .and_then(<[_]>::first)
            .map(|c| c.as_ref().to_vec())
            .ok_or_else(|| end(CloseCode::ProtocolError, "TLS handshake without a certificate"))?;
        let mut n = NtlmClient::new(account, &leaf)
            .map_err(|_| auth_failed("the gateway user name cannot be used for NTLM"))?;
        let t1 = n.negotiate(&spn).map_err(|_| auth_failed("NTLM could not start"))?;
        ntlm = Some(n);
        Zeroizing::new(format!("NTLM {}", encode_base64(&t1)))
    };
    if ntlm.is_none() {
        *auth = "basic";
    }
    let mut legs = 0;
    for _ in 0..MAX_ROUNDS {
        conn.write(&http::request(host, port, &key, &id, Some(header.as_str())))
            .await
            .map_err(wire)?;
        let head = conn.read_response().await.map_err(wire)?;
        match head.status {
            101 => {
                let accept_ok =
                    head.get("sec-websocket-accept") == Some(http::accept_key(&key).as_str());
                if !head.has_token("upgrade", "websocket") || !accept_ok {
                    return Err(end(
                        CloseCode::ProtocolError,
                        "the RD Gateway did not upgrade to WebSocket",
                    ));
                }
                return Ok(Upgrade::Done(Box::new(conn)));
            }
            401 => {
                let c = http::challenges(&head).ok_or_else(|| {
                    end(CloseCode::ProtocolError, "malformed NTLM challenge from the RD Gateway")
                })?;
                let closing = head.has_token("connection", "close");
                if let (Some(n), Some(token), 0, false) =
                    (ntlm.as_mut(), c.ntlm_token.as_deref(), legs, closing)
                {
                    let t3 = n.authenticate(token, &spn).map_err(|_| {
                        auth_failed("the RD Gateway sent an unusable NTLM challenge")
                    })?;
                    header = Zeroizing::new(format!("NTLM {}", encode_base64(&t3)));
                    legs = 1;
                    continue;
                }
                if *auth == "basic" || legs == 1 {
                    return Err(auth_failed("the RD Gateway refused the credentials"));
                }
                if c.basic {
                    if !gw.opts.allow_basic_gateway {
                        return Err(auth_failed("the RD Gateway offers only Basic authentication; enable allowBasicGateway to use it"));
                    }
                    *auth = "basic";
                    audit.push(SessionAudit::GatewayBasic { host: gw.opts.label() });
                    ntlm = None;
                    header = basic_header(account);
                    if closing {
                        return Ok(Upgrade::Reopen(header));
                    }
                    continue;
                }
                if c.negotiate {
                    return Err(auth_failed("the RD Gateway requires Kerberos (Negotiate without NTLM), which is not supported"));
                }
                return Err(auth_failed("the RD Gateway refused the credentials"));
            }
            400 | 404 | 405 | 501 => {
                return Err(end(
                    CloseCode::GatewayUnsupported,
                    "the RD Gateway has no WebSocket endpoint (RPC over HTTP gateways are not supported)",
                ));
            }
            s => {
                return Err((
                    CloseCode::GatewayRefused,
                    format!("the RD Gateway refused the connection (HTTP {s})"),
                ));
            }
        }
    }
    Err(auth_failed("the RD Gateway did not finish authentication"))
}

/// The next setup packet, skipping keepalives and service messages.
async fn expect(ws: &mut WsConn<GwStream>) -> Result<Packet, End> {
    for _ in 0..MAX_SKIPS {
        match ws.recv().await.map_err(wire)? {
            Packet::Keepalive | Packet::ServiceMessage { .. } => {}
            Packet::CloseChannel { .. } | Packet::CloseChannelResponse { .. } => {
                return Err(end(CloseCode::GatewayRefused, "the RD Gateway closed the tunnel"));
            }
            p => return Ok(p),
        }
    }
    Err(end(CloseCode::ProtocolError, "the RD Gateway sent too many messages during setup"))
}

fn out_of_order() -> End {
    end(CloseCode::ProtocolError, "unexpected RD Gateway packet during setup")
}

fn refused(what: &str, code: u32) -> End {
    (CloseCode::GatewayRefused, format!("the RD Gateway refused the {what} (0x{code:08X})"))
}

/// `HANDSHAKE` → `TUNNEL_CREATE` → `TUNNEL_AUTHORIZE` → `CHANNEL_CREATE`; the tunnel id.
async fn tunnel(ws: &mut WsConn<GwStream>, target: &Target) -> Result<u32, End> {
    ws.send(&pdu::handshake_request()).await.map_err(wire)?;
    match expect(ws).await? {
        Packet::HandshakeResponse { error: 0, major: 1, .. } => {}
        Packet::HandshakeResponse { error: 0, .. } => {
            return Err(end(
                CloseCode::GatewayUnsupported,
                "the RD Gateway speaks another MS-TSGU version",
            ));
        }
        Packet::HandshakeResponse { error, .. } => return Err(refused("handshake", error)),
        _ => return Err(out_of_order()),
    }
    ws.send(&pdu::tunnel_create()).await.map_err(wire)?;
    let tunnel_id = match expect(ws).await? {
        Packet::TunnelResponse { status: 0, tunnel_id, .. } => tunnel_id.unwrap_or(0),
        Packet::TunnelResponse { status, .. } => return Err(refused("tunnel", status)),
        _ => return Err(out_of_order()),
    };
    ws.send(&pdu::tunnel_auth(&target.client_name)).await.map_err(wire)?;
    match expect(ws).await? {
        Packet::TunnelAuthResponse { error: 0, .. } => {}
        Packet::TunnelAuthResponse { error, .. } => {
            return Err(refused("tunnel authorization", error))
        }
        _ => return Err(out_of_order()),
    }
    let create = pdu::channel_create(&target.host, target.port).ok_or_else(|| {
        end(CloseCode::ProtocolError, "the target host cannot be sent to the gateway")
    })?;
    ws.send(&create).await.map_err(wire)?;
    match expect(ws).await? {
        Packet::ChannelResponse { error: 0, .. } => Ok(tunnel_id),
        Packet::ChannelResponse { error, .. } => Err(refused(
            &format!("channel to {}", super::host_port(&target.host, target.port)),
            error,
        )),
        _ => Err(out_of_order()),
    }
}
