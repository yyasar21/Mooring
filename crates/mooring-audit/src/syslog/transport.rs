//! Blocking syslog connections: UDP (RFC 5426, one message per datagram), TCP (RFC 6587
//! octet counting) and TLS (RFC 5425 octet counting over rustls, ring provider).
//!
//! Every socket operation has a [`IO_TIMEOUT`], so a dead collector costs the mirror thread at
//! most a few seconds per attempt and never touches the caller.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use super::{SyslogConfig, SyslogError, Transport};

/// Connect / write timeout.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Trust anchors for the TLS transport.
#[derive(Debug, Clone)]
pub enum TlsRoots {
    /// The operating system's trust store (`rustls-native-certs`), loaded once per process.
    /// Enterprise CAs installed in the OS store are honoured.
    System,
    /// An explicit root store (tests; a future "custom CA" setting).
    Custom(Arc<RootCertStore>),
}

impl TlsRoots {
    fn store(&self) -> Result<Arc<RootCertStore>, SyslogError> {
        match self {
            Self::Custom(s) => Ok(Arc::clone(s)),
            Self::System => {
                static SYSTEM: OnceLock<Arc<RootCertStore>> = OnceLock::new();
                let store = SYSTEM.get_or_init(|| {
                    let loaded = rustls_native_certs::load_native_certs();
                    if !loaded.errors.is_empty() {
                        tracing::warn!(count = loaded.errors.len(), "some system roots unreadable");
                    }
                    let mut store = RootCertStore::empty();
                    let (ok, bad) = store.add_parsable_certificates(loaded.certs);
                    tracing::debug!(ok, bad, "system roots loaded for syslog TLS");
                    Arc::new(store)
                });
                if store.is_empty() {
                    return Err(SyslogError::Tls("no system trust anchors found".into()));
                }
                Ok(Arc::clone(store))
            }
        }
    }
}

/// An open connection to the collector.
pub enum Conn {
    /// Connected UDP socket.
    Udp(UdpSocket),
    /// Plain TCP.
    Tcp(TcpStream),
    /// TLS over TCP.
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Udp(_) => "Conn::Udp",
            Self::Tcp(_) => "Conn::Tcp",
            Self::Tls(_) => "Conn::Tls",
        })
    }
}

fn resolve(cfg: &SyslogConfig) -> Result<Vec<SocketAddr>, SyslogError> {
    let addrs: Vec<SocketAddr> = (cfg.host.as_str(), cfg.port)
        .to_socket_addrs()
        .map_err(|_| SyslogError::Resolve)?
        .collect();
    if addrs.is_empty() {
        return Err(SyslogError::Resolve);
    }
    Ok(addrs)
}

fn tcp_connect(addrs: &[SocketAddr]) -> Result<TcpStream, SyslogError> {
    let mut last = SyslogError::Resolve;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, IO_TIMEOUT) {
            Ok(s) => {
                s.set_write_timeout(Some(IO_TIMEOUT)).map_err(SyslogError::io)?;
                s.set_read_timeout(Some(IO_TIMEOUT)).map_err(SyslogError::io)?;
                s.set_nodelay(true).map_err(SyslogError::io)?;
                return Ok(s);
            }
            Err(e) => last = SyslogError::io(e),
        }
    }
    Err(last)
}

/// Open a connection per `cfg` (DNS lookup, connect, and for TLS a full handshake with
/// certificate and host-name verification).
pub fn connect(cfg: &SyslogConfig, roots: &TlsRoots) -> Result<Conn, SyslogError> {
    let addrs = resolve(cfg)?;
    match cfg.transport {
        Transport::Udp => {
            let addr = addrs[0];
            let local: SocketAddr =
                if addr.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
            let s = UdpSocket::bind(local).map_err(SyslogError::io)?;
            s.set_write_timeout(Some(IO_TIMEOUT)).map_err(SyslogError::io)?;
            s.connect(addr).map_err(SyslogError::io)?;
            Ok(Conn::Udp(s))
        }
        Transport::Tcp => Ok(Conn::Tcp(tcp_connect(&addrs)?)),
        Transport::Tls => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| SyslogError::Tls(e.to_string()))?
                .with_root_certificates(roots.store()?)
                .with_no_client_auth();
            let name = ServerName::try_from(cfg.host.clone())
                .map_err(|_| SyslogError::invalid("host", "not a valid TLS server name"))?;
            let conn = ClientConnection::new(Arc::new(config), name)
                .map_err(|e| SyslogError::Tls(e.to_string()))?;
            let mut stream = StreamOwned::new(conn, tcp_connect(&addrs)?);
            // Drive the handshake now so a bad certificate is reported by `connect`.
            while stream.conn.is_handshaking() {
                stream.conn.complete_io(&mut stream.sock).map_err(SyslogError::tls_io)?;
            }
            Ok(Conn::Tls(Box::new(stream)))
        }
    }
}

/// RFC 6587 / 5425 octet-counting frame: `LEN SP MSG`.
#[must_use]
pub fn octet_frame(msg: &[u8]) -> Vec<u8> {
    let mut out = format!("{} ", msg.len()).into_bytes();
    out.extend_from_slice(msg);
    out
}

impl Conn {
    /// Send one message (framed for stream transports).
    pub fn send(&mut self, msg: &[u8]) -> Result<(), SyslogError> {
        match self {
            Self::Udp(s) => {
                let n = s.send(msg).map_err(SyslogError::io)?;
                if n != msg.len() {
                    return Err(SyslogError::Io(std::io::ErrorKind::WriteZero));
                }
                Ok(())
            }
            Self::Tcp(s) => {
                s.write_all(&octet_frame(msg)).and_then(|()| s.flush()).map_err(SyslogError::io)
            }
            Self::Tls(s) => {
                s.write_all(&octet_frame(msg)).and_then(|()| s.flush()).map_err(SyslogError::tls_io)
            }
        }
    }
}
