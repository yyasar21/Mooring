//! Minimal SOCKS5 server side for dynamic forwarding (RFC 1928): no authentication,
//! `CONNECT` only, IPv4 / IPv6 / domain targets.
//!
//! The peer is a local application and is treated as hostile: every length is bounded by the
//! protocol (at most 4 + 1 + 255 + 2 bytes per request), the handshake runs under a timeout,
//! and [`parse_request`] is a pure function over bytes (proptest here, fuzz target for QA).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The whole greeting + request must arrive within this time.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const VERSION: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 1;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;

/// Reply codes (RFC 1928 §6) used here.
pub(crate) const REP_OK: u8 = 0;
pub(crate) const REP_FAILURE: u8 = 1;
pub(crate) const REP_HOST_UNREACHABLE: u8 = 4;
const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 8;

/// Why a SOCKS handshake was refused. Never carries peer bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksError {
    /// Not SOCKS version 5.
    Version,
    /// The client does not offer "no authentication".
    NoAcceptableMethod,
    /// A command other than CONNECT.
    Command,
    /// Unknown address type.
    AddressType,
    /// Empty, non-printable or invalid domain name, or port 0.
    BadTarget,
    /// The request is shorter or longer than its address type says.
    Length,
    /// I/O error or timeout during the handshake.
    Io,
}

/// A CONNECT target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    /// IPv4 / IPv6 literal (no brackets) or domain name.
    pub host: String,
    /// Destination port (never 0).
    pub port: u16,
}

/// Parse one complete SOCKS5 request: `VER CMD RSV ATYP DST.ADDR DST.PORT`.
pub fn parse_request(buf: &[u8]) -> Result<SocksTarget, SocksError> {
    let [ver, cmd, _rsv, atyp, rest @ ..] = buf else {
        return Err(SocksError::Length);
    };
    if *ver != VERSION {
        return Err(SocksError::Version);
    }
    if *cmd != CMD_CONNECT {
        return Err(SocksError::Command);
    }
    let (host, port_bytes) = match *atyp {
        ATYP_V4 => {
            let (addr, port) = split_exact::<4>(rest)?;
            (Ipv4Addr::from(addr).to_string(), port)
        }
        ATYP_V6 => {
            let (addr, port) = split_exact::<16>(rest)?;
            (Ipv6Addr::from(addr).to_string(), port)
        }
        ATYP_DOMAIN => {
            let [len, tail @ ..] = rest else {
                return Err(SocksError::Length);
            };
            let len = usize::from(*len);
            if tail.len() != len + 2 {
                return Err(SocksError::Length);
            }
            let (name, port) = tail.split_at(len);
            (domain(name)?, [port[0], port[1]])
        }
        _ => return Err(SocksError::AddressType),
    };
    let port = u16::from_be_bytes(port_bytes);
    if port == 0 {
        return Err(SocksError::BadTarget);
    }
    Ok(SocksTarget { host, port })
}

fn split_exact<const N: usize>(rest: &[u8]) -> Result<([u8; N], [u8; 2]), SocksError> {
    if rest.len() != N + 2 {
        return Err(SocksError::Length);
    }
    let (addr, port) = rest.split_at(N);
    let addr: [u8; N] = addr.try_into().map_err(|_| SocksError::Length)?;
    let port: [u8; 2] = port.try_into().map_err(|_| SocksError::Length)?;
    Ok((addr, port))
}

fn domain(name: &[u8]) -> Result<String, SocksError> {
    if name.is_empty() || !name.iter().all(u8::is_ascii_graphic) {
        return Err(SocksError::BadTarget);
    }
    let name = std::str::from_utf8(name).map_err(|_| SocksError::BadTarget)?;
    mooring_core::validate_host(name).map_err(|_| SocksError::BadTarget)
}

/// Run the greeting and read the CONNECT request. Error replies are sent here; the caller
/// sends the final reply with [`reply`] once the SSH channel is (or is not) open.
pub(crate) async fn handshake<S>(stream: &mut S) -> Result<SocksTarget, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake_inner(stream))
        .await
        .map_err(|_| SocksError::Io)?
}

async fn handshake_inner<S>(stream: &mut S) -> Result<SocksTarget, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io = |_| SocksError::Io;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != VERSION {
        return Err(SocksError::Version);
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await.map_err(io)?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await;
        return Err(SocksError::NoAcceptableMethod);
    }
    stream.write_all(&[VERSION, METHOD_NO_AUTH]).await.map_err(io)?;

    let mut req = vec![0u8; 4];
    stream.read_exact(&mut req).await.map_err(io)?;
    let rest = match req[3] {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io)?;
            req.push(len[0]);
            usize::from(len[0]) + 2
        }
        _ => {
            let _ = reply(stream, REP_ADDRESS_NOT_SUPPORTED).await;
            return Err(SocksError::AddressType);
        }
    };
    let start = req.len();
    req.resize(start + rest, 0);
    stream.read_exact(&mut req[start..]).await.map_err(io)?;
    let parsed = parse_request(&req);
    match parsed {
        Err(SocksError::Command) => {
            let _ = reply(stream, REP_COMMAND_NOT_SUPPORTED).await;
        }
        Err(_) => {
            let _ = reply(stream, REP_FAILURE).await;
        }
        Ok(_) => {}
    }
    parsed
}

/// Send a reply with an all-zero IPv4 bind address (clients ignore it for CONNECT).
pub(crate) async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, rep: u8) -> std::io::Result<()> {
    stream.write_all(&[VERSION, rep, 0, ATYP_V4, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_each_address_type() {
        let v4 = parse_request(&[5, 1, 0, 1, 192, 0, 2, 7, 0x1F, 0x90]).expect("v4");
        assert_eq!(v4, SocksTarget { host: "192.0.2.7".into(), port: 8080 });
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 22]);
        assert_eq!(parse_request(&v6).expect("v6").host, "::1");
        let mut dn = vec![5, 1, 0, 3, 9];
        dn.extend_from_slice(b"localhost");
        dn.extend_from_slice(&[0, 80]);
        assert_eq!(parse_request(&dn).expect("domain").host, "localhost");
    }

    #[test]
    fn rejects_bad_requests() {
        assert_eq!(parse_request(&[4, 1, 0, 1, 1, 1, 1, 1, 0, 1]), Err(SocksError::Version));
        assert_eq!(parse_request(&[5, 2, 0, 1, 1, 1, 1, 1, 0, 1]), Err(SocksError::Command));
        assert_eq!(parse_request(&[5, 1, 0, 9, 1, 1]), Err(SocksError::AddressType));
        assert_eq!(parse_request(&[5, 1, 0, 1, 1, 1, 1, 1, 0, 0]), Err(SocksError::BadTarget));
        assert_eq!(parse_request(&[5, 1, 0, 1, 1, 1, 1]), Err(SocksError::Length));
        assert_eq!(parse_request(&[5, 1, 0, 3, 0, 0, 80]), Err(SocksError::BadTarget));
        assert_eq!(parse_request(&[5, 1, 0, 3, 2, b'a', 0x1b, 0, 80]), Err(SocksError::BadTarget));
        assert_eq!(parse_request(&[5, 1, 0, 3, 5, b'a', 0, 80]), Err(SocksError::Length));
        assert_eq!(parse_request(&[]), Err(SocksError::Length));
    }

    #[tokio::test]
    async fn handshake_refuses_auth_only_clients() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[5, 1, 2]).await.expect("write");
        assert_eq!(handshake(&mut server).await, Err(SocksError::NoAcceptableMethod));
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.expect("read");
        assert_eq!(answer, [5, 0xFF]);
    }

    #[tokio::test]
    async fn handshake_rejects_bind_command() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80]).await.expect("write");
        assert_eq!(handshake(&mut server).await, Err(SocksError::Command));
        let mut answer = [0u8; 12];
        client.read_exact(&mut answer).await.expect("read");
        assert_eq!(answer[2..4], [5, REP_COMMAND_NOT_SUPPORTED]);
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse_request(&bytes);
        }

        #[test]
        fn domain_round_trip(name in "[a-z][a-z0-9.-]{0,60}", port in 1u16..) {
            let mut req = vec![5, 1, 0, 3, u8::try_from(name.len()).expect("short")];
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
            let t = parse_request(&req).expect("valid");
            prop_assert_eq!(t, SocksTarget { host: name, port });
        }
    }
}
