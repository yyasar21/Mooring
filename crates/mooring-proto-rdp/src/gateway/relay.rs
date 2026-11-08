//! After `CHANNEL_RESPONSE`: one task moves the RDP stream between an in-process duplex
//! (what the RDP connector reads and writes) and `DATA` packets on the gateway WebSocket.
//! `KEEPALIVE` every 15 minutes; the gateway's `CLOSE_CHANNEL` is answered and ends the
//! stream; `REAUTH_MESSAGE` ends it too (the session reconnects a fresh tunnel, ADR-0027 §1);
//! any packet that does not belong in the data phase is a protocol error. The end of the
//! relay is an EOF for the RDP side (`server_ended` / `network` there).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use super::conn::WsConn;
use super::pdu::{self, Packet};

/// Client keepalive period (ADR-0027 §1).
pub(crate) const KEEPALIVE: Duration = Duration::from_secs(15 * 60);
/// In-process buffer between the relay and the RDP connector.
pub(crate) const DUPLEX: usize = 128 * 1024;

/// Why the relay ended (logged at `debug`; never shown with server text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayEnd {
    /// The RDP side closed.
    Local,
    /// The gateway closed the channel or the socket.
    Gateway,
    /// The gateway asked to re-authenticate.
    Reauth,
    /// A read / write failed.
    Io,
    /// The gateway sent something outside the data phase.
    Protocol,
}

/// Run until either side ends.
pub(crate) async fn run<S>(mut ws: WsConn<S>, mut local: DuplexStream) -> RelayEnd
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await;
    let mut lbuf = vec![0u8; pdu::MAX_DATA];
    let mut rbuf = vec![0u8; 16 * 1024];
    let end = loop {
        // Packets already buffered (the tunnel setup may have read ahead).
        match drain(&mut ws, &mut local).await {
            Ok(()) => {}
            Err(e) => break e,
        }
        tokio::select! {
            n = local.read(&mut lbuf) => match n {
                Ok(0) | Err(_) => break RelayEnd::Local,
                Ok(n) => {
                    if ws.send(&pdu::data(&lbuf[..n])).await.is_err() {
                        break RelayEnd::Io;
                    }
                }
            },
            n = ws.conn.io.read(&mut rbuf) => match n {
                Ok(0) | Err(_) => break RelayEnd::Gateway,
                Ok(n) => ws.feed(&rbuf[..n]),
            },
            _ = keepalive.tick() => {
                if ws.send(&pdu::keepalive()).await.is_err() {
                    break RelayEnd::Io;
                }
            }
        }
    };
    if end == RelayEnd::Local {
        let _ = ws.send(&pdu::close_channel(false)).await;
    }
    ws.close().await;
    let _ = local.shutdown().await;
    tracing::debug!(end = ?end, "rd gateway relay ended");
    end
}

async fn drain<S>(ws: &mut WsConn<S>, local: &mut DuplexStream) -> Result<(), RelayEnd>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let packet = match ws.poll_packet().await {
            Ok(Some(p)) => p,
            Ok(None) => return Ok(()),
            Err(super::conn::Wire::Io) => return Err(RelayEnd::Gateway),
            Err(super::conn::Wire::Protocol(_)) => return Err(RelayEnd::Protocol),
        };
        match packet {
            Packet::Data(d) => {
                if local.write_all(&d).await.is_err() {
                    return Err(RelayEnd::Local);
                }
            }
            Packet::Keepalive | Packet::ServiceMessage { .. } => {}
            Packet::CloseChannel { .. } => {
                let _ = ws.send(&pdu::close_channel(true)).await;
                return Err(RelayEnd::Gateway);
            }
            Packet::CloseChannelResponse { .. } => return Err(RelayEnd::Gateway),
            Packet::Reauth => return Err(RelayEnd::Reauth),
            _ => return Err(RelayEnd::Protocol),
        }
    }
}
