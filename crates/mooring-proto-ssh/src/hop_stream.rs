//! [`HopStream`]: the byte stream of one hop or of the target (ADR-0025 §2).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use russh::client::Msg;
use russh::ChannelStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// The byte stream a hop or the target runs over.
pub enum HopStream {
    /// Hop 0: a plain socket.
    Tcp(TcpStream),
    /// Every later hop and the target: a `direct-tcpip` channel of the previous hop.
    Channel(ChannelStream<Msg>),
}

impl std::fmt::Debug for HopStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp(_) => "HopStream::Tcp",
            Self::Channel(_) => "HopStream::Channel",
        })
    }
}

impl AsyncRead for HopStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Channel(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HopStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Channel(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Channel(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Channel(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
