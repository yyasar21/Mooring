//! Data path of the forwards: accept loops, the SOCKS5 front and the bounded bidirectional
//! copy between a TCP stream and an SSH channel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{ChannelOpenHandle, Handle, Msg};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use crate::chain_proxy::Gate;
use crate::forward::COPY_BUFFER;
use crate::handler::ClientHandler;
use crate::socks;

/// Connect timeout for remote-forward targets on this machine.
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a remote forward's incoming channels go.
#[derive(Clone)]
pub(crate) struct Route {
    pub(crate) target: SocketAddr,
    pub(crate) cancel: watch::Receiver<bool>,
    pub(crate) limit: Arc<Semaphore>,
}

/// Resolves when the forward is cancelled (or its owner is gone).
async fn cancelled(mut cancel: watch::Receiver<bool>) {
    while !*cancel.borrow_and_update() {
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

/// Copy both ways until both sides finish or the forward is cancelled.
async fn splice<A, B>(mut a: A, mut b: B, cancel: watch::Receiver<bool>)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        r = tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, COPY_BUFFER, COPY_BUFFER) => {
            if let Err(e) = r {
                tracing::debug!(kind = ?e.kind(), "forwarded connection ended with an error");
            }
        }
        () = cancelled(cancel) => {}
    }
}

fn origin(peer: SocketAddr) -> (String, u32) {
    (peer.ip().to_string(), u32::from(peer.port()))
}

async fn open_direct(
    handle: &Handle<ClientHandler>,
    host: &str,
    port: u16,
    peer: SocketAddr,
) -> Option<Channel<Msg>> {
    let (oa, op) = origin(peer);
    match handle.channel_open_direct_tcpip(host, u32::from(port), oa, op).await {
        Ok(ch) => Some(ch),
        Err(e) => {
            tracing::debug!(error = %e, "direct-tcpip refused");
            None
        }
    }
}

/// Accept connections until cancelled; `serve` handles one connection.
/// `limit` holds [`MAX_CONNECTIONS_PER_FORWARD`](crate::forward::MAX_CONNECTIONS_PER_FORWARD) permits; the forward's live connection
/// count is read from it.
async fn accept_loop<F, Fut>(
    listener: TcpListener,
    cancel: watch::Receiver<bool>,
    limit: Arc<Semaphore>,
    serve: F,
) where
    F: Fn(TcpStream, SocketAddr, OwnedSemaphorePermit) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let stop = cancelled(cancel);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                        tracing::warn!("forward connection limit reached; dropping connection");
                        continue;
                    };
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(serve(stream, peer, permit));
                }
                Err(e) => {
                    tracing::debug!(kind = ?e.kind(), "forward accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

pub(crate) async fn local_loop(
    listener: TcpListener,
    handle: Arc<Handle<ClientHandler>>,
    host: String,
    port: u16,
    cancel: watch::Receiver<bool>,
    limit: Arc<Semaphore>,
) {
    let cancel2 = cancel.clone();
    accept_loop(listener, cancel, limit, move |stream, peer, permit| {
        let (handle, host, cancel) = (Arc::clone(&handle), host.clone(), cancel2.clone());
        async move {
            let _permit = permit;
            if let Some(ch) = open_direct(&handle, &host, port, peer).await {
                splice(stream, ch.into_stream(), cancel).await;
            }
        }
    })
    .await;
}

pub(crate) async fn dynamic_loop(
    listener: TcpListener,
    handle: Arc<Handle<ClientHandler>>,
    cancel: watch::Receiver<bool>,
    limit: Arc<Semaphore>,
    gate: Option<Arc<Gate>>,
) {
    let cancel2 = cancel.clone();
    accept_loop(listener, cancel, limit, move |mut stream, peer, permit| {
        let (handle, cancel, gate) = (Arc::clone(&handle), cancel2.clone(), gate.clone());
        async move {
            let _permit = permit;
            let target = match socks::handshake(&mut stream).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(error = ?e, "socks5 handshake refused");
                    return;
                }
            };
            if let Some(gate) = gate.as_deref() {
                if !gate.admit(&target.host, target.port) {
                    let _ = socks::reply(&mut stream, socks::REP_NOT_ALLOWED).await;
                    return;
                }
            }
            let Some(ch) = open_direct(&handle, &target.host, target.port, peer).await else {
                let _ = socks::reply(&mut stream, socks::REP_HOST_UNREACHABLE).await;
                return;
            };
            if socks::reply(&mut stream, socks::REP_OK).await.is_ok() {
                splice(stream, ch.into_stream(), cancel).await;
            }
        }
    })
    .await;
}

/// Handle a `forwarded-tcpip` channel the server opened for one of our remote forwards.
/// Unknown forwards are rejected; the target connect runs in its own task so the russh
/// session loop never waits on it.
pub(crate) fn accept_forwarded(
    route: Option<Route>,
    channel: Channel<Msg>,
    reply: ChannelOpenHandle,
) {
    let Some(route) = route else {
        tracing::debug!("forwarded-tcpip for an unknown forward rejected");
        tokio::spawn(reply.reject(ChannelOpenFailure::AdministrativelyProhibited));
        return;
    };
    let Ok(permit) = Arc::clone(&route.limit).try_acquire_owned() else {
        tracing::warn!("remote forward connection limit reached");
        tokio::spawn(reply.reject(ChannelOpenFailure::ResourceShortage));
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let connect =
            tokio::time::timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(route.target));
        let Ok(Ok(stream)) = connect.await else {
            tracing::debug!("remote forward target unreachable");
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return;
        };
        let _ = stream.set_nodelay(true);
        reply.accept().await;
        splice(stream, channel.into_stream(), route.cancel).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn splice_copies_both_ways_and_stops_on_cancel() {
        let (mut a_user, a) = tokio::io::duplex(1024);
        let (mut b_user, b) = tokio::io::duplex(1024);
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(splice(a, b, rx));
        a_user.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        b_user.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
        b_user.write_all(b"pong").await.expect("write");
        a_user.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pong");
        tx.send(true).expect("cancel");
        tokio::time::timeout(Duration::from_secs(2), task).await.expect("stops").expect("join");
    }
}
