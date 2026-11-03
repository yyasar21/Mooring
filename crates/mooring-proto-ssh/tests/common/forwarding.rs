//! Server side of forwarding for the test server, plus a loopback TCP echo service.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use russh::server::{self, Msg};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Remote-forward listeners of one server connection, by (address, port).
pub type Listeners = Arc<Mutex<HashMap<(String, u32), JoinHandle<()>>>>;

/// Echo server on 127.0.0.1; returns its address. Each connection echoes until EOF.
pub async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn splice(stream: TcpStream, channel: Channel<Msg>) {
    let mut stream = stream;
    let mut ch = channel.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut ch).await;
}

/// `direct-tcpip`: connect to the target and splice, or reject.
pub fn direct(channel: Channel<Msg>, host: String, port: u32, reply: server::ChannelOpenHandle) {
    tokio::spawn(async move {
        let Ok(port) = u16::try_from(port) else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return;
        };
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(stream) => {
                reply.accept().await;
                splice(stream, channel).await;
            }
            Err(_) => reply.reject(ChannelOpenFailure::ConnectFailed).await,
        }
    });
}

/// `tcpip-forward`: listen on loopback and open a `forwarded-tcpip` channel per connection.
pub async fn listen(
    listeners: &Listeners,
    handle: server::Handle,
    address: &str,
    port: &mut u32,
) -> bool {
    let Ok(requested) = u16::try_from(*port) else {
        return false;
    };
    let Ok(listener) = TcpListener::bind(("127.0.0.1", requested)).await else {
        return false;
    };
    let Ok(bound) = listener.local_addr() else {
        return false;
    };
    *port = u32::from(bound.port());
    let (addr, p) = (address.to_owned(), *port);
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let handle = handle.clone();
            let addr = addr.clone();
            tokio::spawn(async move {
                let opened = handle
                    .channel_open_forwarded_tcpip(
                        addr,
                        p,
                        peer.ip().to_string(),
                        u32::from(peer.port()),
                    )
                    .await;
                if let Ok(channel) = opened {
                    splice(stream, channel).await;
                }
            });
        }
    });
    listeners.lock().expect("lock").insert((address.to_owned(), *port), task);
    true
}

/// `cancel-tcpip-forward`.
pub fn cancel(listeners: &Listeners, address: &str, port: u32) -> bool {
    match listeners.lock().expect("lock").remove(&(address.to_owned(), port)) {
        Some(task) => {
            task.abort();
            true
        }
        None => false,
    }
}
