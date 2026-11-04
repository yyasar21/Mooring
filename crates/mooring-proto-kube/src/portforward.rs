//! Pod port-forward (ADR-0014 §5): one `pods/portforward` WebSocket (`v4.channel.k8s.io`, one
//! port) per local connection, exposed as `AsyncRead + AsyncWrite` ([`PortForwardStream`]),
//! plus a loopback-only listener ([`PodForward`]) for the ADR-0010 Forwards panel. External
//! exposure is not offered in A3: a non-loopback bind is refused (same rule as
//! `mooring_proto_ssh::Exposure::Loopback`).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{SinkExt as _, StreamExt as _};
use mooring_core::SessionAudit;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::audit::{AuditSink, KubeAudit};
use crate::browse::{check_ns, check_pod};
use crate::client::{KubeClient, KubeWs};
use crate::error::KubeError;
use crate::frame::{encode, PfDecoder, PfEvent};

/// Sub-protocol of the port-forward WebSocket.
pub const PF_PROTOCOLS: [&str; 1] = ["v4.channel.k8s.io"];
/// Concurrent connections per forward (ADR-0007 value).
pub const MAX_CONNECTIONS_PER_FORWARD: usize = 128;
/// Copy buffer.
pub const COPY_BUFFER: usize = 32 * 1024;

/// Pod side of a forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodTarget {
    /// Namespace.
    pub namespace: String,
    /// Pod.
    pub pod: String,
    /// Container port.
    pub port: u16,
}

impl PodTarget {
    /// `ns/pod:port` (UI and audit form).
    pub fn display(&self) -> String {
        format!("{}/{}:{}", self.namespace, self.pod, self.port)
    }

    fn path(&self) -> Result<String, KubeError> {
        check_ns(&self.namespace)?;
        check_pod(&self.pod)?;
        if self.port == 0 {
            return Err(KubeError::Invalid("port must be 1-65535"));
        }
        Ok(format!(
            "/api/v1/namespaces/{}/pods/{}/portforward?ports={}",
            self.namespace, self.pod, self.port
        ))
    }
}

/// One forwarded connection as a byte stream. Dropping it ends the WebSocket.
#[derive(Debug)]
pub struct PortForwardStream {
    io: DuplexStream,
    task: JoinHandle<()>,
}

impl Drop for PortForwardStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AsyncRead for PortForwardStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for PortForwardStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Bridge the WebSocket and the local half until either side ends.
async fn bridge(mut ws: KubeWs, mut local: DuplexStream, port: u16) {
    let mut dec = PfDecoder::new(port);
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Binary(b))) => match dec.feed(&b) {
                    Ok(PfEvent::Header) => {}
                    Ok(PfEvent::Data(d)) => {
                        if local.write_all(d).await.is_err() {
                            break;
                        }
                    }
                    Ok(PfEvent::Error(e)) => {
                        if !e.is_empty() {
                            tracing::debug!("pod port-forward ended by the kubelet");
                            break;
                        }
                    }
                    Err(_) => {
                        tracing::debug!("pod port-forward: malformed frame");
                        break;
                    }
                },
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            n = local.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws.send(Message::Binary(encode(0, &buf[..n]).into())).await.is_err() {
                        break;
                    }
                }
            },
        }
    }
    let _ = local.shutdown().await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), ws.close(None)).await;
}

impl KubeClient {
    /// Open one forwarded stream to `target`.
    pub async fn port_forward(&self, target: &PodTarget) -> Result<PortForwardStream, KubeError> {
        if !self.limits.port_forward_enabled {
            return Err(KubeError::Invalid("port-forward is disabled for this connection"));
        }
        let path = target.path()?;
        let (ws, _) = self.upgrade(&path, &PF_PROTOCOLS).await?;
        let (io, local) = tokio::io::duplex(COPY_BUFFER * 2);
        let task = tokio::spawn(bridge(ws, local, target.port));
        Ok(PortForwardStream { io, task })
    }
}

/// A loopback listener forwarding every accepted connection to a pod port.
#[derive(Debug)]
pub struct PodForward {
    id: String,
    bind: SocketAddr,
    target: PodTarget,
    connections: Arc<AtomicUsize>,
    task: Option<JoinHandle<()>>,
    audit: AuditSink,
}

impl PodForward {
    /// Bind `bind` (loopback only; port 0 picks one) and start accepting. Records
    /// `session.forward.open` with kind `pod`. `id` is the session-local id (e.g. `fwd-3`).
    pub async fn open(
        client: &KubeClient,
        id: &str,
        bind: SocketAddr,
        target: PodTarget,
    ) -> Result<Self, KubeError> {
        if !bind.ip().is_loopback() {
            return Err(KubeError::Invalid("pod forwards bind to loopback only in this version"));
        }
        if !client.limits.port_forward_enabled {
            return Err(KubeError::Invalid("port-forward is disabled for this connection"));
        }
        target.path()?;
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| KubeError::Invalid("could not bind the local port"))?;
        let bind = listener.local_addr().map_err(|_| KubeError::Invalid("local address"))?;
        let connections = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(accept_loop(
            listener,
            client.clone(),
            target.clone(),
            Arc::clone(&connections),
        ));
        let audit = client.audit.clone();
        audit.push(KubeAudit::Session(SessionAudit::ForwardOpened {
            id: id.to_owned(),
            kind: "pod",
            bind: bind.to_string(),
            target: target.display(),
            exposure: "loopback",
        }));
        Ok(Self { id: id.to_owned(), bind, target, connections, task: Some(task), audit })
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.bind
    }

    /// The pod side.
    pub fn target(&self) -> &PodTarget {
        &self.target
    }

    /// Open connections.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Stop listening and drop every connection; records `session.forward.close`.
    pub fn close(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            self.audit.push(KubeAudit::Session(SessionAudit::ForwardClosed {
                id: self.id.clone(),
                kind: "pod",
                bind: self.bind.to_string(),
                target: self.target.display(),
            }));
        }
    }
}

impl Drop for PodForward {
    fn drop(&mut self) {
        self.close();
    }
}

async fn accept_loop(
    listener: TcpListener,
    client: KubeClient,
    target: PodTarget,
    count: Arc<AtomicUsize>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_FORWARD));
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((mut tcp, _)) = accepted else { continue };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(tcp);
                    continue;
                };
                let (client, target, count) = (client.clone(), target.clone(), Arc::clone(&count));
                conns.spawn(async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut stream) = client.port_forward(&target).await {
                        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                    }
                    count.fetch_sub(1, Ordering::Relaxed);
                    drop(permit);
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}
