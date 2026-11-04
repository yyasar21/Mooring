//! Response body: a fixed buffer (exact `Content-Length`) or a channel-fed stream (chunked:
//! kube log follow / watch, huge-log and slow-loris knobs).

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_LENGTH};
use http::Response;
use http_body::{Frame, SizeHint};
use tokio::sync::mpsc;

/// Response body of every mock server.
#[derive(Debug)]
pub enum Body {
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl Body {
    pub fn full(b: impl Into<Bytes>) -> Self {
        Self::Full(Some(b.into()))
    }

    /// A streamed body and its feeding end; the body ends when the sender is dropped.
    pub fn channel(buffer: usize) -> (mpsc::Sender<Bytes>, Self) {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        (tx, Self::Stream(rx))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Self::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Stream(rx) => rx.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(Some(b)) => SizeHint::with_exact(u64::try_from(b.len()).unwrap_or(u64::MAX)),
            Self::Full(None) => SizeHint::with_exact(0),
            Self::Stream(_) => SizeHint::default(),
        }
    }
}

/// Re-sends a fixed body one byte per `gap`, announcing the full `Content-Length` first.
pub(super) fn drip(resp: Response<Body>, gap: Duration) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    let Body::Full(Some(data)) = body else { return Response::from_parts(parts, body) };
    if let Ok(v) = HeaderValue::from_str(&data.len().to_string()) {
        parts.headers.insert(CONTENT_LENGTH, v);
    }
    let (tx, body) = Body::channel(1);
    tokio::spawn(async move {
        for i in 0..data.len() {
            tokio::time::sleep(gap).await;
            if tx.send(data.slice(i..=i)).await.is_err() {
                return;
            }
        }
    });
    Response::from_parts(parts, body)
}
