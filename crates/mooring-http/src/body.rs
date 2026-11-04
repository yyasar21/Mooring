//! Capped response bodies. The cap is checked against `Content-Length` before the first byte
//! and against every frame before it is copied (review 5: no allocation before the check).

use std::future::Future as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use zeroize::Zeroizing;

use crate::config::STREAM_CHUNK;
use crate::error::HttpError;

/// Read the whole body into a zeroizing buffer, failing as soon as it would exceed `cap`.
/// The buffer grows by frame size, never by a server-declared length.
pub(crate) async fn read_capped(
    mut body: Incoming,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let mut out = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| HttpError::Protocol)?;
        if let Ok(data) = frame.into_data() {
            if data.len() > cap - out.len() {
                return Err(HttpError::BodyTooLarge { cap });
            }
            // Grow with headroom ourselves so old (secret) buffers are zeroized, not freed.
            if out.capacity() - out.len() < data.len() {
                let want = (out.len() + data.len()).max(out.capacity() * 2).min(cap);
                let mut bigger = Zeroizing::new(Vec::with_capacity(want));
                bigger.extend_from_slice(&out);
                out = bigger;
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// A streamed body (`get_stream`): chunks of at most 64 KiB, at most `total_cap` bytes; the
/// bytes up to the cap are delivered, then the stream ends with [`BodyStream::truncated`].
#[derive(Debug)]
pub struct BodyStream {
    body: Incoming,
    pending: Bytes,
    remaining: usize,
    truncated: bool,
    done: bool,
}

impl BodyStream {
    pub(crate) fn new(body: Incoming, total_cap: usize) -> Self {
        Self { body, pending: Bytes::new(), remaining: total_cap, truncated: false, done: false }
    }

    /// The next chunk (≤ 64 KiB), `None` at the end or at the cap.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        loop {
            if self.done {
                return Ok(None);
            }
            if !self.pending.is_empty() {
                let n = self.pending.len().min(STREAM_CHUNK).min(self.remaining);
                if n == 0 {
                    self.truncated = true;
                    self.done = true;
                    return Ok(None);
                }
                self.remaining -= n;
                return Ok(Some(self.pending.split_to(n)));
            }
            match self.body.frame().await {
                None => {
                    self.done = true;
                }
                Some(Err(_)) => {
                    self.done = true;
                    return Err(HttpError::Protocol);
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.pending = data;
                    }
                }
            }
        }
    }

    /// Whether the stream stopped at the total cap (more bytes were offered).
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// A body for the tower service: errors (instead of growing) once `cap` bytes have passed,
/// and, when built with a deadline, errors with [`HttpError::Timeout`] once the whole body
/// has taken longer than that budget (a dripped response cannot stay open for hours).
#[derive(Debug)]
pub struct CappedBody {
    inner: Incoming,
    remaining: usize,
    cap: usize,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl CappedBody {
    pub(crate) fn new(inner: Incoming, cap: usize) -> Self {
        Self { inner, remaining: cap, cap, deadline: None }
    }

    /// The same body with a total deadline for reading it (must be called in a Tokio
    /// runtime context).
    pub(crate) fn with_deadline(mut self, budget: std::time::Duration) -> Self {
        self.deadline = Some(Box::pin(tokio::time::sleep(budget)));
        self
    }
}

impl Body for CappedBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, HttpError>>> {
        let this = self.get_mut();
        if let Some(d) = this.deadline.as_mut() {
            if d.as_mut().poll(cx).is_ready() {
                this.remaining = 0;
                return Poll::Ready(Some(Err(HttpError::Timeout)));
            }
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if data.len() > this.remaining {
                        this.remaining = 0;
                        return Poll::Ready(Some(Err(HttpError::BodyTooLarge { cap: this.cap })));
                    }
                    this.remaining -= data.len();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => Poll::Ready(Some(Err(HttpError::Protocol))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
