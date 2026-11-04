//! [`HttpService`]: the client as a `tower` service, for `kube::Client::new(service, ns)`
//! (ADR-0014 §2). K3 stacks its `ReadOnlyGuard` on top of it.
//!
//! Same connector, verifier, rate limit, concurrency slots and head deadline as the helpers.
//! Requests may carry a path-only URI (joined to the base) or an absolute URI of the base
//! origin; any other authority is refused. No retries (the body is not replayable), redirects
//! refused, response bodies capped ([`CappedBody`]). Upgrades (`exec`, `portforward`) work:
//! the response keeps hyper's upgrade handle.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::USER_AGENT;
use http::{HeaderValue, Request, Response};
use http_body_util::BodyExt as _;

use crate::body::CappedBody;
use crate::client::{log, BoxError, HttpClient};
use crate::config::MAX_BODY_CEILING;
use crate::error::HttpError;
use crate::headers::mark_sensitive;
use crate::parse::content_length;

/// `tower::Service<Request<B>>` over an [`HttpClient`].
#[derive(Debug, Clone)]
pub struct HttpService {
    client: HttpClient,
    cap: usize,
}

impl HttpClient {
    /// A tower service whose response bodies are capped at `body_cap` (≤ 256 MiB; e.g. 16 MiB
    /// for kube lists, larger for a log stream service).
    pub fn service(&self, body_cap: usize) -> Result<HttpService, HttpError> {
        if body_cap == 0 || body_cap > MAX_BODY_CEILING {
            return Err(HttpError::InvalidRequest("body_cap must be 1..=256 MiB"));
        }
        Ok(HttpService { client: self.clone(), cap: body_cap })
    }
}

impl HttpService {
    async fn call_inner<B>(self, req: Request<B>) -> Result<Response<CappedBody>, HttpError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let base = &self.client.inner.base;
        let (mut parts, body) = req.into_parts();
        let uri = if parts.uri.authority().is_some() {
            if !base.same_origin(&parts.uri) {
                return Err(HttpError::InvalidRequest("request URI names another origin"));
            }
            let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
            base.uri(pq.strip_prefix(&base.prefix).unwrap_or(pq))?
        } else {
            let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
            base.uri(pq)?
        };
        parts.uri = uri;
        mark_sensitive(&mut parts.headers);
        let ua = HeaderValue::from_str(&self.client.inner.cfg.user_agent)
            .map_err(|_| HttpError::InvalidConfig("user_agent"))?;
        parts.headers.insert(USER_AGENT, ua);
        let method = parts.method.clone();
        let body = body.map_err(Into::into).boxed_unsync();
        let resp = self.client.send_once(Request::from_parts(parts, body)).await?;
        log(&method, &resp);
        if resp.status().is_redirection() && resp.status() != http::StatusCode::NOT_MODIFIED {
            return Err(HttpError::Redirect { status: resp.status() });
        }
        content_length(resp.headers(), self.cap)?;
        let cap = self.cap;
        Ok(resp.map(|b| CappedBody::new(b, cap)))
    }
}

impl<B> tower_service::Service<Request<B>> for HttpService
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response<CappedBody>;
    type Error = HttpError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        Box::pin(self.clone().call_inner(req))
    }
}
