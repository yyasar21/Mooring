//! [`ReadOnlyGuard`] (ADR-0014 §4): a tower layer under `kube::Client` that matches every
//! request's `(method, path template, query)` against a closed allow-list **before** the
//! request leaves the process. Anything else is refused locally ([`Refused`],
//! `kube.forbidden_request`) and recorded as `kube.request_refused`.
//!
//! Matching is deliberately literal: the path must be plain ASCII with no percent-encoding,
//! no `;`, no empty, `.` or `..` segment, no trailing `/`; `{ns}` / `{container}` are RFC 1123
//! labels and `{pod}` an RFC 1123 subdomain (K2's helpers). Query keys are raw ASCII names from
//! a per-route allow-list (so `dryRun`, `fieldManager`, `dry%52un` never match), each at most
//! once; values are percent-decoded and then checked per key.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Method, Request};
use mooring_core::credential::kubeconfig::{is_dns_label, is_dns_subdomain};
use mooring_core::options::ExecCommand;
use tower::{BoxError, Layer, Service};

use crate::audit::{AuditSink, KubeAudit};
use crate::query::{parse_query, QueryRule, RuleKind};

/// Longest path + query the guard looks at.
pub const MAX_GUARD_URI: usize = 8 * 1024;
/// `tailLines` ceiling per request (ADR-0014 §5; K2 decision: requests clamp to this).
pub const MAX_TAIL_LINES: u64 = 10_000;
/// Largest `limit` of a list page (ADR-0014 §5).
pub const MAX_LIST_LIMIT: u64 = 500;

/// One allow-listed endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    /// `GET /version`.
    Version,
    /// `GET /api`.
    Api,
    /// `GET /apis`.
    Apis,
    /// `GET /api/v1/namespaces`.
    Namespaces,
    /// `GET /api/v1/namespaces/{ns}`.
    Namespace,
    /// `GET /api/v1/namespaces/{ns}/pods` (list or `watch=1`).
    Pods,
    /// `GET /api/v1/namespaces/{ns}/pods/{pod}`.
    Pod,
    /// `GET /api/v1/namespaces/{ns}/pods/{pod}/log`.
    PodLog,
    /// `GET`+Upgrade `/api/v1/namespaces/{ns}/pods/{pod}/exec`.
    PodExec,
    /// `GET`+Upgrade `/api/v1/namespaces/{ns}/pods/{pod}/portforward`.
    PodPortForward,
    /// `POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews`.
    AccessReview,
    /// `POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews`.
    RulesReview,
    /// `POST /apis/authentication.k8s.io/v1/selfsubjectreviews`.
    SelfReview,
}

impl Route {
    /// The path template (for audit; never the concrete names).
    pub const fn template(self) -> &'static str {
        match self {
            Self::Version => "/version",
            Self::Api => "/api",
            Self::Apis => "/apis",
            Self::Namespaces => "/api/v1/namespaces",
            Self::Namespace => "/api/v1/namespaces/{ns}",
            Self::Pods => "/api/v1/namespaces/{ns}/pods",
            Self::Pod => "/api/v1/namespaces/{ns}/pods/{pod}",
            Self::PodLog => "/api/v1/namespaces/{ns}/pods/{pod}/log",
            Self::PodExec => "/api/v1/namespaces/{ns}/pods/{pod}/exec",
            Self::PodPortForward => "/api/v1/namespaces/{ns}/pods/{pod}/portforward",
            Self::AccessReview => "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            Self::RulesReview => "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            Self::SelfReview => "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        }
    }

    /// Every route (for tests and documentation).
    pub const ALL: [Self; 13] = [
        Self::Version,
        Self::Api,
        Self::Apis,
        Self::Namespaces,
        Self::Namespace,
        Self::Pods,
        Self::Pod,
        Self::PodLog,
        Self::PodExec,
        Self::PodPortForward,
        Self::AccessReview,
        Self::RulesReview,
        Self::SelfReview,
    ];

    fn kind(self) -> Kind {
        match self {
            Self::PodExec | Self::PodPortForward => Kind::Upgrade,
            Self::AccessReview | Self::RulesReview | Self::SelfReview => Kind::Post,
            _ => Kind::Read,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Upgrade,
    Post,
}

/// A request the guard refused. `Display` is static text; neither the path nor the query is
/// kept (only the method, when it is a standard one, and the matched template, if any).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("request refused by the read-only guard: {reason}")]
pub struct Refused {
    /// Upper-case standard method name, or `OTHER`.
    pub method: &'static str,
    /// The route template when the path matched one, `unlisted` otherwise.
    pub template: &'static str,
    /// Why (static).
    pub reason: &'static str,
}

fn method_name(m: &Method) -> &'static str {
    match *m {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

/// Policy values the guard needs besides the fixed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardPolicy {
    /// `limitBytes` ceiling (the connection's `maxLogBytes`).
    pub max_log_bytes: u64,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self { max_log_bytes: 8 * 1024 * 1024 }
    }
}

/// What the guard sees of a request.
#[derive(Debug, Clone, Copy)]
pub struct RequestShape<'a> {
    /// Method.
    pub method: &'a Method,
    /// `path[?query]` (an absolute URI is refused).
    pub uri: &'a http::Uri,
    /// `Upgrade: websocket` + `Connection: upgrade` present.
    pub websocket: bool,
    /// Any `Impersonate-*` header present.
    pub impersonates: bool,
}

impl<'a> RequestShape<'a> {
    /// The shape of an `http::Request`.
    pub fn of<B>(req: &'a Request<B>) -> Self {
        let h = req.headers();
        let has = |name: http::header::HeaderName, want: &str| {
            h.get_all(name).iter().any(|v| {
                v.to_str().is_ok_and(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(want)))
            })
        };
        let websocket =
            has(http::header::UPGRADE, "websocket") && has(http::header::CONNECTION, "upgrade");
        let impersonates =
            h.keys().any(|k| k.as_str().to_ascii_lowercase().starts_with("impersonate-"));
        Self { method: req.method(), uri: req.uri(), websocket, impersonates }
    }
}

/// The decision for one request: `Ok(route)` or the refusal.
pub fn check(shape: RequestShape<'_>, policy: GuardPolicy) -> Result<Route, Refused> {
    let method = method_name(shape.method);
    let refuse =
        |template: &'static str, reason: &'static str| Refused { method, template, reason };
    if shape.uri.scheme().is_some() || shape.uri.authority().is_some() {
        return Err(refuse("unlisted", "absolute request URIs are not allowed"));
    }
    let pq = shape.uri.path_and_query().map_or("", |p| p.as_str());
    if pq.len() > MAX_GUARD_URI {
        return Err(refuse("unlisted", "request URI too long"));
    }
    let (path, query) = match pq.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (pq, None),
    };
    let route = match_path(path).ok_or(refuse("unlisted", "path is not on the allow-list"))?;
    let template = route.template();
    if shape.impersonates {
        return Err(refuse(template, "impersonation headers are not allowed"));
    }
    let method_ok = match route.kind() {
        Kind::Read => {
            (*shape.method == Method::GET || *shape.method == Method::HEAD) && !shape.websocket
        }
        Kind::Upgrade => *shape.method == Method::GET && shape.websocket,
        Kind::Post => *shape.method == Method::POST && !shape.websocket,
    };
    if !method_ok {
        return Err(refuse(template, "method not allowed for this path"));
    }
    let query = query.unwrap_or("");
    parse_query(query, rules(route), policy).map_err(|r| refuse(template, r))?;
    let required = match route {
        Route::PodExec => Some("command"),
        Route::PodPortForward => Some("ports"),
        _ => None,
    };
    if let Some(key) = required {
        if !query.split('&').any(|p| p.split_once('=').is_some_and(|(k, _)| k == key)) {
            return Err(refuse(template, "required query parameter missing"));
        }
    }
    Ok(route)
}

/// Path → route. `None` for anything not literally on the list.
pub(crate) fn match_path(path: &str) -> Option<Route> {
    if !path.starts_with('/')
        || !path.bytes().all(|b| b.is_ascii_graphic())
        || path.contains(['%', ';', '\\', '#', '?'])
    {
        return None;
    }
    let segs: Vec<&str> = path[1..].split('/').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return None;
    }
    let route = match segs.as_slice() {
        ["version"] => Route::Version,
        ["api"] => Route::Api,
        ["apis"] => Route::Apis,
        ["api", "v1", "namespaces"] => Route::Namespaces,
        ["api", "v1", "namespaces", ns] if is_dns_label(ns) => Route::Namespace,
        ["api", "v1", "namespaces", ns, "pods"] if is_dns_label(ns) => Route::Pods,
        ["api", "v1", "namespaces", ns, "pods", pod, rest @ ..]
            if is_dns_label(ns) && is_dns_subdomain(pod) =>
        {
            match rest {
                [] => Route::Pod,
                ["log"] => Route::PodLog,
                ["exec"] => Route::PodExec,
                ["portforward"] => Route::PodPortForward,
                _ => return None,
            }
        }
        ["apis", "authorization.k8s.io", "v1", "selfsubjectaccessreviews"] => Route::AccessReview,
        ["apis", "authorization.k8s.io", "v1", "selfsubjectrulesreviews"] => Route::RulesReview,
        ["apis", "authentication.k8s.io", "v1", "selfsubjectreviews"] => Route::SelfReview,
        _ => return None,
    };
    Some(route)
}

fn rules(route: Route) -> &'static [QueryRule] {
    use RuleKind::{Bool, Command, Container, Continue, LimitBytes, ListLimit, Port, Selector};
    use RuleKind::{ResourceVersion, Seconds, TailLines};
    const LIST: &[QueryRule] = &[
        QueryRule { key: "limit", kind: ListLimit },
        QueryRule { key: "continue", kind: Continue },
    ];
    const PODS: &[QueryRule] = &[
        QueryRule { key: "limit", kind: ListLimit },
        QueryRule { key: "continue", kind: Continue },
        QueryRule { key: "labelSelector", kind: Selector },
        QueryRule { key: "watch", kind: Bool },
        QueryRule { key: "allowWatchBookmarks", kind: Bool },
        QueryRule { key: "resourceVersion", kind: ResourceVersion },
        QueryRule { key: "timeoutSeconds", kind: Seconds },
    ];
    const LOG: &[QueryRule] = &[
        QueryRule { key: "container", kind: Container },
        QueryRule { key: "follow", kind: Bool },
        QueryRule { key: "timestamps", kind: Bool },
        QueryRule { key: "tailLines", kind: TailLines },
        QueryRule { key: "limitBytes", kind: LimitBytes },
        QueryRule { key: "sinceSeconds", kind: Seconds },
    ];
    const EXEC: &[QueryRule] = &[
        QueryRule { key: "command", kind: Command },
        QueryRule { key: "container", kind: Container },
        QueryRule { key: "stdin", kind: Bool },
        QueryRule { key: "stdout", kind: Bool },
        QueryRule { key: "stderr", kind: Bool },
        QueryRule { key: "tty", kind: Bool },
    ];
    const PF: &[QueryRule] = &[QueryRule { key: "ports", kind: Port }];
    match route {
        Route::Namespaces => LIST,
        Route::Pods => PODS,
        Route::PodLog => LOG,
        Route::PodExec => EXEC,
        Route::PodPortForward => PF,
        _ => &[],
    }
}

/// Whether `s` is one of the owner-approved exec commands (decision 3).
pub(crate) fn is_allowed_command(s: &str) -> bool {
    ExecCommand::parse(s).is_some()
}

/// The layer: wrap the service under `kube::Client` with it.
#[derive(Debug, Clone)]
pub struct ReadOnlyGuardLayer {
    policy: GuardPolicy,
    audit: AuditSink,
}

impl ReadOnlyGuardLayer {
    /// A guard with `policy`, recording refusals into `audit`.
    pub fn new(policy: GuardPolicy, audit: AuditSink) -> Self {
        Self { policy, audit }
    }
}

impl<S> Layer<S> for ReadOnlyGuardLayer {
    type Service = ReadOnlyGuard<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ReadOnlyGuard { inner, policy: self.policy, audit: self.audit.clone() }
    }
}

/// The guarded service. A refusal is a [`Refused`] inside the `BoxError`.
#[derive(Debug, Clone)]
pub struct ReadOnlyGuard<S> {
    inner: S,
    policy: GuardPolicy,
    audit: AuditSink,
}

type BoxFut<T> = Pin<Box<dyn Future<Output = Result<T, BoxError>> + Send>>;

impl<S, B> Service<Request<B>> for ReadOnlyGuard<S>
where
    S: Service<Request<B>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFut<S::Response>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        match check(RequestShape::of(&req), self.policy) {
            Ok(_) => {
                let fut = self.inner.call(req);
                Box::pin(async move { fut.await.map_err(Into::into) })
            }
            Err(refused) => {
                tracing::warn!(
                    method = refused.method,
                    template = refused.template,
                    "kube request refused"
                );
                self.audit.push(KubeAudit::RequestRefused {
                    method: refused.method,
                    template: refused.template,
                });
                let err: BoxError = Box::new(refused);
                Box::pin(std::future::ready(Err(err)))
            }
        }
    }
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
