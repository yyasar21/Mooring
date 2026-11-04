//! Allow-list classification, auth, RBAC and the JSON endpoints of the kube mock.

use std::sync::Arc;

use http::{Method, StatusCode};
use serde_json::{json, Value};

use super::fixtures::{namespace_json, status, AccessRule};
use super::{lock, KubeConfig, KubeState};
use crate::http::{json, Ctx, Handler, HandlerFuture, HttpKnobs, Reply};

/// A request on the ADR-0014 §4 allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Route {
    Version,
    Api,
    Apis,
    Namespaces,
    Namespace(String),
    Pods(String),
    Pod(String, String),
    Log(String, String),
    Exec(String, String),
    PortForward(String, String),
    AccessReview,
    RulesReview,
    SelfReview,
}

/// RFC 1123 subdomain (≤ 253, lowercase alphanumerics, `-`, `.`; alphanumeric at both ends).
fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 253
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.'))
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && !s.contains("..")
}

/// Maps `(method, path, query)` to an allowed [`Route`], or names the violation.
pub(super) fn classify(
    method: &Method,
    path: &str,
    query: &[(String, String)],
) -> Result<Route, String> {
    if let Some((k, _)) = query.iter().find(|(k, _)| k == "dryRun" || k == "fieldManager") {
        return Err(format!("query parameter {k} is refused (mutation helper)"));
    }
    let deny = || format!("{method} {path} is not on the ADR-0014 allow-list");
    let segs: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
    let get = *method == Method::GET;
    let post = *method == Method::POST;
    let names_ok = |names: &[&str]| names.iter().all(|n| valid_name(n));
    let route = match segs.as_slice() {
        ["version"] if get => Route::Version,
        ["api"] if get => Route::Api,
        ["apis"] if get => Route::Apis,
        ["api", "v1", "namespaces"] if get => Route::Namespaces,
        ["api", "v1", "namespaces", ns] if get && names_ok(&[ns]) => {
            Route::Namespace((*ns).to_owned())
        }
        ["api", "v1", "namespaces", ns, "pods"] if get && names_ok(&[ns]) => {
            Route::Pods((*ns).to_owned())
        }
        ["api", "v1", "namespaces", ns, "pods", pod] if get && names_ok(&[ns, pod]) => {
            Route::Pod((*ns).to_owned(), (*pod).to_owned())
        }
        ["api", "v1", "namespaces", ns, "pods", pod, sub] if get && names_ok(&[ns, pod]) => {
            let (ns, pod) = ((*ns).to_owned(), (*pod).to_owned());
            match *sub {
                "log" => Route::Log(ns, pod),
                "exec" => Route::Exec(ns, pod),
                "portforward" => Route::PortForward(ns, pod),
                _ => return Err(deny()),
            }
        }
        ["apis", "authorization.k8s.io", "v1", "selfsubjectaccessreviews"] if post => {
            Route::AccessReview
        }
        ["apis", "authorization.k8s.io", "v1", "selfsubjectrulesreviews"] if post => {
            Route::RulesReview
        }
        ["apis", "authentication.k8s.io", "v1", "selfsubjectreviews"] if post => Route::SelfReview,
        _ => return Err(deny()),
    };
    Ok(route)
}

impl Handler for KubeState {
    fn http_knobs(&self) -> HttpKnobs {
        lock(&self.config).http.clone()
    }

    fn handle(self: Arc<Self>, ctx: Ctx) -> HandlerFuture {
        Box::pin(async move { self.route(ctx).await })
    }
}

fn reply(code: StatusCode, v: &Value) -> Reply {
    json(code, v).into()
}

fn err(code: StatusCode, reason: &str, message: &str) -> Reply {
    reply(code, &status(code.as_u16(), reason, message))
}

/// The user the request authenticates as: bearer token first, then a verified client cert.
fn authenticate(ctx: &Ctx, cfg: &KubeConfig) -> Option<String> {
    let bearer = ctx.header("authorization").and_then(|v| v.strip_prefix("Bearer "));
    match (bearer, &cfg.token) {
        (Some(t), Some(ok)) if t == ok => return Some(cfg.user.clone()),
        (Some(_), _) => return None,
        _ => {}
    }
    (cfg.client_cert_auth && ctx.client_cert.is_some()).then(|| cfg.cert_user.clone())
}

fn allowed(rules: &[AccessRule], verb: &str, resource: &str, ns: Option<&str>) -> bool {
    rules.iter().any(|r| r.allows(verb, resource, ns))
}

/// 403 in the API server's wording when RBAC denies `verb resource` (in `ns`).
pub(super) fn rbac(
    cfg: &KubeConfig,
    user: &str,
    verb: &str,
    resource: &str,
    ns: Option<&str>,
) -> Option<Reply> {
    if allowed(&cfg.rules, verb, resource, ns) {
        return None;
    }
    let (res, sub) = resource.split_once('/').map_or((resource, None), |(r, s)| (r, Some(s)));
    let what =
        sub.map_or_else(|| format!("resource \"{res}\""), |s| format!("resource \"{res}/{s}\""));
    let scope = ns
        .map_or_else(|| "at the cluster scope".to_owned(), |n| format!("in the namespace \"{n}\""));
    let msg = format!(
        "{resource} is forbidden: User \"{user}\" cannot {verb} {what} in API group \"\" {scope}"
    );
    Some(err(StatusCode::FORBIDDEN, "Forbidden", &msg))
}

/// `limit` / `continue` (opaque `c<offset>`) over `items`.
fn paginate(ctx: &Ctx, items: &[Value]) -> Result<(Vec<Value>, Option<String>), Box<Reply>> {
    let limit = ctx.query_get("limit").and_then(|l| l.parse::<usize>().ok()).unwrap_or(0);
    let start = match ctx.query_get("continue").filter(|c| !c.is_empty()) {
        None => 0,
        Some(c) => match c.strip_prefix('c').and_then(|n| n.parse::<usize>().ok()) {
            Some(n) if n <= items.len() => n,
            _ => {
                return Err(Box::new(err(
                    StatusCode::GONE,
                    "Expired",
                    "the provided continue parameter is too old",
                )))
            }
        },
    };
    let end = if limit == 0 { items.len() } else { (start + limit).min(items.len()) };
    let next = (end < items.len()).then(|| format!("c{end}"));
    Ok((items[start..end].to_vec(), next))
}

fn list(kind: &str, items: &[Value], next: Option<String>, pad: Option<usize>) -> Reply {
    let mut meta = json!({ "resourceVersion": "1" });
    if let Some(c) = next {
        meta["continue"] = Value::String(c);
    }
    let mut v = json!({ "kind": kind, "apiVersion": "v1", "metadata": meta, "items": items });
    if let Some(n) = pad {
        v["mooringPadding"] = Value::String("x".repeat(n));
    }
    reply(StatusCode::OK, &v)
}

impl KubeState {
    async fn route(self: Arc<Self>, ctx: Ctx) -> Reply {
        let route = match classify(&ctx.method, &ctx.path, &ctx.query()) {
            Ok(r) => r,
            Err(reason) => return Reply::violation(reason),
        };
        let cfg = self.config();
        if let Some(r) = discovery(&route, &cfg) {
            return r;
        }
        let Some(user) = authenticate(&ctx, &cfg).filter(|_| !cfg.knobs.force_401) else {
            return err(StatusCode::UNAUTHORIZED, "Unauthorized", "Unauthorized");
        };
        if cfg.knobs.force_403 {
            return err(StatusCode::FORBIDDEN, "Forbidden", "forbidden by the force_403 knob");
        }
        let ns_known = |ns: &str| cfg.namespaces.iter().any(|n| n == ns);
        let not_found = |what: &str, name: &str| {
            err(StatusCode::NOT_FOUND, "NotFound", &format!("{what} \"{name}\" not found"))
        };
        match route {
            Route::Namespaces => {
                if let Some(r) = rbac(&cfg, &user, "list", "namespaces", None) {
                    return r;
                }
                let items: Vec<Value> = cfg.namespaces.iter().map(|n| namespace_json(n)).collect();
                match paginate(&ctx, &items) {
                    Ok((items, next)) => {
                        list("NamespaceList", &items, next, cfg.knobs.oversized_body)
                    }
                    Err(r) => *r,
                }
            }
            Route::Namespace(ns) => {
                if let Some(r) = rbac(&cfg, &user, "get", "namespaces", None) {
                    return r;
                }
                if !ns_known(&ns) {
                    return not_found("namespaces", &ns);
                }
                reply(StatusCode::OK, &namespace_json(&ns))
            }
            Route::Pods(ns) => {
                let watch = ctx.query_get("watch").is_some_and(|w| w == "1" || w == "true");
                let verb = if watch { "watch" } else { "list" };
                if let Some(r) = rbac(&cfg, &user, verb, "pods", Some(&ns)) {
                    return r;
                }
                if !ns_known(&ns) {
                    return not_found("namespaces", &ns);
                }
                let selector = ctx.query_get("labelSelector").unwrap_or_default();
                let pods: Vec<_> = cfg
                    .pods
                    .iter()
                    .filter(|p| p.namespace == ns && p.matches_selector(&selector))
                    .cloned()
                    .collect();
                if watch {
                    return self.watch(&ctx, &ns, pods);
                }
                let items: Vec<Value> = pods.iter().map(super::PodFixture::to_json).collect();
                match paginate(&ctx, &items) {
                    Ok((items, next)) => list("PodList", &items, next, cfg.knobs.oversized_body),
                    Err(r) => *r,
                }
            }
            Route::Pod(ns, pod) => {
                if let Some(r) = rbac(&cfg, &user, "get", "pods", Some(&ns)) {
                    return r;
                }
                match cfg.pods.iter().find(|p| p.namespace == ns && p.name == pod) {
                    Some(p) => reply(StatusCode::OK, &p.to_json()),
                    None => not_found("pods", &pod),
                }
            }
            Route::Log(ns, pod) => Self::log(&ctx, &cfg, &user, &ns, &pod),
            Route::Exec(ns, pod) => self.exec(ctx, &cfg, &user, &ns, &pod),
            Route::PortForward(ns, pod) => self.port_forward(ctx, &cfg, &user, &ns, &pod),
            Route::AccessReview => access_review(&ctx, &cfg),
            Route::RulesReview => rules_review(&ctx, &cfg),
            Route::SelfReview => {
                let groups = &cfg.groups;
                let v = json!({ "kind": "SelfSubjectReview", "apiVersion": "authentication.k8s.io/v1",
                    "metadata": { "creationTimestamp": null },
                    "status": { "userInfo": { "username": user, "groups": groups } } });
                reply(StatusCode::CREATED, &v)
            }
            Route::Version | Route::Api | Route::Apis => unreachable_discovery(),
        }
    }
}

fn unreachable_discovery() -> Reply {
    err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "discovery handled above")
}

/// `/version`, `/api`, `/apis` (no auth needed, as `system:public-info-viewer` allows).
fn discovery(route: &Route, cfg: &KubeConfig) -> Option<Reply> {
    let v = match route {
        Route::Version => json!({ "major": "1", "minor": "30", "gitVersion": cfg.git_version,
                                  "platform": "linux/amd64" }),
        Route::Api => json!({ "kind": "APIVersions", "versions": ["v1"],
            "serverAddressByClientCIDRs": [{ "clientCIDR": "0.0.0.0/0", "serverAddress": "192.0.2.10:6443" }] }),
        Route::Apis => api_groups(),
        _ => return None,
    };
    Some(reply(StatusCode::OK, &v))
}

fn api_groups() -> Value {
    let group = |name: &str| {
        let gv = format!("{name}/v1");
        json!({ "name": name, "versions": [{ "groupVersion": gv, "version": "v1" }],
                "preferredVersion": { "groupVersion": gv, "version": "v1" } })
    };
    json!({ "kind": "APIGroupList", "apiVersion": "v1",
            "groups": [group("authorization.k8s.io"), group("authentication.k8s.io")] })
}

fn access_review(ctx: &Ctx, cfg: &KubeConfig) -> Reply {
    let Some(body) = ctx.json_body() else {
        return err(StatusCode::BAD_REQUEST, "BadRequest", "invalid SelfSubjectAccessReview body");
    };
    let attrs = &body["spec"]["resourceAttributes"];
    let s = |k: &str| attrs[k].as_str().unwrap_or("").to_owned();
    let (verb, res, sub, ns) = (s("verb"), s("resource"), s("subresource"), s("namespace"));
    let resource = if sub.is_empty() { res } else { format!("{res}/{sub}") };
    let ok = attrs.is_object()
        && allowed(&cfg.rules, &verb, &resource, (!ns.is_empty()).then_some(ns.as_str()));
    let mut out = body.clone();
    out["kind"] = json!("SelfSubjectAccessReview");
    out["apiVersion"] = json!("authorization.k8s.io/v1");
    out["status"] = if ok {
        json!({ "allowed": true, "reason": "RBAC: allowed by the mock rule set" })
    } else {
        json!({ "allowed": false })
    };
    reply(StatusCode::CREATED, &out)
}

fn rules_review(ctx: &Ctx, cfg: &KubeConfig) -> Reply {
    let ns = ctx.json_body().and_then(|b| b["spec"]["namespace"].as_str().map(str::to_owned));
    let Some(ns) = ns.filter(|n| !n.is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "BadRequest", "no namespace on request");
    };
    let rules: Vec<Value> = cfg
        .rules
        .iter()
        .filter(|r| r.namespaces.as_ref().is_none_or(|l| l.contains(&ns)))
        .map(AccessRule::to_json)
        .collect();
    let v = json!({ "kind": "SelfSubjectRulesReview", "apiVersion": "authorization.k8s.io/v1",
        "spec": { "namespace": ns },
        "status": { "resourceRules": rules, "nonResourceRules": [], "incomplete": false } });
    reply(StatusCode::CREATED, &v)
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::{classify, Route};

    fn c(m: &Method, p: &str) -> Result<Route, String> {
        classify(m, p, &[])
    }

    #[test]
    fn allow_list_matrix() {
        assert_eq!(c(&Method::GET, "/version"), Ok(Route::Version));
        assert!(matches!(
            c(&Method::GET, "/api/v1/namespaces/default/pods/web-0/exec"),
            Ok(Route::Exec(..))
        ));
        assert!(c(&Method::POST, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews").is_ok());
        for (m, p) in [
            (Method::GET, "/api/v1/namespaces/default/secrets"),
            (Method::GET, "/api/v1/namespaces/default/configmaps/x"),
            (Method::GET, "/api/v1/secrets"),
            (Method::DELETE, "/api/v1/namespaces/default/pods/web-0"),
            (Method::PATCH, "/api/v1/namespaces/default/pods/web-0"),
            (Method::PUT, "/api/v1/namespaces/default"),
            (Method::POST, "/api/v1/namespaces/default/pods"),
            (Method::POST, "/api/v1/namespaces/default/pods/web-0/exec"),
            (Method::GET, "/api/v1/namespaces/../pods"),
            (Method::GET, "/api/v1/namespaces/a%2Fb/pods"),
            (Method::GET, "/api/v1/namespaces/Default/pods"),
            (Method::GET, "/api/v1/namespaces/default/events"),
            (Method::GET, "/apis/apps/v1/deployments"),
        ] {
            assert!(c(&m, p).is_err(), "{m} {p} must be a violation");
        }
        let q = [("dryRun".to_owned(), "All".to_owned())];
        assert!(classify(&Method::GET, "/api/v1/namespaces", &q).is_err());
    }
}
