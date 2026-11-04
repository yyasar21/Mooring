//! In-process Vault mock on loopback plaintext (tests only). Synthetic values only.
//! TODO(merge): replace with `mooring-testsrv::vault` once QA lands it (ADR-0016 test plan).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

/// One token the mock knows.
#[derive(Debug, Clone)]
pub struct Tok {
    pub policies: Vec<&'static str>,
    pub ttl: u64,
    pub renewable: bool,
    pub kv: bool,
}

/// One KV version.
#[derive(Debug, Clone)]
pub struct Ver {
    pub data: Value,
    pub deleted: bool,
    pub destroyed: bool,
}

#[derive(Debug, Default)]
pub struct State {
    pub tokens: HashMap<String, Tok>,
    pub approle: Option<(String, String)>,
    pub approle_ttl: u64,
    pub renew_ttl: u64,
    pub kv: HashMap<String, Vec<Ver>>,
    pub sealed: bool,
    /// `path -> (status, body)` served verbatim.
    pub raw: HashMap<String, (u16, String)>,
    pub hits: Vec<String>,
    pub namespaces: Vec<Option<String>>,
    pub revoked: Vec<String>,
    pub issued: usize,
    pub oidc_nonce: Option<String>,
}

pub struct Mock {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<State>>,
}

impl Mock {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn hits(&self, path: &str) -> usize {
        self.with(|s| s.hits.iter().filter(|h| h.as_str() == path).count())
    }
}

pub const IDP_STATE: &str = "st-mock";
pub const GOOD_CODE: &str = "code-ok";

fn reply(status: u16, body: &Value) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body.to_string())));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::OK);
    r
}

fn auth(token: &str, t: &Tok) -> Value {
    json!({"auth": {"client_token": token, "accessor": "acc", "policies": t.policies,
                    "token_policies": t.policies, "lease_duration": t.ttl, "renewable": t.renewable}})
}

fn issue(s: &mut State, ttl: u64) -> (String, Tok) {
    s.issued += 1;
    let token = format!("hvs.mock-{}", s.issued);
    let t = Tok { policies: vec!["default", "app"], ttl, renewable: true, kv: true };
    s.tokens.insert(token.clone(), t.clone());
    (token, t)
}

fn query(q: &str, key: &str) -> Option<String> {
    q.split('&').find_map(|p| p.strip_prefix(&format!("{key}="))).map(str::to_owned)
}

fn kv_read(s: &State, rest: &str, q: &str) -> (u16, Value) {
    let Some(versions) = s.kv.get(rest) else { return (404, json!({"errors": []})) };
    let n = query(q, "version").and_then(|v| v.parse::<usize>().ok()).unwrap_or(versions.len());
    let Some(v) = n.checked_sub(1).and_then(|i| versions.get(i)) else {
        return (404, json!({"errors": []}));
    };
    let meta = json!({"version": n, "destroyed": v.destroyed,
                      "deletion_time": if v.deleted { "2026-11-01T00:00:00Z" } else { "" }});
    if v.deleted || v.destroyed {
        return (404, json!({"data": {"data": null, "metadata": meta}}));
    }
    (200, json!({"data": {"data": v.data, "metadata": meta}}))
}

#[allow(clippy::many_single_char_names)]
fn route(
    s: &mut State,
    method: &str,
    path: &str,
    q: &str,
    token: Option<&str>,
    body: &Value,
) -> (u16, Value) {
    let tok = token.and_then(|t| s.tokens.get(t).cloned());
    match (method, path) {
        ("GET", "/v1/auth/token/lookup-self") => match tok {
            Some(t) => (
                200,
                json!({"data": {"id": token, "policies": t.policies, "ttl": t.ttl,
                                              "renewable": t.renewable}}),
            ),
            None => (403, json!({"errors": ["permission denied"]})),
        },
        ("POST", "/v1/auth/token/renew-self") => match tok {
            Some(mut t) if t.renewable => {
                t.ttl = s.renew_ttl;
                s.tokens.insert(token.unwrap_or_default().to_owned(), t.clone());
                (200, auth(token.unwrap_or_default(), &t))
            }
            _ => (403, json!({"errors": ["permission denied"]})),
        },
        ("POST", "/v1/auth/token/revoke-self") => {
            if let Some(t) = token {
                s.tokens.remove(t);
                s.revoked.push(t.to_owned());
            }
            (204, json!({}))
        }
        ("POST", p) if p.ends_with("/oidc/auth_url") => {
            s.oidc_nonce = body["client_nonce"].as_str().map(str::to_owned);
            let url = format!("https://idp.example.test/authorize?client_id=c&state={IDP_STATE}");
            (200, json!({"data": {"auth_url": url}}))
        }
        ("GET", p) if p.ends_with("/oidc/callback") => {
            let ok = query(q, "code").as_deref() == Some(GOOD_CODE)
                && query(q, "state").as_deref() == Some(IDP_STATE)
                && query(q, "client_nonce") == s.oidc_nonce;
            if !ok {
                return (400, json!({"errors": ["invalid state or nonce"]}));
            }
            let (token, t) = issue(s, 3600);
            (200, auth(&token, &t))
        }
        ("POST", p) if p.ends_with("/login") => {
            let given = (body["role_id"].as_str(), body["secret_id"].as_str());
            match &s.approle {
                Some((r, sid)) if given == (Some(r.as_str()), Some(sid.as_str())) => {
                    let ttl = s.approle_ttl;
                    let (token, t) = issue(s, ttl);
                    (200, auth(&token, &t))
                }
                _ => (400, json!({"errors": ["invalid role or secret ID"]})),
            }
        }
        ("GET", p) => match (tok, p.strip_prefix("/v1/")) {
            (Some(t), Some(rest)) if t.kv => kv_read(s, &rest.replacen("/data/", "/", 1), q),
            _ => (403, json!({"errors": ["permission denied"]})),
        },
        _ => (405, json!({"errors": []})),
    }
}

async fn handle(
    state: Arc<Mutex<State>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let q = req.uri().query().unwrap_or_default().to_owned();
    let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let (token, ns) = (h("x-vault-token"), h("x-vault-namespace"));
    let bytes = req
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
    s.hits.push(path.clone());
    s.namespaces.push(ns);
    if s.sealed {
        return Ok(reply(503, &json!({"errors": ["Vault is sealed"]})));
    }
    if let Some((status, raw)) = s.raw.get(&path).cloned() {
        let mut r = Response::new(Full::new(Bytes::from(raw)));
        *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::OK);
        return Ok(r);
    }
    let (status, v) = route(&mut s, &method, &path, &q, token.as_deref(), &body);
    Ok(reply(status, &v))
}

pub async fn start(state: State) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let state = Arc::new(Mutex::new(state));
    let shared = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let st = Arc::clone(&shared);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |r| handle(Arc::clone(&st), r));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Mock { addr, state }
}
