//! Routes of the Vault mock.

use std::sync::Arc;
use std::time::Instant;

use ::http::header::{HeaderValue, LOCATION};
use ::http::{Method, StatusCode};
use serde_json::{json, Value};

use super::{Dynamic, Issued, KvSecret, TokenEvent, VaultState};
use crate::http::{
    self, empty, json, random_hex, time, Ctx, Handler, HandlerFuture, HttpKnobs, Reply,
};

impl Handler for VaultState {
    fn http_knobs(&self) -> HttpKnobs {
        self.lock().config.http.clone()
    }

    fn handle(self: Arc<Self>, ctx: Ctx) -> HandlerFuture {
        Box::pin(async move { route(&mut self.lock(), &ctx) })
    }
}

fn errors(code: StatusCode, msgs: &[&str]) -> Reply {
    json(code, &json!({ "errors": msgs })).into()
}

fn denied() -> Reply {
    errors(StatusCode::FORBIDDEN, &["1 error occurred:\n\t* permission denied\n\n"])
}

fn envelope(data: &Value, auth: &Value) -> Value {
    json!({ "request_id": format!("req-{}", random_hex(8)), "lease_id": "", "renewable": false,
            "lease_duration": 0, "data": data, "wrap_info": null, "warnings": null, "auth": auth })
}

fn remaining(t: &Issued) -> u64 {
    if t.ttl == 0 {
        return 0;
    }
    t.ttl.saturating_sub(Instant::now().duration_since(t.since).as_secs())
}

/// The live token behind `X-Vault-Token`, if any.
fn token<'a>(d: &'a mut Dynamic, ctx: &Ctx) -> Option<(String, &'a mut Issued)> {
    let tok = ctx.header("x-vault-token")?.to_owned();
    let t = d.tokens.get_mut(&tok)?;
    let expired = t.ttl != 0 && remaining(t) == 0;
    (!t.revoked && !expired).then_some((tok, t))
}

fn auth_block(token: &str, t: &Issued) -> Value {
    json!({ "client_token": token, "accessor": t.accessor, "policies": t.policies,
            "token_policies": t.policies, "metadata": null, "lease_duration": t.ttl,
            "renewable": t.renewable, "entity_id": "", "token_type": "service", "orphan": true })
}

fn issue(d: &mut Dynamic, kind: &str, policies: Vec<String>, ttl: u64) -> Reply {
    let token = format!("hvs.{}", random_hex(16));
    let t = Issued {
        policies,
        ttl,
        renewable: true,
        since: Instant::now(),
        accessor: random_hex(12),
        revoked: false,
    };
    d.events.push(TokenEvent { kind: kind.to_owned(), accessor: t.accessor.clone() });
    let body = envelope(&Value::Null, &auth_block(&token, &t));
    d.tokens.insert(token, t);
    json(StatusCode::OK, &body).into()
}

fn route(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let k = d.config.knobs.clone();
    let path = ctx.path.as_str();
    if path == "/v1/sys/health" && ctx.method == Method::GET {
        let code = if k.sealed {
            503
        } else if k.standby {
            429
        } else {
            200
        };
        let v = json!({ "initialized": true, "sealed": k.sealed, "standby": k.standby,
                        "version": "1.18.0", "cluster_name": "vault-cluster-test" });
        return json(StatusCode::from_u16(code).unwrap_or(StatusCode::OK), &v).into();
    }
    if k.sealed {
        return errors(StatusCode::SERVICE_UNAVAILABLE, &["Vault is sealed"]);
    }
    if k.standby {
        let mut r = empty(StatusCode::TEMPORARY_REDIRECT);
        let loc = format!("https://vault-active.example.test:8200{path}");
        if let Ok(v) = HeaderValue::from_str(&loc) {
            r.headers_mut().insert(LOCATION, v);
        }
        return r.into();
    }
    if let Some(ns) = &d.config.namespace {
        if ctx.header("x-vault-namespace").map(|h| h.trim_matches('/'))
            != Some(ns.trim_matches('/'))
        {
            return denied();
        }
    }
    let segs: Vec<&str> = path.strip_prefix("/v1/").unwrap_or("").split('/').collect();
    let (approle, oidc) = (d.config.approle.mount.clone(), d.config.oidc.mount.clone());
    let m = &ctx.method;
    match segs.as_slice() {
        ["auth", "token", "lookup-self"] if *m == Method::GET => lookup(d, ctx),
        ["auth", "token", "renew-self"] if *m == Method::POST => renew(d, ctx),
        ["auth", "token", "revoke-self"] if *m == Method::POST => match token(d, ctx) {
            Some((_, t)) => {
                t.revoked = true;
                let accessor = t.accessor.clone();
                d.events.push(TokenEvent { kind: "revoke".to_owned(), accessor });
                empty(StatusCode::NO_CONTENT).into()
            }
            None => denied(),
        },
        ["auth", mount, "login"] if *m == Method::POST && *mount == approle => {
            let b = ctx.json_body().unwrap_or(Value::Null);
            let r = &d.config.approle;
            if b["role_id"].as_str() == Some(&r.role_id)
                && b["secret_id"].as_str() == Some(&r.secret_id)
            {
                let (p, ttl) = (r.policies.clone(), r.ttl);
                issue(d, "login-approle", p, ttl)
            } else {
                errors(StatusCode::BAD_REQUEST, &["invalid role ID or secret ID"])
            }
        }
        ["auth", mount, "oidc", "auth_url"] if *m == Method::POST && *mount == oidc => {
            auth_url(d, ctx)
        }
        ["auth", mount, "oidc", "callback"] if *m == Method::GET && *mount == oidc => {
            callback(d, ctx)
        }
        [mount, "data" | "metadata", rest @ ..] if *m == Method::GET && !rest.is_empty() => {
            let (mount, kind, path) = ((*mount).to_owned(), segs[1], rest.join("/"));
            let Some(mine) = token(d, ctx).map(|(_, t)| t.policies.clone()) else {
                return denied();
            };
            if k.force_403 {
                return denied();
            }
            let full = format!("{mount}/{kind}/{path}");
            let allowed = mine.iter().any(|p| p == "root")
                || d.config.policies.iter().any(|p| {
                    mine.contains(&p.name) && p.read.iter().any(|r| full.starts_with(r.as_str()))
                });
            if !allowed {
                return denied();
            }
            if kind == "data" {
                kv_data(d, ctx, &mount, &path)
            } else {
                kv_metadata(d, &mount, &path)
            }
        }
        _ => Reply::violation(format!("{m} {path} is not a read-only route of the Vault mock")),
    }
}

fn lookup(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let root = d.config.knobs.root_token;
    let Some((tok, t)) = token(d, ctx) else { return denied() };
    let (policies, ttl) =
        if root { (vec!["root".to_owned()], 0) } else { (t.policies.clone(), remaining(t)) };
    let now = time::now_unix();
    let expire = (ttl > 0).then(|| time::rfc3339(now + i64::try_from(ttl).unwrap_or(0)));
    let data = json!({ "accessor": t.accessor, "creation_time": now, "creation_ttl": t.ttl,
        "display_name": "token", "entity_id": "", "expire_time": expire, "explicit_max_ttl": 0,
        "id": tok, "issue_time": time::rfc3339(now), "meta": null, "num_uses": 0, "orphan": true,
        "path": "auth/token/create", "policies": policies, "renewable": t.renewable && !root,
        "ttl": ttl, "type": "service" });
    let accessor = t.accessor.clone();
    d.events.push(TokenEvent { kind: "lookup".to_owned(), accessor });
    json(StatusCode::OK, &envelope(&data, &Value::Null)).into()
}

fn renew(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let Some((tok, t)) = token(d, ctx) else { return denied() };
    if !t.renewable {
        return errors(StatusCode::BAD_REQUEST, &["lease is not renewable"]);
    }
    t.since = Instant::now();
    let body = envelope(&Value::Null, &auth_block(&tok, t));
    let accessor = t.accessor.clone();
    d.events.push(TokenEvent { kind: "renew".to_owned(), accessor });
    json(StatusCode::OK, &body).into()
}

fn auth_url(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let b = ctx.json_body().unwrap_or(Value::Null);
    let s = |k: &str| b[k].as_str().unwrap_or("").to_owned();
    let (role, redirect, nonce) = (s("role"), s("redirect_uri"), s("client_nonce"));
    let o = &d.config.oidc;
    if role != o.role {
        return errors(StatusCode::BAD_REQUEST, &[&format!("role \"{role}\" could not be found")]);
    }
    if !o.allowed_redirect_uris.contains(&redirect) {
        return errors(
            StatusCode::BAD_REQUEST,
            &[&format!("unauthorized redirect_uri: {redirect}")],
        );
    }
    let state = format!("st_{}", random_hex(16));
    let url = format!(
        "{}?client_id=mooring&nonce=n_{}&redirect_uri={}&response_type=code&scope=openid&state={state}",
        o.idp_authorize,
        random_hex(8),
        http::pct_encode(&redirect, false)
    );
    d.oidc_states.insert(state, (nonce, redirect));
    json(StatusCode::OK, &envelope(&json!({ "auth_url": url }), &Value::Null)).into()
}

fn callback(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let q = |k: &str| ctx.query_get(k).unwrap_or_default();
    let Some((nonce, _)) = d.oidc_states.remove(&q("state")) else {
        return errors(StatusCode::BAD_REQUEST, &["Expired or missing OAuth state."]);
    };
    if q("code") != d.config.oidc.code {
        return errors(StatusCode::BAD_REQUEST, &["Error exchanging oidc code"]);
    }
    if q("client_nonce") != nonce {
        return errors(StatusCode::BAD_REQUEST, &["invalid client_nonce"]);
    }
    let (p, ttl) = (d.config.oidc.policies.clone(), d.config.oidc.ttl);
    issue(d, "login-oidc", p, ttl)
}

fn find<'a>(d: &'a Dynamic, mount: &str, path: &str) -> Option<&'a KvSecret> {
    d.config.kv.iter().find(|s| s.mount == mount && s.path == path)
}

const CREATED: &str = "2026-11-01T00:00:00.000000Z";
const DELETED: &str = "2026-11-02T00:00:00.000000Z";

fn kv_data(d: &Dynamic, ctx: &Ctx, mount: &str, path: &str) -> Reply {
    if let Some(raw) = &d.config.knobs.raw_kv_body {
        return http::bytes(StatusCode::OK, "application/json", raw.clone()).into();
    }
    let not_found = || errors(StatusCode::NOT_FOUND, &[]);
    let Some(s) = find(d, mount, path) else { return not_found() };
    let n = match ctx.query_get("version").map(|v| v.parse::<usize>()) {
        None | Some(Ok(0)) => s.versions.len(),
        Some(Ok(n)) => n,
        Some(Err(_)) => return errors(StatusCode::BAD_REQUEST, &["invalid version"]),
    };
    let Some(v) = n.checked_sub(1).and_then(|i| s.versions.get(i)) else { return not_found() };
    let gone = v.deleted || v.destroyed;
    let meta = json!({ "created_time": CREATED, "custom_metadata": null,
        "deletion_time": if v.deleted { DELETED } else { "" }, "destroyed": v.destroyed, "version": n });
    let data = json!({ "data": if gone { Value::Null } else { v.data.clone() }, "metadata": meta });
    let mut body = envelope(&data, &Value::Null);
    if let Some(pad) = d.config.knobs.oversized_body {
        body["mooringPadding"] = Value::String("x".repeat(pad));
    }
    json(if gone { StatusCode::NOT_FOUND } else { StatusCode::OK }, &body).into()
}

fn kv_metadata(d: &Dynamic, mount: &str, path: &str) -> Reply {
    let Some(s) = find(d, mount, path) else { return errors(StatusCode::NOT_FOUND, &[]) };
    let versions: serde_json::Map<String, Value> = s
        .versions
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let del = if v.deleted { DELETED } else { "" };
            (
                (i + 1).to_string(),
                json!({ "created_time": CREATED, "deletion_time": del, "destroyed": v.destroyed }),
            )
        })
        .collect();
    let data = json!({ "cas_required": false, "created_time": CREATED, "current_version": s.versions.len(),
        "custom_metadata": null, "delete_version_after": "0s", "max_versions": 0, "oldest_version": 1,
        "updated_time": CREATED, "versions": versions });
    json(StatusCode::OK, &envelope(&data, &Value::Null)).into()
}
