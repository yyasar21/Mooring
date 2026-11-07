//! Dynamic engines of the Vault mock (ADR-0026 §Test plan): `database/creds/<role>`,
//! `ssh/sign/<role>`, `ssh/creds/<role>` (OTP), `pki/issue/<role>`, `pki/revoke` and
//! `sys/leases/renew` / `revoke`. Leases count down in real time; every issue, renewal and
//! revocation is an event the tests assert on. Synthetic values only.

use std::time::Instant;

use ::http::{Method, StatusCode};
use serde_json::{json, Value};

use super::{Dynamic, LeaseEvent, MockLease};
use crate::http::{self, json, random_hex, Ctx, Reply};

/// Mounts and fixtures of the dynamic engines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicConfig {
    pub database_mount: String,
    /// Lease duration of database credentials (seconds).
    pub db_ttl: u64,
    pub db_renewable: bool,
    pub ssh_mount: String,
    /// The `signed_key` `ssh/sign` returns (the mock has no CA; tests bring a fixture).
    pub ssh_signed_key: String,
    pub pki_mount: String,
    pub pki_certificate: String,
    pub pki_private_key: String,
    /// Whether `pki/issue` creates a lease (`generate_lease` on the role).
    pub pki_lease: bool,
}

impl Default for DynamicConfig {
    fn default() -> Self {
        Self {
            database_mount: "database".to_owned(),
            db_ttl: 3600,
            db_renewable: true,
            ssh_mount: "ssh".to_owned(),
            ssh_signed_key: String::new(),
            pki_mount: "pki".to_owned(),
            pki_certificate: String::new(),
            pki_private_key: String::new(),
            pki_lease: false,
        }
    }
}

fn bad(msg: &str) -> Reply {
    json(StatusCode::BAD_REQUEST, &json!({ "errors": [msg] })).into()
}

fn lease(d: &mut Dynamic, path: &str, ttl: u64, renewable: bool) -> String {
    let id = format!("{path}/{}", random_hex(12));
    d.leases
        .insert(id.clone(), MockLease { ttl, renewable, since: Instant::now(), revoked: false });
    d.lease_events.push(LeaseEvent { kind: "issue".to_owned(), lease: id.clone() });
    id
}

fn envelope(lease_id: &str, ttl: u64, renewable: bool, data: &Value) -> Value {
    json!({ "request_id": format!("req-{}", random_hex(8)), "lease_id": lease_id,
            "lease_duration": ttl, "renewable": renewable, "data": data,
            "wrap_info": null, "warnings": null, "auth": null })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Renew,
    Revoke,
    DbCreds,
    SshOtp,
    SshSign,
    PkiIssue,
    PkiRevoke,
}

fn classify(c: &DynamicConfig, m: &Method, segs: &[&str]) -> Option<Route> {
    let n = segs.len();
    let mount = if n >= 2 { segs[..n - 2].join("/") } else { String::new() };
    let parent = if n >= 1 { segs[..n - 1].join("/") } else { String::new() };
    Some(match segs {
        ["sys", "leases", "renew"] if *m == Method::PUT => Route::Renew,
        ["sys", "leases", "revoke"] if *m == Method::PUT => Route::Revoke,
        [.., "creds", _] if *m == Method::GET && mount == c.database_mount => Route::DbCreds,
        [.., "creds", _] if *m == Method::POST && mount == c.ssh_mount => Route::SshOtp,
        [.., "sign", _] if *m == Method::POST && mount == c.ssh_mount => Route::SshSign,
        [.., "issue", _] if *m == Method::POST && mount == c.pki_mount => Route::PkiIssue,
        [.., "revoke"] if *m == Method::POST && parent == c.pki_mount => Route::PkiRevoke,
        _ => return None,
    })
}

/// `Some(reply)` when `segs` is a dynamic-engine route; `allowed` = a live token and no
/// forced 403 (a refused request gets 403, never a violation).
pub(super) fn route(d: &mut Dynamic, ctx: &Ctx, segs: &[&str], allowed: bool) -> Option<Reply> {
    let c = d.config.dynamic.clone();
    let r = classify(&c, &ctx.method, segs)?;
    if !allowed {
        return Some(
            json(StatusCode::FORBIDDEN, &json!({ "errors": ["permission denied"] })).into(),
        );
    }
    if let Some(raw) = d.config.knobs.raw_dynamic_body.clone() {
        if matches!(r, Route::DbCreds | Route::SshOtp | Route::SshSign | Route::PkiIssue) {
            return Some(http::bytes(StatusCode::OK, "application/json", raw).into());
        }
    }
    let path = segs.join("/");
    Some(match r {
        Route::Renew => renew(d, ctx),
        Route::Revoke => revoke(d, ctx),
        Route::DbCreds => {
            let id = lease(d, &path, c.db_ttl, c.db_renewable);
            let data = json!({ "username": format!("v-mooring-{}", random_hex(4)),
                               "password": format!("A1a-{}", random_hex(10)) });
            json(StatusCode::OK, &envelope(&id, c.db_ttl, c.db_renewable, &data)).into()
        }
        Route::SshOtp => {
            let b = ctx.json_body().unwrap_or(Value::Null);
            let (ip, user) = (b["ip"].as_str().unwrap_or(""), b["username"].as_str().unwrap_or(""));
            if ip.parse::<std::net::IpAddr>().is_err() || user.is_empty() {
                return Some(bad("missing ip or username"));
            }
            let id = lease(d, &path, 600, false);
            let data = json!({ "key": format!("otp-{}", random_hex(8)), "key_type": "otp",
                               "username": user, "ip": ip, "port": 22 });
            json(StatusCode::OK, &envelope(&id, 600, false, &data)).into()
        }
        Route::SshSign => {
            let b = ctx.json_body().unwrap_or(Value::Null);
            if b.get("private_key").is_some() {
                return Some(Reply::violation("a private key was sent to ssh/sign"));
            }
            if !b["public_key"].as_str().is_some_and(|k| k.starts_with("ssh-")) {
                return Some(bad("missing public_key"));
            }
            d.sign_requests.push(b);
            let data = json!({ "serial_number": "2a", "signed_key": c.ssh_signed_key });
            json(StatusCode::OK, &envelope("", 0, false, &data)).into()
        }
        Route::PkiIssue => {
            let b = ctx.json_body().unwrap_or(Value::Null);
            if b["common_name"].as_str().is_none_or(str::is_empty) {
                return Some(bad("missing common_name"));
            }
            let serial = format!("{}:{}", random_hex(1), random_hex(1));
            let (id, ttl) =
                if c.pki_lease { (lease(d, &path, 3600, false), 3600) } else { (String::new(), 0) };
            let data = json!({ "certificate": c.pki_certificate, "issuing_ca": c.pki_certificate,
                               "ca_chain": [c.pki_certificate], "private_key": c.pki_private_key,
                               "private_key_type": "ec", "serial_number": serial });
            json(StatusCode::OK, &envelope(&id, ttl, false, &data)).into()
        }
        Route::PkiRevoke => {
            let b = ctx.json_body().unwrap_or(Value::Null);
            let serial = b["serial_number"].as_str().unwrap_or("").to_owned();
            d.lease_events.push(LeaseEvent { kind: "revoke_cert".to_owned(), lease: serial });
            json(StatusCode::OK, &envelope("", 0, false, &json!({ "revocation_time": 1 }))).into()
        }
    })
}

fn renew(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let b = ctx.json_body().unwrap_or(Value::Null);
    let id = b["lease_id"].as_str().unwrap_or("").to_owned();
    if d.config.knobs.lease_renew_fails {
        return bad("lease not found or lease is not renewable");
    }
    let Some(l) = d.leases.get_mut(&id).filter(|l| !l.revoked && l.renewable) else {
        return bad("lease not found or lease is not renewable");
    };
    l.since = Instant::now();
    let ttl = b["increment"].as_u64().unwrap_or(l.ttl).min(l.ttl);
    d.lease_events.push(LeaseEvent { kind: "renew".to_owned(), lease: id.clone() });
    json(StatusCode::OK, &json!({ "lease_id": id, "renewable": true, "lease_duration": ttl }))
        .into()
}

fn revoke(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let b = ctx.json_body().unwrap_or(Value::Null);
    let id = b["lease_id"].as_str().unwrap_or("").to_owned();
    if let Some(l) = d.leases.get_mut(&id) {
        l.revoked = true;
    }
    d.lease_events.push(LeaseEvent { kind: "revoke".to_owned(), lease: id });
    http::empty(StatusCode::NO_CONTENT).into()
}
