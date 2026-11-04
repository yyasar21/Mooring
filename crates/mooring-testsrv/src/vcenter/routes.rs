//! Routes of the vCenter mock.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use http::header::{HeaderValue, RETRY_AFTER};
use http::{Method, StatusCode};
use serde_json::{json, Value};

use super::{Dynamic, PowerAction, TicketRequest, VcenterState};
use crate::http::{empty, json, random_hex, Ctx, Handler, HandlerFuture, HttpKnobs, Reply};

impl Handler for VcenterState {
    fn http_knobs(&self) -> HttpKnobs {
        self.lock().config.http.clone()
    }

    fn handle(self: Arc<Self>, ctx: Ctx) -> HandlerFuture {
        Box::pin(async move { route(&mut self.lock(), &ctx) })
    }
}

fn error(code: StatusCode, kind: &str, msg: &str) -> Reply {
    let v = json!({ "error_type": kind,
        "messages": [{ "args": [], "default_message": msg, "id": format!("vapi.{}", kind.to_ascii_lowercase()) }] });
    json(code, &v).into()
}

fn ok(v: &Value) -> Reply {
    json(StatusCode::OK, v).into()
}

fn rate_limited(d: &mut Dynamic) -> bool {
    let Some(limit) = d.config.knobs.rate_limit_per_sec else { return false };
    let now = Instant::now();
    if now.duration_since(d.window.0) >= Duration::from_secs(1) {
        d.window = (now, 0);
    }
    d.window.1 += 1;
    d.window.1 > limit
}

fn basic_ok(ctx: &Ctx, d: &Dynamic) -> bool {
    let Some(b64) = ctx.header("authorization").and_then(|v| v.strip_prefix("Basic ")) else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let expect = format!("{}:{}", d.config.username, d.config.password);
    raw == expect.as_bytes()
}

fn route(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    if rate_limited(d) {
        let mut r = error(StatusCode::TOO_MANY_REQUESTS, "RESOURCE_BUSY", "rate limit exceeded");
        r.resp.headers_mut().insert(RETRY_AFTER, HeaderValue::from_static("1"));
        return r;
    }
    let segs: Vec<&str> = ctx.path.strip_prefix('/').unwrap_or(&ctx.path).split('/').collect();
    let m = &ctx.method;
    if segs == ["api", "session"] {
        return session(d, ctx);
    }
    let known = match segs.as_slice() {
        ["api", "appliance", "system", "version"]
        | ["api", "vcenter", "datacenter" | "cluster" | "host" | "vm"]
        | ["api", "vcenter", "vm", _]
        | ["api", "vcenter", "vm", _, "guest", "identity"] => *m == Method::GET,
        ["api", "vcenter", "vm", _, "power"] => *m == Method::GET || *m == Method::POST,
        ["api", "vcenter", "vm", _, "guest", "power"]
        | ["api", "vcenter", "vm", _, "console", "tickets"] => *m == Method::POST,
        _ => false,
    };
    if !known {
        return Reply::violation(format!("{m} {} is not a route of the vCenter mock", ctx.path));
    }
    let token = ctx.header("vmware-api-session-id").unwrap_or("");
    if !d.sessions.contains(token) {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "This method requires authentication.",
        );
    }
    match (m, segs.as_slice()) {
        (_, ["api", "appliance", "system", "version"]) => ok(&json!({
            "version": "8.0.3.00400", "build": "24322831", "product": "VMware vCenter Server",
            "type": "vCenter Server with an embedded Platform Services Controller" })),
        (_, ["api", "vcenter", kind]) => list(d, ctx, kind),
        (_, ["api", "vcenter", "vm", vm]) => match d.inventory.vms.iter().find(|v| v.id == *vm) {
            Some(v) => ok(&v.detail_json()),
            None => not_found(vm),
        },
        (&Method::GET, ["api", "vcenter", "vm", vm, "power"]) => {
            match d.inventory.vms.iter().find(|v| v.id == *vm) {
                Some(v) => ok(&json!({ "state": v.power_state })),
                None => not_found(vm),
            }
        }
        (_, ["api", "vcenter", "vm", vm, "power"]) => power(d, ctx, vm, "power"),
        (_, ["api", "vcenter", "vm", vm, "guest", "power"]) => power(d, ctx, vm, "guest"),
        (_, ["api", "vcenter", "vm", vm, "guest", "identity"]) => identity(d, vm),
        (_, ["api", "vcenter", "vm", vm, "console", "tickets"]) => ticket(d, ctx, vm),
        _ => Reply::violation("unreachable vCenter route"),
    }
}

fn not_found(vm: &str) -> Reply {
    error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        &format!("Virtual machine with identifier '{vm}' does not exist."),
    )
}

fn session(d: &mut Dynamic, ctx: &Ctx) -> Reply {
    let token = ctx.header("vmware-api-session-id").unwrap_or("").to_owned();
    match ctx.method {
        Method::POST => {
            if !basic_ok(ctx, d) {
                return error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHENTICATED",
                    "Authentication required.",
                );
            }
            let id = random_hex(16);
            d.sessions.insert(id.clone());
            d.logins += 1;
            json(StatusCode::CREATED, &Value::String(id)).into()
        }
        Method::DELETE if d.sessions.remove(&token) => empty(StatusCode::NO_CONTENT).into(),
        Method::GET if d.sessions.contains(&token) => ok(&json!({
            "user": format!("EXAMPLE.TEST\\{}", d.config.username.split('@').next().unwrap_or("")),
            "created_time": "2026-11-04T00:00:00.000Z", "last_accessed_time": "2026-11-04T00:00:00.000Z" })),
        Method::DELETE | Method::GET => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "This method requires authentication.",
        ),
        _ => Reply::violation(format!("{} /api/session", ctx.method)),
    }
}

fn list(d: &Dynamic, ctx: &Ctx, kind: &str) -> Reply {
    let f = |k: &str| ctx.query_all(k);
    let pass = |filter: &[String], v: &str| filter.is_empty() || filter.iter().any(|x| x == v);
    let (dcs, cls, hosts, names) = (f("datacenters"), f("clusters"), f("hosts"), f("names"));
    let inv = &d.inventory;
    let host_ok = |h: &super::Host| {
        let standalone = ctx.query_get("standalone").map(|s| s == "true");
        pass(&dcs, &h.datacenter)
            && (cls.is_empty() || h.cluster.as_ref().is_some_and(|c| cls.contains(c)))
            && pass(&hosts, &h.id)
            && standalone.is_none_or(|s| s == h.cluster.is_none())
    };
    let items: Vec<Value> = match kind {
        "datacenter" => inv
            .datacenters
            .iter()
            .filter(|x| pass(&f("datacenters"), &x.id) && pass(&names, &x.name))
            .map(super::Datacenter::to_json)
            .collect(),
        "cluster" => inv
            .clusters
            .iter()
            .filter(|x| pass(&dcs, &x.datacenter) && pass(&cls, &x.id) && pass(&names, &x.name))
            .map(super::Cluster::to_json)
            .collect(),
        "host" => inv
            .hosts
            .iter()
            .filter(|h| host_ok(h) && pass(&names, &h.name))
            .map(super::Host::to_json)
            .collect(),
        _ => {
            let states = f("power_states");
            inv.vms
                .iter()
                .filter(|v| {
                    inv.host(&v.host).is_some_and(host_ok)
                        && pass(&f("vms"), &v.id)
                        && pass(&names, &v.name)
                        && pass(&states, &v.power_state)
                })
                .map(super::Vm::to_json)
                .collect()
        }
    };
    if items.len() > d.config.knobs.result_limit {
        let msg = format!(
            "Too many {kind} objects ({}). Add more filter criteria to reduce the number.",
            items.len()
        );
        return error(StatusCode::BAD_REQUEST, "UNABLE_TO_ALLOCATE_RESOURCE", &msg);
    }
    ok(&Value::Array(items))
}

fn power(d: &mut Dynamic, ctx: &Ctx, vm: &str, kind: &str) -> Reply {
    let action = ctx.query_get("action").unwrap_or_default();
    let tools_missing = d.config.knobs.tools_missing;
    let reply = match d.inventory.vm_mut(vm) {
        None => not_found(vm),
        Some(v) => {
            let state = v.power_state.as_str();
            let guest_op =
                kind == "guest" && matches!(action.as_str(), "shutdown" | "reboot" | "standby");
            let next = if guest_op && (tools_missing || !v.tools) {
                Err("SERVICE_UNAVAILABLE")
            } else {
                match (kind, action.as_str(), state) {
                    ("power", "start", "POWERED_OFF" | "SUSPENDED")
                    | ("power", "reset", "POWERED_ON")
                    | ("guest", "reboot", "POWERED_ON") => Ok("POWERED_ON"),
                    ("power", "stop", "POWERED_ON" | "SUSPENDED")
                    | ("guest", "shutdown", "POWERED_ON") => Ok("POWERED_OFF"),
                    ("power", "suspend", "POWERED_ON") | ("guest", "standby", "POWERED_ON") => {
                        Ok("SUSPENDED")
                    }
                    ("power", "start" | "stop", _) => Err("ALREADY_IN_DESIRED_STATE"),
                    ("power", "reset" | "suspend", _)
                    | ("guest", "shutdown" | "reboot" | "standby", _) => {
                        Err("NOT_ALLOWED_IN_CURRENT_STATE")
                    }
                    _ => Err("INVALID_ARGUMENT"),
                }
            };
            match next {
                Ok(s) => {
                    s.clone_into(&mut v.power_state);
                    if s != "POWERED_ON" {
                        v.tools = false;
                    }
                    empty(StatusCode::NO_CONTENT).into()
                }
                Err("SERVICE_UNAVAILABLE") => error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "VMware Tools is not running in the guest.",
                ),
                Err(e) => error(
                    StatusCode::BAD_REQUEST,
                    e,
                    &format!("{kind} action '{action}' refused in state {state}"),
                ),
            }
        }
    };
    d.power.push(PowerAction {
        vm: vm.to_owned(),
        kind: kind.to_owned(),
        action,
        status: reply.resp.status().as_u16(),
    });
    reply
}

fn identity(d: &Dynamic, vm: &str) -> Reply {
    let Some(v) = d.inventory.vms.iter().find(|v| v.id == vm) else { return not_found(vm) };
    if d.config.knobs.tools_missing || !v.tools {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "VMware Tools is not running.",
        );
    }
    ok(
        &json!({ "name": "OTHER_LINUX_64", "family": "LINUX", "full_name": { "default_message": "Other Linux (64-bit)" },
                "host_name": format!("{}.example.test", v.name), "ip_address": v.ip }),
    )
}

fn ticket(d: &mut Dynamic, ctx: &Ctx, vm: &str) -> Reply {
    let kind =
        ctx.json_body().and_then(|b| b["type"].as_str().map(str::to_owned)).unwrap_or_default();
    d.tickets.push(TicketRequest { vm: vm.to_owned(), kind: kind.clone() });
    let Some(v) = d.inventory.vms.iter().find(|v| v.id == vm) else { return not_found(vm) };
    if d.config.knobs.tickets_unavailable {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "console tickets unavailable",
        );
    }
    let host = d.inventory.host(&v.host).map_or("esx.example.test", |h| h.name.as_str());
    let t = random_hex(16);
    let url = match kind.as_str() {
        "VMRC" => format!("vmrc://clone:cst-{t}@vcenter.example.test:443/?moid={vm}"),
        "WEBMKS" => format!("wss://{host}:443/ticket/{t}"),
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "type must be VMRC or WEBMKS",
            )
        }
    };
    json(StatusCode::CREATED, &json!({ "ticket": url })).into()
}
