//! In-process mock 1Password Connect server (ADR-0026 §Test plan) on loopback TLS:
//! `GET /heartbeat`, `GET /v1/vaults[?filter=name eq "…"]`,
//! `GET /v1/vaults/{id}/items[?filter=title eq "…"]`, `GET /v1/vaults/{id}/items/{id}`, with
//! the bearer token checked (401) and hostile knobs (raw item bodies, an off-host redirect,
//! padding past the client's cap). Every other route or method is a violation: the client
//! only ever reads. Synthetic values only.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use ::http::header::{HeaderValue, LOCATION};
use ::http::{Method, StatusCode};
use serde_json::{json, Value};

use crate::http::{
    self, empty, json, Ctx, Handler, HandlerFuture, HttpKnobs, Recorder, Reply, Running,
};
use crate::tls::TestCert;

/// One vault and its items (each item a full Connect item object with `id` and `title`).
#[derive(Debug, Clone, PartialEq)]
pub struct OpVault {
    pub id: String,
    pub name: String,
    pub items: Vec<Value>,
}

/// Hostile behaviour.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectKnobs {
    /// Item reads return exactly this body.
    pub raw_item_body: Option<String>,
    /// Every request gets a 302 to another host.
    pub redirect_off_host: bool,
    /// Item reads are padded to at least this many bytes.
    pub oversized_body: Option<usize>,
}

/// Configuration of one Connect mock.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub token: String,
    pub vaults: Vec<OpVault>,
    pub knobs: ConnectKnobs,
    pub http: HttpKnobs,
    pub cert: Option<TestCert>,
}

/// Vault `Infra` (`aaaaaaaaaaaaaaaaaaaaaaaaaa`) with item `DB prod` (login: username,
/// password, a TOTP field, a section `admin` with its own password) and item `API` (one
/// `credential` field).
pub fn default_vaults() -> Vec<OpVault> {
    let db = json!({ "id": "bbbbbbbbbbbbbbbbbbbbbbbbbb", "title": "DB prod", "category": "LOGIN",
        "vault": { "id": "aaaaaaaaaaaaaaaaaaaaaaaaaa" },
        "sections": [{ "id": "sec1", "label": "admin" }],
        "fields": [
            { "id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "app" },
            { "id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "op-testpass" },
            { "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "ignored" },
            { "id": "totp1", "type": "OTP", "label": "one-time password",
              "value": "otpauth://totp/x?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=x", "totp": "123456" },
            { "id": "adminpw", "type": "CONCEALED", "label": "password", "value": "op-adminpass",
              "section": { "id": "sec1" } }
        ] });
    let api = json!({ "id": "cccccccccccccccccccccccccc", "title": "API", "category": "API_CREDENTIAL",
        "vault": { "id": "aaaaaaaaaaaaaaaaaaaaaaaaaa" },
        "fields": [{ "id": "credential", "type": "CONCEALED", "label": "credential", "value": "op-token-1" }] });
    vec![OpVault {
        id: "aaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        name: "Infra".into(),
        items: vec![db, api],
    }]
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            token: "test-only-connect-token".to_owned(),
            vaults: default_vaults(),
            knobs: ConnectKnobs::default(),
            http: HttpKnobs::default(),
            cert: None,
        }
    }
}

#[derive(Debug)]
struct State {
    config: Mutex<ConnectConfig>,
}

impl State {
    fn lock(&self) -> MutexGuard<'_, ConnectConfig> {
        self.config.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Handle of a running Connect mock; dropping it stops the server.
#[derive(Debug)]
pub struct ConnectServer {
    running: Running,
    cert: TestCert,
    state: Arc<State>,
    recorder: Recorder,
}

/// Starts the mock on `127.0.0.1:port` (`0` = ephemeral). Needs a Tokio runtime.
pub async fn start(mut config: ConnectConfig, port: u16) -> io::Result<ConnectServer> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(io::Error::other)?,
    };
    let tls = cert.server_config().map_err(io::Error::other)?;
    let state = Arc::new(State { config: Mutex::new(config) });
    let recorder = Recorder::default();
    let running = http::serve(tls, port, Arc::clone(&state), recorder.clone()).await?;
    Ok(ConnectServer { running, cert, state, recorder })
}

impl ConnectServer {
    pub fn addr(&self) -> SocketAddr {
        self.running.addr
    }

    /// `https://127.0.0.1:<port>` (the source `address`).
    pub fn base_url(&self) -> String {
        format!("https://{}", self.running.addr)
    }

    pub fn cert(&self) -> &TestCert {
        &self.cert
    }

    pub fn recorder(&self) -> &Recorder {
        &self.recorder
    }

    pub fn set_knobs(&self, knobs: ConnectKnobs) {
        self.state.lock().knobs = knobs;
    }

    pub fn set_vaults(&self, vaults: Vec<OpVault>) {
        self.state.lock().vaults = vaults;
    }
}

impl Handler for State {
    fn http_knobs(&self) -> HttpKnobs {
        self.lock().http.clone()
    }

    fn handle(self: Arc<Self>, ctx: Ctx) -> HandlerFuture {
        Box::pin(async move { route(&self.lock(), &ctx) })
    }
}

fn error(status: StatusCode, message: &str) -> Reply {
    json(status, &json!({ "status": status.as_u16(), "message": message })).into()
}

/// `name eq "x"` / `title eq "x"` → `x`.
fn filter_value(ctx: &Ctx, attr: &str) -> Option<String> {
    let f = ctx.query_get("filter")?;
    let v = f.strip_prefix(attr)?.strip_prefix(" eq \"")?.strip_suffix('"')?;
    Some(v.to_owned())
}

fn route(c: &ConnectConfig, ctx: &Ctx) -> Reply {
    if ctx.method != Method::GET {
        return Reply::violation(format!(
            "{} {} is not a read of the Connect mock",
            ctx.method, ctx.path
        ));
    }
    if c.knobs.redirect_off_host {
        let mut r = empty(StatusCode::FOUND);
        if let Ok(v) = HeaderValue::from_str("https://connect.attacker.example.test/v1/vaults") {
            r.headers_mut().insert(LOCATION, v);
        }
        return r.into();
    }
    if ctx.path == "/heartbeat" {
        return http::bytes(StatusCode::OK, "text/plain", ".").into();
    }
    let authorized = ctx.header("authorization") == Some(format!("Bearer {}", c.token).as_str());
    if !authorized {
        return error(StatusCode::UNAUTHORIZED, "Invalid bearer token");
    }
    let segs: Vec<&str> = ctx.path.strip_prefix("/v1/").unwrap_or("").split('/').collect();
    match segs.as_slice() {
        ["vaults"] => {
            let want = filter_value(ctx, "name");
            let list: Vec<Value> = c
                .vaults
                .iter()
                .filter(|v| want.as_ref().is_none_or(|w| *w == v.name))
                .map(|v| json!({ "id": v.id, "name": v.name, "type": "USER_CREATED" }))
                .collect();
            json(StatusCode::OK, &Value::Array(list)).into()
        }
        ["vaults", vid, "items"] => {
            let Some(v) = c.vaults.iter().find(|v| v.id == *vid) else {
                return error(StatusCode::NOT_FOUND, "Invalid Vault UUID");
            };
            let want = filter_value(ctx, "title");
            let list: Vec<Value> = v
                .items
                .iter()
                .filter(|i| want.as_ref().is_none_or(|w| i["title"].as_str() == Some(w)))
                .map(|i| json!({ "id": i["id"], "title": i["title"], "vault": { "id": v.id } }))
                .collect();
            json(StatusCode::OK, &Value::Array(list)).into()
        }
        ["vaults", vid, "items", iid] => {
            if let Some(raw) = &c.knobs.raw_item_body {
                return http::bytes(StatusCode::OK, "application/json", raw.clone()).into();
            }
            let item = c
                .vaults
                .iter()
                .find(|v| v.id == *vid)
                .and_then(|v| v.items.iter().find(|i| i["id"].as_str() == Some(iid)));
            let Some(item) = item else { return error(StatusCode::NOT_FOUND, "Invalid Item UUID") };
            let mut body = item.clone();
            if let Some(pad) = c.knobs.oversized_body {
                body["mooringPadding"] = Value::String("x".repeat(pad));
            }
            json(StatusCode::OK, &body).into()
        }
        _ => Reply::violation(format!("GET {} is not a route of the Connect mock", ctx.path)),
    }
}
