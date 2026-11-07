//! In-process mock HashiCorp Vault / OpenBao (ADR-0016 §Test plan) on loopback TLS.
//!
//! Token `lookup-self` / `renew-self` / `revoke-self`, AppRole login, OIDC `auth_url` +
//! `callback` (fake IdP: [`VaultServer::idp_redirect`] plays the browser), KV v2 `data` (with
//! `?version=`) and `metadata` reads, `sys/health`, policy checks (403), sealed / standby
//! knobs. Token TTLs count down in real time. Every write to KV and every other path is a
//! violation (500): the client only ever reads secrets.

mod dynamic;
mod routes;

pub use dynamic::DynamicConfig;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use serde_json::{json, Value};

use crate::http::{self, HttpKnobs, Recorder, Running};
use crate::tls::TestCert;

/// A pre-existing token (the `token` auth method).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFixture {
    pub token: String,
    pub policies: Vec<String>,
    /// Seconds; `0` = no expiry (as for root tokens).
    pub ttl: u64,
    pub renewable: bool,
}

/// The AppRole the mock accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRoleFixture {
    pub mount: String,
    pub role_id: String,
    pub secret_id: String,
    pub policies: Vec<String>,
    pub ttl: u64,
}

/// The OIDC role and fake IdP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcFixture {
    pub mount: String,
    pub role: String,
    pub allowed_redirect_uris: Vec<String>,
    /// Authorization endpoint of the fake IdP.
    pub idp_authorize: String,
    /// The authorization code the fake IdP hands out.
    pub code: String,
    pub policies: Vec<String>,
    pub ttl: u64,
}

/// One KV v2 version.
#[derive(Debug, Clone, PartialEq)]
pub struct KvVersion {
    /// The `data.data` object (any JSON, so non-string values can be tested).
    pub data: Value,
    pub deleted: bool,
    pub destroyed: bool,
}

impl KvVersion {
    pub fn new(data: Value) -> Self {
        Self { data, deleted: false, destroyed: false }
    }
}

/// A KV v2 secret: `GET /v1/<mount>/data/<path>`.
#[derive(Debug, Clone, PartialEq)]
pub struct KvSecret {
    pub mount: String,
    pub path: String,
    /// Version 1 first.
    pub versions: Vec<KvVersion>,
}

/// A policy: read access to every path starting with one of `read` (`secret/data/team-a/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub read: Vec<String>,
}

/// Failure behaviour of the Vault mock.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VaultKnobs {
    /// Every request gets 503 "Vault is sealed".
    pub sealed: bool,
    /// Every request except `sys/health` gets a 307 to another node (redirects must be refused).
    pub standby: bool,
    /// `lookup-self` reports the `root` policy for every token (root-token refusal test).
    pub root_token: bool,
    /// Every authenticated request gets 403.
    pub force_403: bool,
    /// KV `data` reads return exactly this body (hostile shapes: duplicate keys, non-strings).
    pub raw_kv_body: Option<String>,
    /// KV `data` reads are padded to at least this many bytes (valid JSON).
    pub oversized_body: Option<usize>,
    /// Dynamic-engine issues (`creds`, `sign`, `issue`) return exactly this body.
    pub raw_dynamic_body: Option<String>,
    /// `sys/leases/renew` fails with 400.
    pub lease_renew_fails: bool,
}

/// Configuration of one Vault mock.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub tokens: Vec<TokenFixture>,
    pub approle: AppRoleFixture,
    pub oidc: OidcFixture,
    pub kv: Vec<KvSecret>,
    pub policies: Vec<Policy>,
    /// ADR-0026 dynamic engines.
    pub dynamic: DynamicConfig,
    /// Required `X-Vault-Namespace` (Enterprise / OpenBao namespaces); `None` = not checked.
    pub namespace: Option<String>,
    pub knobs: VaultKnobs,
    pub http: HttpKnobs,
    pub cert: Option<TestCert>,
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

impl Default for VaultConfig {
    fn default() -> Self {
        let read = strings(&["default", "mooring-read"]);
        Self {
            tokens: vec![
                TokenFixture {
                    token: "hvs.test-token".to_owned(),
                    policies: read.clone(),
                    ttl: 3600,
                    renewable: true,
                },
                TokenFixture {
                    token: "hvs.root-token".to_owned(),
                    policies: strings(&["root"]),
                    ttl: 0,
                    renewable: false,
                },
                TokenFixture {
                    token: "hvs.no-policy".to_owned(),
                    policies: strings(&["default"]),
                    ttl: 3600,
                    renewable: false,
                },
            ],
            approle: AppRoleFixture {
                mount: "approle".to_owned(),
                role_id: "test-role-id".to_owned(),
                secret_id: "test-secret-id".to_owned(),
                policies: read.clone(),
                ttl: 1200,
            },
            oidc: OidcFixture {
                mount: "oidc".to_owned(),
                role: "mooring".to_owned(),
                allowed_redirect_uris: strings(&["http://localhost:8250/oidc/callback"]),
                idp_authorize: "https://idp.example.test/authorize".to_owned(),
                code: "test-oidc-code".to_owned(),
                policies: read,
                ttl: 900,
            },
            kv: default_kv(),
            policies: vec![Policy {
                name: "mooring-read".to_owned(),
                read: strings(&["secret/data/", "secret/metadata/"]),
            }],
            dynamic: DynamicConfig::default(),
            namespace: None,
            knobs: VaultKnobs::default(),
            http: HttpKnobs::default(),
            cert: None,
        }
    }
}

/// `secret/servers/web` (v1, v2), `secret/servers/deleted` (deleted), `secret/servers/destroyed`.
pub fn default_kv() -> Vec<KvSecret> {
    let secret = |path: &str, versions| KvSecret {
        mount: "secret".to_owned(),
        path: path.to_owned(),
        versions,
    };
    vec![
        secret(
            "servers/web",
            vec![
                KvVersion::new(json!({ "username": "alice", "password": "old-testpass" })),
                KvVersion::new(
                    json!({ "username": "alice", "password": "testpass", "domain": "EXAMPLE" }),
                ),
            ],
        ),
        secret(
            "servers/deleted",
            vec![KvVersion { deleted: true, ..KvVersion::new(json!({ "password": "x" })) }],
        ),
        secret(
            "servers/destroyed",
            vec![KvVersion { destroyed: true, ..KvVersion::new(Value::Null) }],
        ),
    ]
}

/// A token lifecycle event (logins, renewals, revocations, lookups).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEvent {
    /// `lookup`, `renew`, `revoke`, `login-approle`, `login-oidc`.
    pub kind: String,
    pub accessor: String,
}

/// A dynamic lease event (`issue`, `renew`, `revoke`, `revoke_cert`) with its lease id (or
/// the certificate serial for `revoke_cert`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseEvent {
    pub kind: String,
    pub lease: String,
}

#[derive(Debug, Clone)]
struct MockLease {
    ttl: u64,
    renewable: bool,
    since: Instant,
    revoked: bool,
}

#[derive(Debug, Clone)]
struct Issued {
    policies: Vec<String>,
    ttl: u64,
    renewable: bool,
    since: Instant,
    accessor: String,
    revoked: bool,
}

#[derive(Debug)]
struct Dynamic {
    config: VaultConfig,
    tokens: HashMap<String, Issued>,
    /// OIDC `state` → (`client_nonce`, `redirect_uri`).
    oidc_states: HashMap<String, (String, String)>,
    events: Vec<TokenEvent>,
    leases: HashMap<String, MockLease>,
    lease_events: Vec<LeaseEvent>,
    sign_requests: Vec<Value>,
}

#[derive(Debug)]
pub(crate) struct VaultState {
    inner: Mutex<Dynamic>,
}

impl VaultState {
    fn lock(&self) -> MutexGuard<'_, Dynamic> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Handle of a running Vault mock; dropping it stops the server.
#[derive(Debug)]
pub struct VaultServer {
    running: Running,
    cert: TestCert,
    state: Arc<VaultState>,
    recorder: Recorder,
}

/// Starts the mock on `127.0.0.1:port` (`0` = ephemeral). Needs a Tokio runtime.
pub async fn start(mut config: VaultConfig, port: u16) -> io::Result<VaultServer> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(io::Error::other)?,
    };
    let tls = cert.server_config().map_err(io::Error::other)?;
    let tokens = config
        .tokens
        .iter()
        .map(|t| {
            let issued = Issued {
                policies: t.policies.clone(),
                ttl: t.ttl,
                renewable: t.renewable,
                since: Instant::now(),
                accessor: http::random_hex(12),
                revoked: false,
            };
            (t.token.clone(), issued)
        })
        .collect();
    let state = Arc::new(VaultState {
        inner: Mutex::new(Dynamic {
            config,
            tokens,
            oidc_states: HashMap::new(),
            events: Vec::new(),
            leases: HashMap::new(),
            lease_events: Vec::new(),
            sign_requests: Vec::new(),
        }),
    });
    let recorder = Recorder::default();
    let running = http::serve(tls, port, Arc::clone(&state), recorder.clone()).await?;
    Ok(VaultServer { running, cert, state, recorder })
}

impl VaultServer {
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

    /// Transport knobs (response delay, slow-loris drip, request-body cap) for later requests.
    pub fn set_http_knobs(&self, knobs: HttpKnobs) {
        self.state.lock().config.http = knobs;
    }

    pub fn set_knobs(&self, knobs: VaultKnobs) {
        self.state.lock().config.knobs = knobs;
    }

    pub fn set_kv(&self, kv: Vec<KvSecret>) {
        self.state.lock().config.kv = kv;
    }

    pub fn token_events(&self) -> Vec<TokenEvent> {
        self.state.lock().events.clone()
    }

    pub fn set_dynamic(&self, dynamic: DynamicConfig) {
        self.state.lock().config.dynamic = dynamic;
    }

    /// Every lease issue / renew / revoke so far.
    pub fn lease_events(&self) -> Vec<LeaseEvent> {
        self.state.lock().lease_events.clone()
    }

    /// Leases issued and not revoked (expired ones included: Vault would revoke them itself).
    pub fn live_leases(&self) -> usize {
        self.state.lock().leases.values().filter(|l| !l.revoked).count()
    }

    /// The JSON bodies of every `ssh/sign` request.
    pub fn sign_requests(&self) -> Vec<Value> {
        self.state.lock().sign_requests.clone()
    }

    /// Tokens issued by logins (AppRole / OIDC) that are not revoked yet.
    pub fn live_issued_tokens(&self) -> usize {
        let g = self.state.lock();
        let fixtures: Vec<&str> = g.config.tokens.iter().map(|t| t.token.as_str()).collect();
        g.tokens.iter().filter(|(k, t)| !t.revoked && !fixtures.contains(&k.as_str())).count()
    }

    /// Plays the IdP + browser: for an `auth_url` this server issued, the redirect URL the IdP
    /// would send the browser to (`<redirect_uri>?code=…&state=…`).
    pub fn idp_redirect(&self, auth_url: &str) -> Option<String> {
        let q = auth_url.split_once('?')?.1;
        let pairs = http::parse_query(q);
        let get = |k: &str| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone());
        let (state, redirect) = (get("state")?, get("redirect_uri")?);
        let g = self.state.lock();
        g.oidc_states.contains_key(&state).then(|| {
            let code = &g.config.oidc.code;
            format!(
                "{redirect}?code={}&state={}",
                http::pct_encode(code, false),
                http::pct_encode(&state, false)
            )
        })
    }
}
