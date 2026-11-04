//! In-process mock Kubernetes API server (ADR-0014 §Test plan) on loopback TLS.
//!
//! Serves discovery, namespaces, pods (list / get / watch, `limit` + `continue`), `pods/log`
//! (`tailLines`, `follow`, `container`, `limitBytes`, `timestamps`), `pods/exec` and
//! `pods/portforward` over WebSocket (`v5.channel.k8s.io` / `v4.channel.k8s.io`, see
//! [`ws`]), and the three self-review APIs, with bearer-token and client-certificate auth and
//! RBAC from [`AccessRule`]s.
//!
//! **Forbidden-call trap:** any request outside the ADR-0014 §4 allow-list (Secrets,
//! ConfigMaps, any other resource, any mutating verb, `dryRun` / `fieldManager`, invalid names,
//! exec over POST) is answered 500 and recorded as a violation; tests assert
//! `recorder().assert_no_violations()`.

mod fixtures;
mod routes;
mod stream;
mod ws;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::broadcast;

pub use fixtures::{
    default_pods, default_rules, many_pods, AccessRule, ContainerFixture, PodFixture,
};

use crate::http::{self, HttpKnobs, Recorder, Running};
use crate::tls::{ClientIdentity, TestCert};

/// Hostile / failure behaviour of the kube mock (all off by default).
#[derive(Debug, Clone)]
pub struct KubeKnobs {
    /// Every non-discovery request gets 401.
    pub force_401: bool,
    /// Every non-discovery request gets 403.
    pub force_403: bool,
    /// List responses (namespaces, pods) are padded to at least this many bytes (valid JSON).
    pub oversized_body: Option<usize>,
    /// `pods/log` streams this many bytes, ignoring `limitBytes` and `tailLines`.
    pub huge_log: Option<usize>,
    /// Synthetic log length per container.
    pub log_lines: usize,
    /// With `follow=true`: extra lines streamed after the backlog, then the stream ends (as if
    /// the container exited).
    pub follow_lines: usize,
    pub follow_interval: Duration,
    /// WebSocket subprotocols the server accepts, in preference order of the *client*.
    pub ws_protocols: Vec<String>,
    /// Port-forward: send this text on each port's error channel and close.
    pub portforward_error: Option<String>,
    /// Largest WebSocket message accepted from the client.
    pub max_ws_message: usize,
}

impl Default for KubeKnobs {
    fn default() -> Self {
        Self {
            force_401: false,
            force_403: false,
            oversized_body: None,
            huge_log: None,
            log_lines: 100,
            follow_lines: 5,
            follow_interval: Duration::from_millis(20),
            ws_protocols: vec![ws::V5.to_owned(), ws::V4.to_owned()],
            portforward_error: None,
            max_ws_message: 1024 * 1024,
        }
    }
}

/// Configuration of one kube mock.
#[derive(Debug, Clone)]
pub struct KubeConfig {
    /// Accepted bearer token (`None` = bearer auth off).
    pub token: Option<String>,
    /// Ask for and accept client certificates from a generated test CA.
    pub client_cert_auth: bool,
    /// Identity reported for the bearer token / the client certificate.
    pub user: String,
    pub cert_user: String,
    pub groups: Vec<String>,
    pub namespaces: Vec<String>,
    pub pods: Vec<PodFixture>,
    pub rules: Vec<AccessRule>,
    pub git_version: String,
    pub knobs: KubeKnobs,
    pub http: HttpKnobs,
    /// Server certificate; `None` = a fresh self-signed one.
    pub cert: Option<TestCert>,
}

impl Default for KubeConfig {
    fn default() -> Self {
        Self {
            token: Some("test-token".to_owned()),
            client_cert_auth: true,
            user: "alice".to_owned(),
            cert_user: "mooring-client".to_owned(),
            groups: vec!["system:authenticated".to_owned(), "dev".to_owned()],
            namespaces: vec!["default".to_owned(), "kube-system".to_owned(), "team-a".to_owned()],
            pods: default_pods(),
            rules: default_rules(),
            git_version: "v1.30.4".to_owned(),
            knobs: KubeKnobs::default(),
            http: HttpKnobs::default(),
            cert: None,
        }
    }
}

/// One `pods/exec` session the server ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecRecord {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub command: Vec<String>,
    pub tty: bool,
    pub stdin: bool,
    pub protocol: String,
    /// Every terminal size received on the resize channel, `(width, height)`.
    pub resizes: Vec<(u16, u16)>,
    pub stdin_bytes: usize,
    /// Exit code sent on the status channel (`None`: the client hung up first).
    pub exit_code: Option<i32>,
}

/// One `pods/portforward` session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortForwardRecord {
    pub namespace: String,
    pub pod: String,
    pub ports: Vec<u16>,
    pub protocol: String,
    pub bytes_echoed: usize,
}

#[derive(Debug)]
pub(crate) struct KubeState {
    config: Mutex<KubeConfig>,
    exec: Mutex<Vec<ExecRecord>>,
    forwards: Mutex<Vec<PortForwardRecord>>,
    events: broadcast::Sender<String>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl KubeState {
    fn config(&self) -> KubeConfig {
        lock(&self.config).clone()
    }
}

/// Handle of a running kube mock; dropping it stops the server.
#[derive(Debug)]
pub struct KubeServer {
    running: Running,
    cert: TestCert,
    identity: Option<ClientIdentity>,
    state: Arc<KubeState>,
    recorder: Recorder,
}

/// Starts the mock on `127.0.0.1:port` (`0` = ephemeral). Needs a Tokio runtime.
pub async fn start(mut config: KubeConfig, port: u16) -> io::Result<KubeServer> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(io::Error::other)?,
    };
    let identity = if config.client_cert_auth {
        Some(ClientIdentity::generate(&config.cert_user).map_err(io::Error::other)?)
    } else {
        None
    };
    let tls = match &identity {
        Some(id) => cert.server_config_with_client_ca(id.ca_der()),
        None => cert.server_config(),
    }
    .map_err(io::Error::other)?;
    let (events, _) = broadcast::channel(256);
    let state = Arc::new(KubeState {
        config: Mutex::new(config),
        exec: Mutex::new(Vec::new()),
        forwards: Mutex::new(Vec::new()),
        events,
    });
    let recorder = Recorder::default();
    let running = http::serve(tls, port, Arc::clone(&state), recorder.clone()).await?;
    Ok(KubeServer { running, cert, identity, state, recorder })
}

impl KubeServer {
    pub fn addr(&self) -> SocketAddr {
        self.running.addr
    }

    /// `https://127.0.0.1:<port>` (the kubeconfig `server`).
    pub fn base_url(&self) -> String {
        format!("https://{}", self.running.addr)
    }

    pub fn cert(&self) -> &TestCert {
        &self.cert
    }

    /// The client certificate the server accepts (`None` when client-cert auth is off).
    pub fn client_identity(&self) -> Option<&ClientIdentity> {
        self.identity.as_ref()
    }

    pub fn recorder(&self) -> &Recorder {
        &self.recorder
    }

    /// Transport knobs (response delay, slow-loris drip, request-body cap) for later requests.
    pub fn set_http_knobs(&self, knobs: HttpKnobs) {
        lock(&self.state.config).http = knobs;
    }

    pub fn set_knobs(&self, knobs: KubeKnobs) {
        lock(&self.state.config).knobs = knobs;
    }

    pub fn set_rules(&self, rules: Vec<AccessRule>) {
        lock(&self.state.config).rules = rules;
    }

    pub fn set_pods(&self, pods: Vec<PodFixture>) {
        lock(&self.state.config).pods = pods;
    }

    pub fn exec_sessions(&self) -> Vec<ExecRecord> {
        lock(&self.state.exec).clone()
    }

    pub fn port_forwards(&self) -> Vec<PortForwardRecord> {
        lock(&self.state.forwards).clone()
    }

    /// Sends a watch event (`ADDED` / `MODIFIED` / `DELETED`) to every open pod watch of the
    /// pod's namespace.
    pub fn push_pod_event(&self, kind: &str, pod: &PodFixture) {
        let line = serde_json::json!({ "type": kind, "object": pod.to_json() });
        let _ = self.state.events.send(format!("{}\t{line}\n", pod.namespace));
    }
}
