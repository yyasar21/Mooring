//! In-process mock vCenter (vSphere Automation REST `/api`, ADR-0015 §Test plan) on loopback
//! TLS.
//!
//! `POST /api/session` (Basic auth → session id as a JSON string body, as vCenter 7+ does; the
//! client then sends `vmware-api-session-id`), `DELETE`/`GET /api/session`, datacenter /
//! cluster / host / VM lists with the API's filters over a synthetic [`Inventory`], VM detail,
//! power state, power and guest-power actions (recorded in [`VcenterServer::power_actions`]),
//! `guest/identity`, console tickets (`VMRC` / `WEBMKS`, recorded), and
//! `/api/appliance/system/version`. The list APIs do not paginate; like vCenter they refuse a
//! result above [`VcenterKnobs::result_limit`] (4 000) with `UNABLE_TO_ALLOCATE_RESOURCE`.
//! Any other path or method is a violation (500).

mod inventory;
mod routes;

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

pub use inventory::{Cluster, Datacenter, Host, Inventory, InventorySpec, Vm};

use crate::http::{self, HttpKnobs, Recorder, Running};
use crate::tls::TestCert;

/// Failure behaviour of the vCenter mock.
#[derive(Debug, Clone)]
pub struct VcenterKnobs {
    /// At most this many requests per one-second window; the rest get 429 + `Retry-After: 1`.
    pub rate_limit_per_sec: Option<u32>,
    /// A list call matching more objects than this fails (vCenter: 4 000).
    pub result_limit: usize,
    /// `guest/identity` and guest power fail as if VMware Tools were missing on every VM.
    pub tools_missing: bool,
    /// Console tickets are refused (503).
    pub tickets_unavailable: bool,
}

impl Default for VcenterKnobs {
    fn default() -> Self {
        Self {
            rate_limit_per_sec: None,
            result_limit: 4000,
            tools_missing: false,
            tickets_unavailable: false,
        }
    }
}

/// Configuration of one vCenter mock.
#[derive(Debug, Clone)]
pub struct VcenterConfig {
    pub username: String,
    pub password: String,
    pub inventory: InventorySpec,
    pub knobs: VcenterKnobs,
    pub http: HttpKnobs,
    pub cert: Option<TestCert>,
}

impl Default for VcenterConfig {
    fn default() -> Self {
        Self {
            username: "alice@example.test".to_owned(),
            password: "testpass".to_owned(),
            inventory: InventorySpec::default(),
            knobs: VcenterKnobs::default(),
            http: HttpKnobs::default(),
            cert: None,
        }
    }
}

/// A power or guest-power request the server received (whatever its outcome).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerAction {
    pub vm: String,
    /// `power` (`/power?action=`) or `guest` (`/guest/power?action=`).
    pub kind: String,
    pub action: String,
    pub status: u16,
}

/// A console ticket request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRequest {
    pub vm: String,
    pub kind: String,
}

#[derive(Debug)]
struct Dynamic {
    config: VcenterConfig,
    inventory: Inventory,
    sessions: HashSet<String>,
    logins: usize,
    window: (Instant, u32),
    power: Vec<PowerAction>,
    tickets: Vec<TicketRequest>,
}

#[derive(Debug)]
pub(crate) struct VcenterState {
    inner: Mutex<Dynamic>,
}

impl VcenterState {
    fn lock(&self) -> MutexGuard<'_, Dynamic> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Handle of a running vCenter mock; dropping it stops the server.
#[derive(Debug)]
pub struct VcenterServer {
    running: Running,
    cert: TestCert,
    state: Arc<VcenterState>,
    recorder: Recorder,
}

/// Starts the mock on `127.0.0.1:port` (`0` = ephemeral). Needs a Tokio runtime.
pub async fn start(mut config: VcenterConfig, port: u16) -> io::Result<VcenterServer> {
    let cert = match config.cert.take() {
        Some(c) => c,
        None => TestCert::generate(&[]).map_err(io::Error::other)?,
    };
    let tls = cert.server_config().map_err(io::Error::other)?;
    let inventory = Inventory::generate(config.inventory);
    let state = Arc::new(VcenterState {
        inner: Mutex::new(Dynamic {
            config,
            inventory,
            sessions: HashSet::new(),
            logins: 0,
            window: (Instant::now(), 0),
            power: Vec::new(),
            tickets: Vec::new(),
        }),
    });
    let recorder = Recorder::default();
    let running = http::serve(tls, port, Arc::clone(&state), recorder.clone()).await?;
    Ok(VcenterServer { running, cert, state, recorder })
}

impl VcenterServer {
    pub fn addr(&self) -> SocketAddr {
        self.running.addr
    }

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

    pub fn set_knobs(&self, knobs: VcenterKnobs) {
        let mut g = self.state.lock();
        g.config.knobs = knobs;
        g.window = (Instant::now(), 0);
    }

    /// Invalidates every session: the next call gets 401 (the re-login test).
    pub fn expire_sessions(&self) {
        self.state.lock().sessions.clear();
    }

    /// Live sessions (logins minus logouts / expiries).
    pub fn session_count(&self) -> usize {
        self.state.lock().sessions.len()
    }

    /// Successful `POST /api/session` calls so far.
    pub fn login_count(&self) -> usize {
        self.state.lock().logins
    }

    pub fn inventory(&self) -> Inventory {
        self.state.lock().inventory.clone()
    }

    /// Replaces the inventory (VM added / renamed / moved / gone between refreshes).
    pub fn set_inventory(&self, inventory: Inventory) {
        self.state.lock().inventory = inventory;
    }

    pub fn power_actions(&self) -> Vec<PowerAction> {
        self.state.lock().power.clone()
    }

    pub fn ticket_requests(&self) -> Vec<TicketRequest> {
        self.state.lock().tickets.clone()
    }
}
