//! In-test vCenter mock (loopback plaintext hyper server, `example.test` / RFC 5737 data).
//! TODO(merge): switch to QA's `mooring-testsrv::vcenter` once it lands on `a3`.

#![allow(dead_code, clippy::missing_panics_doc)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use mooring_http::{CertProtocol, HttpConfig};
use mooring_vsphere::{Session, VsphereClient};
use secrecy::SecretString;
use tokio::net::TcpListener;
use url::Url;

pub const UPN: &str = "administrator@vsphere.local";
pub const PASSWORD: &str = "pw-for-tests-only";

#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub session: Option<String>,
    pub auth: Option<String>,
    pub body: Vec<u8>,
}

pub type Reply = Response<Full<Bytes>>;

pub fn reply(status: u16, body: impl Into<Bytes>) -> Reply {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r
}

pub fn with_header(mut r: Reply, k: &'static str, v: &str) -> Reply {
    r.headers_mut().insert(k, v.parse().expect("value"));
    r
}

/// Knobs of the mock.
pub struct Vc {
    pub token_seq: AtomicUsize,
    pub valid: Mutex<Option<String>>,
    pub log: Mutex<Vec<Req>>,
    /// VMs per host (`vm-<host>0<i>`).
    pub vms_per_host: AtomicUsize,
    /// Override for any path prefix: (prefix, handler).
    pub overrides: Mutex<Vec<(String, Override)>>,
}

pub type Override = Arc<dyn Fn(&Req, usize) -> Reply + Send + Sync>;

impl Vc {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            token_seq: AtomicUsize::new(0),
            valid: Mutex::new(None),
            log: Mutex::new(Vec::new()),
            vms_per_host: AtomicUsize::new(2),
            overrides: Mutex::new(Vec::new()),
        })
    }

    pub fn expire(&self) {
        *self.valid.lock().expect("lock") = None;
    }

    pub fn on(&self, prefix: &str, f: impl Fn(&Req, usize) -> Reply + Send + Sync + 'static) {
        self.overrides.lock().expect("lock").push((prefix.to_owned(), Arc::new(f)));
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().expect("lock").clone()
    }

    pub fn count(&self, method: &str, prefix: &str) -> usize {
        self.requests().iter().filter(|r| r.method == method && r.path.starts_with(prefix)).count()
    }

    fn route(&self, req: &Req) -> Reply {
        let n = self.count(&req.method, &req.path);
        let over = self
            .overrides
            .lock()
            .expect("lock")
            .iter()
            .rev()
            .find(|(p, _)| req.path.starts_with(p.as_str()))
            .map(|(_, f)| Arc::clone(f));
        if req.path == "/api/session" && req.method == "POST" {
            let good = format!("Basic {}", b64(&format!("{UPN}:{PASSWORD}")));
            if req.auth.as_deref() != Some(good.as_str()) {
                return reply(401, r#"{"error_type":"UNAUTHENTICATED","messages":[]}"#);
            }
            let t = format!("tok-{}", self.token_seq.fetch_add(1, Ordering::SeqCst));
            *self.valid.lock().expect("lock") = Some(t.clone());
            return reply(201, format!("\"{t}\""));
        }
        let valid = self.valid.lock().expect("lock").clone();
        if valid.is_none() || req.session != valid {
            return reply(
                401,
                r#"{"error_type":"UNAUTHENTICATED","messages":[{"default_message":"expired"}]}"#,
            );
        }
        if let Some(f) = over {
            return f(req, n);
        }
        let p = req.path.as_str();
        match (req.method.as_str(), p) {
            ("DELETE", "/api/session") => {
                self.expire();
                reply(204, "")
            }
            ("GET", "/api/vcenter/datacenter") => reply(
                200,
                r#"[{"datacenter":"datacenter-1","name":"DC-Istanbul","future_field":1}]"#,
            ),
            ("GET", "/api/vcenter/cluster?datacenters=datacenter-1") => reply(
                200,
                r#"[{"cluster":"domain-c1","name":"Prod","ha_enabled":true,"drs_enabled":true}]"#,
            ),
            ("GET", "/api/vcenter/host?clusters=domain-c1") => reply(
                200,
                r#"[{"host":"host-1","name":"esx1.example.test","connection_state":"CONNECTED","power_state":"POWERED_ON"},
                    {"host":"host-2","name":"esx2.example.test","connection_state":"CONNECTED","power_state":"POWERED_ON"}]"#,
            ),
            ("GET", "/api/vcenter/host?datacenters=datacenter-1&standalone=true") => reply(
                200,
                r#"[{"host":"host-3","name":"192.0.2.33","connection_state":"NOT_RESPONDING"}]"#,
            ),
            ("GET", _) if p.starts_with("/api/vcenter/vm?hosts=host-") => {
                let host = &p["/api/vcenter/vm?hosts=host-".len()..];
                let n = self.vms_per_host.load(Ordering::SeqCst);
                let items: Vec<String> = (0..n)
                    .map(|i| format!(r#"{{"vm":"vm-{host}0{i}","name":"vm {host}/{i}","power_state":"POWERED_ON","cpu_count":2,"memory_size_MiB":2048}}"#))
                    .collect();
                reply(200, format!("[{}]", items.join(",")))
            }
            _ => reply(404, r#"{"error_type":"NOT_FOUND","messages":[]}"#),
        }
    }
}

pub fn b64(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s)
}

pub struct Mock {
    pub addr: SocketAddr,
    pub vc: Arc<Vc>,
    pub dir: tempfile::TempDir,
}

impl Mock {
    pub fn base(&self) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}/", self.addr.port())).expect("url")
    }

    pub fn config(&self) -> HttpConfig {
        let known = self.dir.path().join(CertProtocol::Vsphere.file_name());
        let mut c = HttpConfig::new(CertProtocol::Vsphere, "http://placeholder", known);
        c.allow_plaintext = true;
        c.use_system_roots = false;
        c.retry.base_delay = Duration::from_millis(1);
        c.retry.max_delay = Duration::from_millis(5);
        c.rate.rps = 1000.0;
        c.rate.burst = 1000;
        c
    }

    pub async fn login(&self) -> Session {
        VsphereClient::login(self.base(), UPN, &password(), self.config()).await.expect("login")
    }
}

pub fn password() -> SecretString {
    SecretString::from(PASSWORD.to_owned())
}

pub async fn serve() -> Mock {
    let vc = Vc::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let state = Arc::clone(&vc);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let state = Arc::clone(&state);
                    async move {
                        let header = |n: &str| {
                            req.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_owned)
                        };
                        let (method, path) = (
                            req.method().to_string(),
                            req.uri()
                                .path_and_query()
                                .map(|p| p.as_str().to_owned())
                                .unwrap_or_default(),
                        );
                        let (session, auth) =
                            (header("vmware-api-session-id"), header("authorization"));
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes().to_vec())
                            .unwrap_or_default();
                        let r = Req { method, path, session, auth, body };
                        let out = state.route(&r);
                        state.log.lock().expect("lock").push(r);
                        Ok::<_, Infallible>(out)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    Mock { addr, vc, dir: tempfile::tempdir().expect("tmp") }
}
