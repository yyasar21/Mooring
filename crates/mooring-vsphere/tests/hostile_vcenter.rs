//! The vSphere client against QA's `mooring-testsrv::vcenter` mock (ADR-0015 §Test plan):
//! the 4 000-result refusal, oversized and deeply nested bodies (via the in-crate mock's raw
//! replies in `inventory.rs`; here the real mock's knobs), rate limiting, missing Tools, and
//! the read-only contract: every test ends with `assert_no_violations()` (no `/rest`, no
//! write, no SOAP) and `power_actions().is_empty()` (nothing was ever powered).

mod common;

use std::time::Duration;

use mooring_http::{CertProtocol, HttpConfig};
use mooring_testsrv::http::HttpKnobs;
use mooring_testsrv::tls::TestCert;
use mooring_testsrv::vcenter::{self, InventorySpec, VcenterConfig, VcenterKnobs, VcenterServer};
use mooring_vsphere::{Caps, HostScope, MoId, Session, VmFilter, VsphereClient};
use url::Url;

struct Mock {
    srv: VcenterServer,
    dir: tempfile::TempDir,
    ca: String,
}

async fn start(spec: InventorySpec, knobs: VcenterKnobs) -> Mock {
    let (cert, ca) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("cert");
    let config =
        VcenterConfig { inventory: spec, knobs, cert: Some(cert), ..VcenterConfig::default() };
    let srv = vcenter::start(config, 0).await.expect("vcenter mock");
    Mock { srv, dir: tempfile::tempdir().expect("tempdir"), ca }
}

impl Mock {
    async fn login(&self) -> Session {
        let known = self.dir.path().join(CertProtocol::Vsphere.file_name());
        let mut c = HttpConfig::new(CertProtocol::Vsphere, "https://placeholder", known);
        c.extra_ca_pem = Some(self.ca.clone());
        c.ca_exclusive = true;
        c.use_system_roots = false;
        c.retry.base_delay = Duration::from_millis(1);
        c.retry.max_delay = Duration::from_millis(5);
        c.timeouts.request = Duration::from_millis(700);
        c.rate.rps = 1000.0;
        c.rate.burst = 1000;
        let base = Url::parse(&self.srv.base_url()).expect("url");
        let pw = secrecy::SecretString::from("testpass".to_owned());
        VsphereClient::login(base, "alice@example.test", &pw, c).await.expect("login")
    }

    fn read_only(&self) {
        self.srv.recorder().assert_no_violations();
        assert!(self.srv.power_actions().is_empty(), "{:?}", self.srv.power_actions());
        assert!(self.srv.ticket_requests().is_empty(), "{:?}", self.srv.ticket_requests());
        assert_eq!(
            self.srv.recorder().count("POST", "/api/vcenter"),
            0,
            "{:?}",
            self.srv.recorder().lines()
        );
    }
}

/// One host with 4 001 VMs: the API refuses the list and so does the client, with
/// `vsphere.too_large`; at 4 000 the whole page comes through. Nothing else is tried.
#[tokio::test]
async fn the_4000_result_refusal_is_too_large() {
    let m = start(InventorySpec::one_host(4_001), VcenterKnobs::default()).await;
    let s = m.login().await;
    let host = MoId::new("host-1").expect("id");
    let f = VmFilter { hosts: vec![host.clone()], ..VmFilter::default() };
    assert_eq!(s.vms(&f).await.expect_err("4001").code(), "vsphere.too_large");
    assert_eq!(s.inventory(&Caps::default()).await.expect_err("4001").code(), "vsphere.too_large");
    m.read_only();

    let m = start(InventorySpec::one_host(4_000), VcenterKnobs::default()).await;
    let s = m.login().await;
    assert_eq!(s.vms(&f).await.expect("4000").len(), 4_000);
    let e = s.inventory(&Caps { vms: 3_999, ..Caps::default() }).await.expect_err("own cap");
    assert_eq!(e.code(), "vsphere.too_large");
    m.read_only();
}

/// The default inventory (clusters, standalone hosts, VMs with and without Tools) is read
/// with GETs only; guest identity of a VM without Tools is `None`, never an error.
#[tokio::test]
async fn a_full_read_is_gets_only() {
    let m = start(InventorySpec::default(), VcenterKnobs::default()).await;
    let s = m.login().await;
    let inv = s.inventory(&Caps::default()).await.expect("inventory");
    assert!(inv.vm_count() > 0 && inv.len() > inv.vm_count());
    let dc = MoId::new("datacenter-1").expect("id");
    assert_eq!(s.hosts(HostScope::Standalone(&dc)).await.expect("standalone").len(), 1);
    for vm in m.srv.inventory().vms.iter().take(6) {
        let id = MoId::new(&vm.id).expect("id");
        let g = s.guest_identity(&id).await.expect("guest identity");
        assert_eq!(g.is_some(), vm.tools, "{}", vm.id);
        let _ = s.power_state(&id).await.expect("power GET");
    }
    assert!(m.srv.recorder().count("GET", "/api/vcenter/vm") >= 7);
    m.read_only();
}

/// With Tools missing everywhere, guest identity is `None` for every VM and no guest power
/// path is ever taken.
#[tokio::test]
async fn tools_missing_is_not_an_error_and_powers_nothing() {
    let knobs = VcenterKnobs { tools_missing: true, ..VcenterKnobs::default() };
    let m = start(InventorySpec::one_host(3), knobs).await;
    let s = m.login().await;
    for n in 1..=3 {
        let id = MoId::new(&format!("vm-{n}")).expect("id");
        assert!(s.guest_identity(&id).await.expect("ok").is_none());
    }
    m.read_only();
}

/// A 429 with `Retry-After` surfaces as `vsphere.rate_limited` with the delay once the
/// client's bounded retries are exhausted; no request is duplicated as a write.
#[tokio::test]
async fn rate_limiting_backs_off_and_reports() {
    let knobs = VcenterKnobs { rate_limit_per_sec: Some(1), ..VcenterKnobs::default() };
    let m = start(InventorySpec::one_host(1), knobs).await;
    let s = m.login().await;
    let mut limited = None;
    for _ in 0..20 {
        if let Err(e) = s.datacenters().await {
            assert_eq!(e.code(), "vsphere.rate_limited", "{e}");
            limited = e.retry_after();
            break;
        }
    }
    assert!(limited.is_some_and(|d| d <= Duration::from_secs(3600)), "{limited:?}");
    m.read_only();
}

/// Session expiry on the server: the next call is `vsphere.auth_failed` (no stored
/// credential means no silent re-login), and the token is never written anywhere else.
#[tokio::test]
async fn an_expired_session_fails_closed() {
    let m = start(InventorySpec::one_host(1), VcenterKnobs::default()).await;
    let s = m.login().await;
    s.datacenters().await.expect("live");
    m.srv.expire_sessions();
    assert_eq!(s.datacenters().await.expect_err("expired").code(), "vsphere.auth_failed");
    assert_eq!(m.srv.login_count(), 1);
    m.read_only();
}

/// The in-crate mock answers whatever body we want: just over 8 MiB, a 100 000-deep array
/// and a 1 MiB string of control characters are refused with static reasons and no leaked
/// server text; the in-crate mock sees no write.
#[tokio::test]
async fn oversized_and_deep_bodies_are_refused() {
    let m = common::serve().await;
    let s = m.login().await;
    let over = vec![b' '; 8 * 1024 * 1024 + 1];
    m.vc.on("/api/vcenter/datacenter", move |_, _| common::reply(200, over.clone()));
    assert_eq!(s.datacenters().await.expect_err("8 MiB + 1").code(), "vsphere.too_large");
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    m.vc.on("/api/vcenter/datacenter", move |_, _| common::reply(200, deep.clone()));
    let e = s.datacenters().await.expect_err("deep");
    assert_eq!(e.code(), "vsphere.failed");
    let ctrl =
        format!(r#"[{{"datacenter":"datacenter-1","name":"{}"}}]"#, "\\u001b".repeat(200_000));
    m.vc.on("/api/vcenter/datacenter", move |_, _| common::reply(200, ctrl.clone()));
    let e = s.datacenters().await.expect_err("control chars");
    assert_eq!(e.code(), "vsphere.failed");
    assert!(!e.to_string().contains("datacenter-1"));
    assert_eq!(m.vc.count("POST", "/api/vcenter"), 0);
    assert_eq!(m.vc.count("PUT", "/"), 0);
}

/// A slow-loris server (one byte every 50 ms) hits the buffered-helper body deadline
/// (`HttpError::Timeout` → `vsphere.unavailable`) instead of holding the caller; retries stay bounded.
#[tokio::test]
async fn slow_loris_hits_the_body_deadline() {
    let m = start(InventorySpec::one_host(1), VcenterKnobs::default()).await;
    let s = m.login().await;
    m.srv.set_http_knobs(HttpKnobs {
        drip: Some(Duration::from_millis(50)),
        ..HttpKnobs::default()
    });
    let started = std::time::Instant::now();
    let e = s.datacenters().await.expect_err("drip");
    assert_eq!(e.code(), "vsphere.unavailable", "{e}"); // HttpError::Timeout maps here
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    m.read_only();
}
