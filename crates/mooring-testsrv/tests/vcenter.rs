//! Self-tests of the vCenter mock: session lifecycle, inventory filters and caps, power,
//! guest identity, console tickets, rate limit and the violation trap.

mod common;

use base64::Engine as _;
use bytes::Bytes;
use common::http_client::{get, post_json, request, send};
use common::within;
use http::Method;
use mooring_testsrv::vcenter::{self, InventorySpec, VcenterConfig, VcenterKnobs, VcenterServer};
use serde_json::json;

fn basic(user: &str, pw: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}")))
}

async fn login(s: &VcenterServer) -> String {
    let auth = basic("alice@example.test", "testpass");
    let r = send(
        s.addr(),
        request(Method::POST, "/api/session", &[("authorization", &auth)], Bytes::new()),
        None,
    )
    .await;
    assert_eq!(r.status, 201);
    r.json().as_str().expect("session id string").to_owned()
}

async fn api(s: &VcenterServer, sid: &str, path: &str) -> common::http_client::Resp {
    get(s.addr(), path, &[("vmware-api-session-id", sid)]).await
}

fn len(v: &serde_json::Value) -> usize {
    v.as_array().map_or(0, Vec::len)
}

async fn srv(config: VcenterConfig) -> VcenterServer {
    vcenter::start(config, 0).await.expect("start")
}

#[tokio::test]
async fn session_login_logout_expiry_and_relogin() {
    let s = srv(VcenterConfig::default()).await;
    within(async {
        let bad = basic("alice@example.test", "wrong");
        let r = send(
            s.addr(),
            request(Method::POST, "/api/session", &[("authorization", &bad)], Bytes::new()),
            None,
        )
        .await;
        assert_eq!((r.status, r.json()["error_type"].as_str()), (401, Some("UNAUTHENTICATED")));
        assert_eq!(get(s.addr(), "/api/vcenter/datacenter", &[]).await.status, 401);
        let sid = login(&s).await;
        assert_eq!(len(&api(&s, &sid, "/api/vcenter/datacenter").await.json()), 1);
        assert!(api(&s, &sid, "/api/session").await.json()["user"]
            .as_str()
            .unwrap_or("")
            .ends_with("alice"));
        s.expire_sessions();
        assert_eq!(api(&s, &sid, "/api/vcenter/vm").await.status, 401);
        let sid = login(&s).await;
        let del = send(
            s.addr(),
            request(
                Method::DELETE,
                "/api/session",
                &[("vmware-api-session-id", &sid)],
                Bytes::new(),
            ),
            None,
        )
        .await;
        assert_eq!(del.status, 204);
        assert_eq!(api(&s, &sid, "/api/vcenter/vm").await.status, 401);
    })
    .await;
    assert_eq!((s.login_count(), s.session_count()), (2, 0));
    let rec = s.recorder().requests();
    assert!(rec
        .iter()
        .filter_map(|r| r.header("authorization"))
        .all(|v| v == mooring_testsrv::http::REDACTED));
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn inventory_filters() {
    let s = srv(VcenterConfig::default()).await;
    within(async {
        let sid = login(&s).await;
        let q = |p: &'static str| api(&s, &sid, p);
        assert_eq!(len(&q("/api/vcenter/cluster?datacenters=datacenter-1").await.json()), 2);
        assert_eq!(len(&q("/api/vcenter/host?clusters=domain-c1").await.json()), 2);
        let standalone =
            q("/api/vcenter/host?datacenters=datacenter-1&standalone=true").await.json();
        assert_eq!(standalone[0]["host"], "host-5");
        assert_eq!(len(&q("/api/vcenter/host?datacenters=datacenter-1").await.json()), 5);
        assert_eq!(len(&q("/api/vcenter/vm?hosts=host-1").await.json()), 3);
        assert_eq!(len(&q("/api/vcenter/vm?hosts=host-1&hosts=host-2").await.json()), 6);
        assert_eq!(len(&q("/api/vcenter/vm?clusters=domain-c2").await.json()), 6);
        assert_eq!(len(&q("/api/vcenter/vm?power_states=POWERED_OFF").await.json()), 5);
        let vm = q("/api/vcenter/vm?names=vm-00004").await.json();
        assert_eq!(vm[0]["vm"], "vm-4");
        assert_eq!(q("/api/vcenter/vm/vm-4").await.json()["name"], "vm-00004");
        assert_eq!(q("/api/vcenter/vm/vm-999").await.status, 404);
        assert_eq!(q("/api/appliance/system/version").await.json()["version"], "8.0.3.00400");
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn result_cap_and_5000_vm_inventory() {
    let one =
        srv(VcenterConfig { inventory: InventorySpec::one_host(4001), ..VcenterConfig::default() })
            .await;
    let big = srv(VcenterConfig {
        inventory: InventorySpec::total_vms(5000),
        ..VcenterConfig::default()
    })
    .await;
    within(async {
        let sid = login(&one).await;
        let r = api(&one, &sid, "/api/vcenter/vm?hosts=host-1").await;
        assert_eq!(
            (r.status, r.json()["error_type"].as_str()),
            (400, Some("UNABLE_TO_ALLOCATE_RESOURCE"))
        );
        let sid = login(&big).await;
        assert_eq!(api(&big, &sid, "/api/vcenter/vm").await.status, 400, "5000 > 4000 in one list");
        let hosts = api(&big, &sid, "/api/vcenter/host").await.json();
        let mut total = 0;
        for h in hosts.as_array().expect("hosts") {
            let id = h["host"].as_str().expect("id");
            total += len(&api(&big, &sid, &format!("/api/vcenter/vm?hosts={id}")).await.json());
        }
        assert_eq!(total, 5000);
    })
    .await;
}

#[tokio::test]
async fn power_actions_are_applied_and_recorded() {
    let s = srv(VcenterConfig::default()).await;
    within(async {
        let sid = login(&s).await;
        let h = [("vmware-api-session-id", sid.as_str())];
        let post =
            |p: &'static str| send(s.addr(), request(Method::POST, p, &h, Bytes::new()), None);
        assert_eq!(api(&s, &sid, "/api/vcenter/vm/vm-1/power").await.json()["state"], "POWERED_ON");
        assert_eq!(
            post("/api/vcenter/vm/vm-1/power?action=start").await.json()["error_type"],
            "ALREADY_IN_DESIRED_STATE"
        );
        assert_eq!(post("/api/vcenter/vm/vm-1/power?action=stop").await.status, 204);
        assert_eq!(
            api(&s, &sid, "/api/vcenter/vm/vm-1/power").await.json()["state"],
            "POWERED_OFF"
        );
        assert_eq!(post("/api/vcenter/vm/vm-1/power?action=reset").await.status, 400);
        assert_eq!(post("/api/vcenter/vm/vm-2/guest/power?action=reboot").await.status, 204);
        assert_eq!(
            post("/api/vcenter/vm/vm-5/guest/power?action=shutdown").await.status,
            503,
            "vm-5: no Tools"
        );
        assert_eq!(post("/api/vcenter/vm/vm-3/power?action=start").await.status, 204);
    })
    .await;
    let acts: Vec<(String, String, u16)> =
        s.power_actions().into_iter().map(|a| (a.vm, a.action, a.status)).collect();
    assert_eq!(acts.len(), 6);
    assert_eq!(acts[1], ("vm-1".to_owned(), "stop".to_owned(), 204));
    assert_eq!(s.inventory().vms[2].power_state, "POWERED_ON");
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn identity_tickets_rate_limit_and_violations() {
    let s = srv(VcenterConfig::default()).await;
    within(async {
        let sid = login(&s).await;
        let h = [("vmware-api-session-id", sid.as_str())];
        let id = api(&s, &sid, "/api/vcenter/vm/vm-1/guest/identity").await.json();
        assert_eq!(
            (id["ip_address"].as_str(), id["family"].as_str()),
            (Some("198.51.100.2"), Some("LINUX"))
        );
        assert_eq!(api(&s, &sid, "/api/vcenter/vm/vm-5/guest/identity").await.status, 503);
        let t = post_json(
            s.addr(),
            "/api/vcenter/vm/vm-1/console/tickets",
            &h,
            &json!({ "type": "VMRC" }),
        )
        .await;
        assert!(t.json()["ticket"].as_str().unwrap_or("").starts_with("vmrc://clone:cst-"));
        let w = post_json(
            s.addr(),
            "/api/vcenter/vm/vm-1/console/tickets",
            &h,
            &json!({ "type": "WEBMKS" }),
        )
        .await;
        assert!(w.json()["ticket"]
            .as_str()
            .unwrap_or("")
            .starts_with("wss://esx-1.example.test:443/ticket/"));
        s.set_knobs(VcenterKnobs { tickets_unavailable: true, ..VcenterKnobs::default() });
        assert_eq!(
            post_json(
                s.addr(),
                "/api/vcenter/vm/vm-1/console/tickets",
                &h,
                &json!({ "type": "VMRC" })
            )
            .await
            .status,
            503
        );
        s.set_knobs(VcenterKnobs { rate_limit_per_sec: Some(3), ..VcenterKnobs::default() });
        let mut statuses = Vec::new();
        for _ in 0..4 {
            statuses.push(api(&s, &sid, "/api/vcenter/datacenter").await);
        }
        assert_eq!(statuses.iter().map(|r| r.status).collect::<Vec<_>>(), [200, 200, 200, 429]);
        assert_eq!(statuses[3].header("retry-after").as_deref(), Some("1"));
        s.set_knobs(VcenterKnobs::default());
        for (m, p) in [
            (Method::DELETE, "/api/vcenter/vm/vm-1"),
            (Method::POST, "/api/vcenter/vm"),
            (Method::GET, "/rest/vcenter/vm"),
            (Method::PATCH, "/api/vcenter/vm/vm-1/hardware"),
        ] {
            assert_eq!(send(s.addr(), request(m, p, &h, Bytes::new()), None).await.status, 500);
        }
    })
    .await;
    assert_eq!(s.ticket_requests().len(), 3);
    assert_eq!(s.recorder().violations().len(), 4);
}
