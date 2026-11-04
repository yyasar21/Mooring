//! Power actions (approval, audit, error mapping, single flight) and console tickets.

mod common;

use std::sync::Mutex;
use std::time::Duration;

use common::{reply, serve};
use mooring_vsphere::{
    MoId, PowerAction, PowerApproval, PowerAudit, PowerOutcome, PowerState, VMRC_TICKET_TTL,
};
use time::OffsetDateTime;

#[derive(Default)]
struct Log(Mutex<Vec<String>>);

impl PowerAudit for Log {
    fn before(&self, vm: &MoId, action: PowerAction) {
        self.0.lock().expect("lock").push(format!("before {vm} {}", action.as_str()));
    }
    fn after(&self, vm: &MoId, action: PowerAction, outcome: Result<PowerOutcome, &'static str>) {
        self.0.lock().expect("lock").push(format!("after {vm} {} {outcome:?}", action.as_str()));
    }
}

fn vm(id: &str) -> MoId {
    MoId::new(id).expect("id")
}

fn approve(id: &str, a: PowerAction) -> PowerApproval {
    PowerApproval::new(&vm(id), a, true, true).expect("approval")
}

#[tokio::test]
async fn each_action_posts_to_its_endpoint_and_is_audited() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm/vm-1/", |_, _| reply(204, ""));
    let s = m.login().await;
    let audit = Log::default();
    for a in PowerAction::ALL {
        let out = s.power(&vm("vm-1"), approve("vm-1", a), &audit).await.expect("action");
        assert_eq!(out, PowerOutcome::Done);
    }
    let posts: Vec<String> =
        m.vc.requests()
            .into_iter()
            .filter(|r| r.method == "POST" && r.path != "/api/session")
            .map(|r| r.path)
            .collect();
    assert_eq!(
        posts,
        [
            "/api/vcenter/vm/vm-1/power?action=start",
            "/api/vcenter/vm/vm-1/guest/power?action=shutdown",
            "/api/vcenter/vm/vm-1/guest/power?action=reboot",
            "/api/vcenter/vm/vm-1/power?action=stop",
            "/api/vcenter/vm/vm-1/power?action=reset",
        ]
    );
    let log = audit.0.lock().expect("lock").clone();
    assert_eq!(log.len(), 10);
    assert_eq!(log[0], "before vm-1 start");
    assert_eq!(log[1], "after vm-1 start Ok(Done)");
}

#[tokio::test]
async fn guest_errors_and_states_are_typed_and_never_retried() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm/vm-1/guest/power", |_, _| {
        reply(503, r#"{"error_type":"SERVICE_UNAVAILABLE","messages":[]}"#)
    });
    m.vc.on("/api/vcenter/vm/vm-1/power", |_, _| {
        reply(400, r#"{"error_type":"ALREADY_IN_DESIRED_STATE","messages":[]}"#)
    });
    m.vc.on("/api/vcenter/vm/vm-2/power", |_, _| {
        reply(400, r#"{"error_type":"NOT_ALLOWED_IN_CURRENT_STATE","messages":[]}"#)
    });
    let s = m.login().await;
    let audit = Log::default();
    let e = s.power(&vm("vm-1"), approve("vm-1", PowerAction::ShutdownGuest), &audit).await;
    assert_eq!(e.expect_err("tools").code(), "vsphere.tools_missing");
    assert_eq!(m.vc.count("POST", "/api/vcenter/vm/vm-1/guest/power"), 1, "POST is never retried");
    let out = s.power(&vm("vm-1"), approve("vm-1", PowerAction::On), &audit).await;
    assert_eq!(out.expect("already"), PowerOutcome::AlreadyInState);
    let e = s.power(&vm("vm-2"), approve("vm-2", PowerAction::Off), &audit).await;
    assert_eq!(e.expect_err("state").code(), "vsphere.wrong_state");
    let log = audit.0.lock().expect("lock").clone();
    assert!(
        log.contains(&"after vm-1 shutdown Err(\"vsphere.tools_missing\")".to_owned()),
        "{log:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_is_bound_to_its_vm_and_one_action_runs_per_vm() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm/vm-1/power", |_, _| {
        std::thread::sleep(Duration::from_millis(200));
        reply(204, "")
    });
    let s = m.login().await;
    let audit = Log::default();
    let e = s.power(&vm("vm-2"), approve("vm-1", PowerAction::Reset), &audit).await;
    assert_eq!(e.expect_err("other vm").code(), "vsphere.invalid");
    assert_eq!(m.vc.count("POST", "/api/vcenter/vm/"), 0);

    let target = vm("vm-1");
    let (first, second) = tokio::join!(
        s.power(&target, approve("vm-1", PowerAction::Off), &audit),
        s.power(&target, approve("vm-1", PowerAction::Reset), &audit),
    );
    let codes = [first.map_err(|e| e.code()), second.map_err(|e| e.code())];
    assert!(
        codes.contains(&Ok(PowerOutcome::Done)) && codes.contains(&Err("vsphere.busy")),
        "{codes:?}"
    );
    // the slot is released afterwards
    s.power(&vm("vm-1"), approve("vm-1", PowerAction::On), &audit).await.expect("free again");
}

#[tokio::test]
async fn expired_session_during_power_relogs_in_and_sends_once_more() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm/vm-1/power", |_, _| reply(204, ""));
    let s = m.login().await.with_reauth(std::sync::Arc::new(|| {
        Some(mooring_vsphere::Credential { upn: common::UPN.into(), password: common::password() })
    }));
    m.vc.expire();
    let out = s.power(&vm("vm-1"), approve("vm-1", PowerAction::On), &Log::default()).await;
    assert_eq!(out.expect("done"), PowerOutcome::Done);
    // first POST hit 401 (not executed), second ran
    assert_eq!(m.vc.count("POST", "/api/vcenter/vm/vm-1/power"), 2);
}

#[tokio::test]
async fn power_state_reads_the_power_endpoint() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm/vm-1/power", |_, _| {
        reply(200, r#"{"state":"SUSPENDED","clean_power_off":false}"#)
    });
    let s = m.login().await;
    assert_eq!(s.power_state(&vm("vm-1")).await.expect("state"), PowerState::Suspended);
}

#[tokio::test]
async fn vmrc_ticket_is_validated_redacted_and_expires() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm/vm-1/console/tickets", |r, _| {
        assert_eq!(r.body, br#"{"type":"VMRC"}"#);
        reply(201, r#"{"ticket":"vmrc://clone:cst-VCT-SECRET@127.0.0.1/?moid=vm-1"}"#)
    });
    m.vc.on("/api/vcenter/vm/vm-2/console/tickets", |_, _| {
        reply(201, r#"{"ticket":"vmrc://clone:cst-VCT-SECRET@evil.example.test/?moid=vm-2"}"#)
    });
    let s = m.login().await;
    let t = s.vmrc_ticket(&vm("vm-1")).await.expect("ticket");
    assert!(!format!("{t:?}").contains("SECRET"));
    let now = OffsetDateTime::now_utc();
    assert!(t.expose_for_open(now).expect("fresh").starts_with("vmrc://clone:"));
    assert!(t.expose_for_open(now + VMRC_TICKET_TTL + Duration::from_secs(1)).is_err());
    let e = s.vmrc_ticket(&vm("vm-2")).await.expect_err("other host");
    assert_eq!(e.code(), "vsphere.failed");
    assert!(!e.to_string().contains("SECRET"));

    let url = s.vsphere_client_url(&vm("vm-1"), None).expect("url");
    assert_eq!(url.path(), "/ui/");
    assert_eq!(url.scheme(), "https");
}
